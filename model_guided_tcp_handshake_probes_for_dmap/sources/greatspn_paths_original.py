#!/usr/bin/env python3
r"""Find k shortest distinct GreatSPN firing sequences by PACKET_SEND_ packet exchanges.

Single-file edition. Requires Python 3.10+, JPype1, a compatible Java runtime,
and installed GreatSPN Editor JARs. Install: python3 -m pip install JPype1

Search using the packet markers already present in the model:
    python3 greatspn_paths.py model.PNPRO \
      --greatspn /Applications/GreatSPN.app/Contents/app --page CPN \
      --end Established --k 1000

The packet metric uses the model's exact, case-sensitive transition-name
prefix PACKET_SEND_. Each firing of a matching transition costs 1 packet;
every other transition costs 0. No packet-flow or naming heuristics are used.
Colored bindings and token multiplicities do not change a firing's cost.
For example, PACKET_SEND_A_SYN and PACKET_SEND_S_SYNACK each cost 1, while
Receive_SYN, Send_SYN, and A_PACKET_SEND_SYN cost 0. The prefix must be at the
start of the native transition name. A model without matching names has only
zero-cost paths; a warning reports this explicitly.
Inspect the rule and complete cost map before searching (no --end needed):
    python3 greatspn_paths.py model.PNPRO \
      --greatspn /Applications/GreatSPN.app/Contents/app --page CPN --inspect-costs

The prefix rule and full transition-cost map are saved beside the JSONL as
.packet_costs.json and included in JSON metadata, grouped results and the
checkpoint. Costs are recomputed from native names on resume. A previous
packet checkpoint is reusable only if its full map and model/query match.
The same prefix rule also applies to legacy .net/.def models.

Dijkstra prioritizes (packet count, firing count), using firing count only to
break ties. Zero-cost internal cycles are supported on finite marking graphs;
an unbounded family of zero-cost states still needs time/memory budgets.
Distinctness remains the complete ordered transition-name sequence, including
internal transitions. Colored binding/marking variants stay correlated.

Omit --start to use all saved initial tokens. Explicit --start keeps named
places' tokens and clears the rest initially. Multiple names form an AND set;
repeat --start/--end for OR alternatives. Partial markings remain supported,
for example --end 'Established=<red>;Pending=0'. Traces stop on the first goal.

Results go in results/ by default: JSONL, summary, grouped JSON, SVG images and
a compressed checkpoint. --results-dir changes that folder. Figures use
selectable text, colorblind-friendly colors, nonzero markings, cumulative costs
and separate correlated colored variants. The default paths_images/ folder
contains overview.svg and all_paths.svg (shared packet-prefix exchange trees),
and path_NNNNNN.svg (packet-only attacker/server lifelines, a full top summary,
and correlated variants; internal firings and markings appear in a trace appendix).
Tree nodes contain miniature packet exchanges; alternative branches sit side by side.
Leading A/S/R or ATTACKER/SERVER tags after PACKET_SEND_ set arrow direction
(underscore, colon, space or hyphen separators are accepted). Untagged or ambiguous senders remain explicitly unlabelled.
Only packet sends are grouped in the tree; distinct firing paths stay separate.
Large figures retain
readable text; select/crop individual path figures for publication. --images-dir
changes the image folder; --no-images disables figures. No plotting dependency
is required. SVG opens in browsers, Inkscape and Illustrator, where it can be
exported as PDF or high-resolution PNG. --pnpro-out retains optional legacy
PNPRO visualization. Figures and live progress distinguish cost from firings.
At a terminal timeout, enter extra seconds, 0 for unlimited time, or Enter to
save and stop; --no-prompt handles unattended runs. Checkpoints save every 30s
and at graceful stops. A hard kill can lose work since the latest checkpoint.
Run the same model/query/output to resume; increase --k for more TOTAL paths.
--fresh starts over. Changed objective maps/model/query/native JARs prevent
unsafe reuse; recognized layout-only edits can remain compatible.

--inspect shows initial markings; --list-transitions lists native names;
--help lists options; --debug keeps raw native timing diagnostics.
Export figures from an existing grouped report without Java/JPype:
    python3 greatspn_paths.py --export-images results/paths.jsonl.grouped.json \
      --images-dir results/figures
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import tempfile
from collections import OrderedDict, defaultdict
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from heapq import heapify, heappop, heappush
from itertools import count
import json
from math import isfinite
import os
from pathlib import Path
import re
import sys
import textwrap
from time import perf_counter
from typing import Any, Callable, Hashable, Iterable, Iterator
import xml.etree.ElementTree as ET
import zipfile

VERSION = "11.0-packet-figures"
PACKET_SEND_PREFIX = "PACKET_SEND_"


# Search limits



@dataclass(frozen=True, slots=True)
class Limits:
    k: int = 1000
    max_expansions: int = 500_000
    max_queue: int = 1_000_000
    seconds: float = 60.0
    cache_states: int = 10_000

    def __post_init__(self):
        for name in ("k", "max_expansions", "max_queue", "cache_states"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        if self.k < 1 or min(self.max_expansions, self.max_queue, self.cache_states) < 0:
            raise ValueError("k must be positive; budgets/cache size cannot be negative")
        if not isfinite(self.seconds) or self.seconds < 0:
            raise ValueError("seconds must be finite and nonnegative")


# Distinct transition-sequence search



@dataclass(slots=True)
class Stats:
    status: str = "running"
    found: int = 0
    expanded: int = 0
    generated: int = 0
    unique_states: int = 0
    peak_queue: int = 0
    elapsed_seconds: float = 0.0
    variant_count: int = 0
    variants_complete: bool = True

    @property
    def complete(self) -> bool:
        return self.status in {"found_k", "exhausted"} and self.variants_complete


def search_sequences(initial, successors, key, is_goal, limits=None,
                     on_sequence=None, on_variant=None, on_sequence_complete=None,
                     on_progress=None, transition_cost=None):
    """One-shot convenience API; the CLI keeps its resumable session instead."""
    return SequenceSearchSession(initial, successors, key, is_goal, transition_cost=transition_cost).run(
        limits, on_sequence=on_sequence, on_variant=on_variant,
        on_sequence_complete=on_sequence_complete, on_progress=on_progress)


# Colored path reports



class _ResumePause(Exception):
    pass


class SequenceSearchSession:
    """Keep the exact Dijkstra frontier and colored witnesses between runs.

    A run's time/expansion allowance is additional to previously completed work.
    Pending prefixes, partial variant enumeration, staged children and the
    bounded native-successor cache survive pauses. Prefixes dominated at the
    previous k are deferred, so asking for a larger k can safely revisit them.
    Native bindings for one marking are collected atomically; one slow native
    batch can exceed the cooperative deadline before a safe pause is reached.
    """

    def __init__(self, initial, successors, key, is_goal, transition_cost=None):
        self.successors = successors
        self.key = key
        self.is_goal = is_goal
        self.transition_cost = transition_cost
        self.cost_map = {}
        self.stats = Stats(peak_queue=1)
        self.vertices = []
        self._keys = {}
        self.witnesses = []
        self.prefixes = []
        self.queue = []
        self.deferred = []
        self.accepted_subsets = defaultdict(int)
        self.cache = OrderedDict()
        self.active = None
        self.serial = 0
        self._last_target = 0
        self.exhausted = False
        vertex = self._canonical(initial)
        witness = self._witness(vertex)
        prefix = self._prefix(0, None, None, {vertex: witness})
        self._enqueue(prefix)

    def _canonical(self, state):
        identity = self.key(state)
        existing = self._keys.get(identity)
        if existing is not None:
            return existing
        identifier = len(self.vertices)
        self.vertices.append({"state": state, "goal": bool(self.is_goal(state))})
        self._keys[identity] = identifier
        return identifier

    def _witness(self, vertex):
        identifier = len(self.witnesses)
        self.witnesses.append({"vertex": vertex, "incoming": []})
        return identifier

    def _prefix(self, cost, parent, transition, witnesses):
        identifier = len(self.prefixes)
        self.prefixes.append({"cost": cost, "parent": parent,
                              "length": 0 if parent is None else self.prefixes[parent]["length"] + 1,
                              "transition": transition, "witnesses": witnesses})
        return identifier

    def _enqueue(self, prefix):
        record = self.prefixes[prefix]
        heappush(self.queue, (record["cost"], record["length"], self.serial, prefix))
        self.serial += 1

    def _weight(self, name, *, remember=True):
        """One fixed nonnegative integer metric weight per transition name.

        Native firings still report unit mechanical steps. A supplied policy
        chooses packet weights independently of those simulator steps.
        """
        weight = 1 if self.transition_cost is None else self.transition_cost(name)
        if type(weight) is not int or weight < 0:
            raise ValueError("Transition costs must be nonnegative integers")
        known = self.cost_map.get(name)
        if known is not None and known != weight:
            raise ValueError(f"Transition {name!r} has inconsistent costs across colored firings")
        if remember:
            self.cost_map[name] = weight
        return weight

    def _pending_count(self):
        staged = len(self.active["children"]) if self.active is not None else 0
        if self.active is not None and self.active["phase"] == "enqueue":
            staged -= self.active["enqueue_index"]
        return len(self.queue) + len(self.deferred) + staged

    def _word(self, prefix):
        names = []
        while self.prefixes[prefix]["parent"] is not None:
            record = self.prefixes[prefix]
            names.append(record["transition"])
            prefix = record["parent"]
        names.reverse()
        return names

    def progress_details(self, action=None):
        """Read the current candidate without modifying search/checkpoint state.

        A candidate ID identifies a prefix, not its eventual result rank.
        Only goal-reaching sequences receive result ranks. An outgoing action
        creates an extension with its own, as-yet unassigned result rank.
        """
        active = self.active
        if active is None:
            if not self.queue:
                return None
            prefix_id = self.queue[0][3]
            phase, rank = "queued", None
        else:
            prefix_id = active["prefix"]
            phase, rank = active["phase"], active["rank"]
        outgoing = action
        source = "native" if action is not None else None
        if outgoing is None and active is not None and phase == "expand":
            edges = active["edges"]
            if edges is not None and active["edge_index"] < len(edges):
                outgoing = edges[active["edge_index"]][0]
                source = "recorded"
        action_cost = None if outgoing is None else self._weight(outgoing.split()[0], remember=False)
        return {"candidate_id": prefix_id + 1, "cost": self.prefixes[prefix_id]["cost"],
                "length": self.prefixes[prefix_id]["length"],
                "transitions": self._word(prefix_id), "phase": phase,
                "result_rank": rank, "next_result_rank": self.stats.found + 1,
                "action_outgoing": outgoing, "action_source": source,
                "action_cost": action_cost,
                "extension_cost": None if action_cost is None else self.prefixes[prefix_id]["cost"] + action_cost}

    def _select(self, prefix):
        record = self.prefixes[prefix]
        witnesses = list(record["witnesses"].values())
        self.active = {
            "prefix": prefix, "phase": "variants", "rank": None,
            "variant_index": 0,
            "goals": [w for w in witnesses if self.vertices[self.witnesses[w]["vertex"]]["goal"]],
            "root_index": 0, "stack": [], "actions_back": [], "pending": None,
            "sources": [w for w in witnesses if not self.vertices[self.witnesses[w]["vertex"]]["goal"]],
            "source_index": 0, "edges": None, "edge_index": 0,
            "children": {}, "enqueue_index": 0, "expansion_started": False,
        }

    def _next_variant(self, check):
        """Advance an explicitly serializable backward DFS by safe steps."""
        active = self.active
        while True:
            check()
            stack = active["stack"]
            if not stack:
                if active["root_index"] >= len(active["goals"]):
                    return None
                root = active["goals"][active["root_index"]]
                active["root_index"] += 1
                stack.append([root, 0])
            witness_id, next_edge = stack[-1]
            witness = self.witnesses[witness_id]
            if not witness["incoming"]:
                actions = list(reversed(active["actions_back"]))
                vertices = [self.witnesses[item[0]]["vertex"] for item in reversed(stack)]
                stack.pop()
                if active["actions_back"]:
                    active["actions_back"].pop()
                return {"actions": actions, "vertices": vertices}
            if next_edge < len(witness["incoming"]):
                parent, action = witness["incoming"][next_edge]
                stack[-1][1] += 1
                active["actions_back"].append(action)
                stack.append([parent, 0])
            else:
                stack.pop()
                if active["actions_back"]:
                    active["actions_back"].pop()

    def _outgoing(self, vertex, capacity):
        if vertex in self.cache:
            self.cache.move_to_end(vertex)
            return self.cache[vertex]
        edges = []
        # Do not interrupt midway through a native iterator: the completed
        # batch is saved before the next deadline check and survives cache=0.
        for action, state, cost in self.successors(self.vertices[vertex]["state"]):
            if type(cost) is not int or cost < 0 or (self.transition_cost is None and cost != 1):
                raise ValueError("Native firing costs must be integer 1 in transition mode; packet policies use nonnegative integer weights")
            if not isinstance(action, str) or not action.split():
                raise ValueError("Every action must contain a transition name")
            weight = self._weight(action.split()[0])
            edges.append((action, self._canonical(state), weight))
        if capacity:
            self.cache[vertex] = edges
            while len(self.cache) > capacity:
                self.cache.popitem(last=False)
        return edges

    def run(self, limits=None, on_sequence=None, on_variant=None,
            on_sequence_complete=None, on_progress=None):
        """Continue this session for another allowance, up to total target k."""
        limits = limits or Limits()
        if limits.k < self.stats.found:
            raise ValueError(f"--k must be at least {self.stats.found}, the number of paths already found")
        self.stats.status = "running"
        self.stats.variants_complete = not (self.active is not None
                                           and self.active["phase"] == "variants"
                                           and self.active["rank"] is not None)
        elapsed_before = self.stats.elapsed_seconds
        expanded_before = self.stats.expanded
        started = perf_counter()
        last_progress = started
        while len(self.cache) > limits.cache_states:
            self.cache.popitem(last=False)
        # Preserve original cost/serial ordering when reviving old cap entries.
        if not self.exhausted and limits.k > self._last_target:
            self.queue.extend(self.deferred)
            self.deferred = []
            heapify(self.queue)
        self._last_target = limits.k

        def check():
            nonlocal last_progress
            if not limits.seconds and on_progress is None:
                return
            now = perf_counter()
            elapsed = now - started
            if limits.seconds and elapsed >= limits.seconds:
                raise _ResumePause("time_limit")
            if on_progress is not None and now - last_progress >= 2.0:
                last_progress = now
                self.stats.elapsed_seconds = elapsed_before + elapsed
                self.stats.unique_states = len(self.vertices)
                on_progress(self.stats, self._pending_count())

        try:
            if self.exhausted:
                self.stats.status = "exhausted"
                return self.stats
            if self.stats.found == limits.k and (self.active is None or self.active["phase"] != "variants"):
                self.stats.status = "found_k"
                return self.stats
            while True:
                check()
                if self.active is None:
                    if not self.queue:
                        self.exhausted = True
                        self.stats.status = "exhausted"
                        break
                    candidate = heappop(self.queue)
                    prefix = candidate[3]
                    subset = frozenset(self.prefixes[prefix]["witnesses"])
                    if self.accepted_subsets[subset] >= limits.k:
                        self.deferred.append(candidate)
                        continue
                    self.accepted_subsets[subset] += 1
                    self._select(prefix)
                active = self.active
                prefix = self.prefixes[active["prefix"]]

                if active["phase"] == "variants":
                    if active["pending"] is None:
                        active["pending"] = self._next_variant(check)
                        if active["pending"] is None:
                            active["phase"] = "expand"
                            if active["rank"] is not None:
                                self.stats.variants_complete = True
                                if on_sequence_complete is not None:
                                    on_sequence_complete(active["rank"], True)
                                if self.stats.found == limits.k:
                                    self.stats.status = "found_k"
                                    break
                            continue
                    check()
                    pending = active["pending"]
                    if active["rank"] is None:
                        names = self._word(active["prefix"])
                        self.stats.found += 1
                        active["rank"] = self.stats.found
                        self.stats.variants_complete = False
                        if on_sequence is not None:
                            on_sequence(active["rank"], prefix["cost"], names)
                    active["variant_index"] += 1
                    self.stats.variant_count += 1
                    # Commit the cursor before calling an external writer. If
                    # it raises after committing its own record, a checkpoint
                    # must not emit that same history a second time. Callers
                    # validate report/engine counts before saving error states.
                    active["pending"] = None
                    if on_variant is not None:
                        on_variant(active["rank"], active["variant_index"],
                                   list(pending["actions"]),
                                   [self.vertices[v]["state"] for v in pending["vertices"]])
                    continue

                if active["phase"] == "expand":
                    if not active["sources"]:
                        self.active = None
                        continue
                    if not active["expansion_started"]:
                        if limits.max_expansions and self.stats.expanded - expanded_before >= limits.max_expansions:
                            raise _ResumePause("expansion_limit")
                        self.stats.expanded += 1
                        active["expansion_started"] = True
                    if active["source_index"] >= len(active["sources"]):
                        active["phase"] = "enqueue"
                        continue
                    witness_id = active["sources"][active["source_index"]]
                    vertex = self.witnesses[witness_id]["vertex"]
                    if active["edges"] is None:
                        active["edges"] = self._outgoing(vertex, limits.cache_states)
                        active["edge_index"] = 0
                        # A slow complete batch is retained even if this check
                        # pauses immediately, including with cache_states=0.
                        check()
                    if active["edge_index"] >= len(active["edges"]):
                        active["source_index"] += 1
                        active["edges"] = None
                        continue
                    action, child, weight = active["edges"][active["edge_index"]]
                    transition = action.split()[0]
                    if transition not in active["children"]:
                        if limits.max_queue and self._pending_count() >= limits.max_queue:
                            raise _ResumePause("queue_limit")
                        active["children"][transition] = {}
                        self.stats.peak_queue = max(self.stats.peak_queue, self._pending_count())
                    reached = active["children"][transition].get(child)
                    if reached is None:
                        reached = self._witness(child)
                        active["children"][transition][child] = reached
                    self.witnesses[reached]["incoming"].append((witness_id, action))
                    active["edge_index"] += 1
                    self.stats.generated += 1
                    continue

                if active["phase"] == "enqueue":
                    children = list(active["children"].items())
                    if active["enqueue_index"] < len(children):
                        transition, witnesses = children[active["enqueue_index"]]
                        child_prefix = self._prefix(prefix["cost"] + self.cost_map[transition], active["prefix"],
                                                    transition, witnesses)
                        self._enqueue(child_prefix)
                        active["enqueue_index"] += 1
                        continue
                    self.active = None
        except _ResumePause as pause:
            self.stats.status = str(pause)
        except KeyboardInterrupt:
            self.stats.status = "interrupted"
        finally:
            active = self.active
            if active is not None and active["phase"] == "variants" and active["rank"] is not None:
                self.stats.variants_complete = False
                if on_sequence_complete is not None:
                    on_sequence_complete(active["rank"], False)
            self.stats.unique_states = len(self.vertices)
            self.stats.elapsed_seconds = elapsed_before + perf_counter() - started
        return self.stats

    def dump(self, encode_state):
        """Return portable JSON data; native states are encoded explicitly."""
        active = deepcopy(self.active)
        if active is not None:
            active["children"] = {name: list(members.items())
                                  for name, members in active["children"].items()}
        return {
            "engine_schema": 2,
            "cost_map": dict(self.cost_map),
            "stats": asdict(self.stats),
            "vertices": [{"state": encode_state(vertex["state"]), "goal": vertex["goal"]}
                         for vertex in self.vertices],
            "witnesses": deepcopy(self.witnesses),
            "prefixes": [{**{key: value for key, value in prefix.items() if key != "witnesses"},
                          "witnesses": list(prefix["witnesses"].items())}
                         for prefix in self.prefixes],
            "queue": [list(entry) for entry in self.queue],
            "deferred": [list(entry) for entry in self.deferred],
            "accepted_subsets": [[sorted(subset), count] for subset, count in self.accepted_subsets.items()],
            "cache": [[vertex, [list(edge) for edge in edges]] for vertex, edges in self.cache.items()],
            "active": active,
            "serial": self.serial,
            "target": self._last_target,
            "exhausted": self.exhausted,
        }

    @classmethod
    def load(cls, data, successors, key, is_goal, decode_state, transition_cost=None):
        """Restore only after the caller verifies model/query/full-cost-policy identity."""
        if not isinstance(data, dict) or data.get("engine_schema") not in (1, 2):
            raise ValueError("Unsupported resumable-search checkpoint format")
        if data["engine_schema"] == 1:
            if transition_cost is not None:
                raise ValueError("Legacy firing-count checkpoints cannot be resumed with a packet cost policy")
            try:
                data = cls._upgrade_unit_checkpoint(data)
            except (KeyError, TypeError, IndexError, AttributeError) as error:
                raise ValueError("Malformed legacy firing-count checkpoint") from error
        session = cls.__new__(cls)
        session.successors, session.key, session.is_goal = successors, key, is_goal
        session.transition_cost = transition_cost
        try:
            session.cost_map = dict(data["cost_map"])
            for name, weight in session.cost_map.items():
                if not isinstance(name, str) or not name.strip() or type(weight) is not int or weight < 0:
                    raise ValueError("Checkpoint transition cost map is invalid")
                session._weight(name, remember=False)
            session.stats = Stats(**data["stats"])
            session.vertices = []
            session._keys = {}
            for record in data["vertices"]:
                state = decode_state(record["state"])
                identity = key(state)
                if identity in session._keys:
                    raise ValueError("Checkpoint contains duplicate native markings")
                goal = bool(is_goal(state))
                if type(record["goal"]) is not bool or goal != record["goal"]:
                    raise ValueError("Checkpoint goal markings do not match the current query")
                session._keys[identity] = len(session.vertices)
                session.vertices.append({"state": state, "goal": goal})
            session.witnesses = deepcopy(data["witnesses"])
            session.prefixes = [
                {**{name: value for name, value in record.items() if name != "witnesses"},
                 "witnesses": dict(record["witnesses"])}
                for record in data["prefixes"]]
            session.queue = [tuple(entry) for entry in data["queue"]]
            session.deferred = [tuple(entry) for entry in data["deferred"]]
            session.accepted_subsets = defaultdict(int, {frozenset(subset): count
                                                       for subset, count in data["accepted_subsets"]})
            session.cache = OrderedDict((vertex, [tuple(edge) for edge in edges])
                                        for vertex, edges in data["cache"])
            session.active = deepcopy(data["active"])
            if session.active is not None:
                session.active["children"] = {name: dict(members)
                                              for name, members in session.active["children"].items()}
            session.serial = data["serial"]
            session._last_target = data["target"]
            session.exhausted = data["exhausted"]
            session._validate_checkpoint()
            heapify(session.queue)
        except (KeyError, TypeError, IndexError, AttributeError) as error:
            raise ValueError("Malformed resumable-search checkpoint") from error
        return session

    @staticmethod
    def _upgrade_unit_checkpoint(source):
        """Upgrade the old unit-firing format without reinterpreting its costs.

        The outer CLI must also require unchanged model/query/cost identity.
        The load-time policy check rejects nonunit policies for encountered
        transition names rather than re-ranking an already emitted frontier.
        """
        data = deepcopy(source)
        data["engine_schema"] = 2
        names = set()
        for prefix in data["prefixes"]:
            prefix["length"] = prefix["cost"]
            if prefix["transition"] is not None:
                names.add(prefix["transition"])
        for witness in data["witnesses"]:
            names.update(action.split()[0] for parent, action in witness["incoming"])
        for vertex, edges in data["cache"]:
            names.update(action.split()[0] for action, target in edges)
            edges[:] = [[action, target, 1] for action, target in edges]
        active = data["active"]
        if active is not None and active["edges"] is not None:
            names.update(action.split()[0] for action, target in active["edges"])
            active["edges"] = [[action, target, 1] for action, target in active["edges"]]
        data["cost_map"] = {name: 1 for name in names}
        for label in ("queue", "deferred"):
            data[label] = [[cost, data["prefixes"][prefix]["length"], serial, prefix]
                           for cost, serial, prefix in data[label]]
        return data

    def _validate_checkpoint(self):
        """Reject broken references before any restored native firing occurs."""
        def index(value, size):
            if type(value) is not int or not 0 <= value < size:
                raise ValueError("Checkpoint contains an invalid graph reference")

        def edges(records):
            for action, vertex, weight in records:
                if not isinstance(action, str) or not action.split():
                    raise ValueError("Checkpoint contains an invalid firing label")
                index(vertex, len(self.vertices))
                if type(weight) is not int or weight < 0 or self.cost_map.get(action.split()[0]) != weight:
                    raise ValueError("Checkpoint firing costs disagree with the transition cost map")

        def counter(value):
            if type(value) is not int or value < 0:
                raise ValueError("Checkpoint search counters are invalid")

        if not self.vertices or not self.prefixes or not self.witnesses:
            raise ValueError("Checkpoint search graph is empty")
        if type(self.serial) is not int or self.serial < 1 or type(self.exhausted) is not bool:
            raise ValueError("Checkpoint counters are invalid")
        if type(self._last_target) is not int or self._last_target < self.stats.found:
            raise ValueError("Checkpoint requested path target is invalid")
        for name in ("found", "expanded", "generated", "unique_states", "peak_queue", "variant_count"):
            counter(getattr(self.stats, name))
        if (type(self.stats.elapsed_seconds) not in (int, float)
                or not isfinite(self.stats.elapsed_seconds) or self.stats.elapsed_seconds < 0
                or type(self.stats.variants_complete) is not bool
                or not isinstance(self.stats.status, str)):
            raise ValueError("Checkpoint search statistics are invalid")
        for number, witness in enumerate(self.witnesses):
            index(witness["vertex"], len(self.vertices))
            for parent, action in witness["incoming"]:
                # Every incoming witness existed before the reached witness.
                index(parent, number)
                if not isinstance(action, str) or not action.split():
                    raise ValueError("Checkpoint contains an invalid witness action")
        identities = set()
        for number, prefix in enumerate(self.prefixes):
            if type(prefix["cost"]) is not int or prefix["cost"] < 0:
                raise ValueError("Checkpoint prefix cost is invalid")
            counter(prefix["length"])
            if prefix["parent"] is not None:
                index(prefix["parent"], number)
                if not isinstance(prefix["transition"], str) or not prefix["transition"].strip():
                    raise ValueError("Checkpoint transition name is invalid")
                parent = self.prefixes[prefix["parent"]]
                if (prefix["cost"] != parent["cost"] + self.cost_map.get(prefix["transition"], -1)
                        or prefix["length"] != parent["length"] + 1):
                    raise ValueError("Checkpoint prefix costs or firing lengths are inconsistent")
            elif number != 0 or prefix["cost"] != 0 or prefix["length"] != 0 or prefix["transition"] is not None:
                raise ValueError("Checkpoint initial prefix is invalid")
            identity = (prefix["parent"], prefix["transition"])
            if identity in identities or not prefix["witnesses"]:
                raise ValueError("Checkpoint transition prefixes are duplicated or empty")
            identities.add(identity)
            for vertex, witness in prefix["witnesses"].items():
                index(vertex, len(self.vertices))
                index(witness, len(self.witnesses))
                if self.witnesses[witness]["vertex"] != vertex:
                    raise ValueError("Checkpoint witness points to the wrong marking")
        serials = set()
        for cost, length, serial, prefix in self.queue + self.deferred:
            index(prefix, len(self.prefixes))
            if (type(cost) is not int or cost != self.prefixes[prefix]["cost"]
                    or type(length) is not int or length != self.prefixes[prefix]["length"]
                    or type(serial) is not int or not 0 <= serial < self.serial or serial in serials):
                raise ValueError("Checkpoint frontier order is invalid")
            serials.add(serial)
        for subset, count in self.accepted_subsets.items():
            if type(count) is not int or count < 0:
                raise ValueError("Checkpoint dominance count is invalid")
            for vertex in subset:
                index(vertex, len(self.vertices))
        for vertex, records in self.cache.items():
            index(vertex, len(self.vertices))
            edges(records)
        if self.active is not None:
            active = self.active
            index(active["prefix"], len(self.prefixes))
            if active["phase"] not in {"variants", "expand", "enqueue"}:
                raise ValueError("Checkpoint active phase is invalid")
            if active["edges"] is not None:
                edges(active["edges"])
                counter(active["edge_index"])
                if active["edge_index"] > len(active["edges"]):
                    raise ValueError("Checkpoint outgoing-firing cursor is invalid")
            for field, maximum in (("root_index", len(active["goals"])),
                                   ("source_index", len(active["sources"])),
                                   ("enqueue_index", len(active["children"]))):
                counter(active[field])
                if active[field] > maximum:
                    raise ValueError("Checkpoint active cursor is invalid")
            counter(active["variant_index"])
            if active["rank"] is not None:
                if type(active["rank"]) is not int or not 1 <= active["rank"] <= self.stats.found:
                    raise ValueError("Checkpoint active path rank is invalid")
            if type(active["expansion_started"]) is not bool:
                raise ValueError("Checkpoint expansion phase is invalid")
            if len(active["actions_back"]) != max(0, len(active["stack"]) - 1):
                raise ValueError("Checkpoint variant history cursor is invalid")
            for witness in active["goals"] + active["sources"]:
                index(witness, len(self.witnesses))
            for witness, position in active["stack"]:
                index(witness, len(self.witnesses))
                if type(position) is not int or not 0 <= position <= len(self.witnesses[witness]["incoming"]):
                    raise ValueError("Checkpoint variant cursor is invalid")
            for members in active["children"].values():
                for vertex, witness in members.items():
                    index(vertex, len(self.vertices))
                    index(witness, len(self.witnesses))
                    if self.witnesses[witness]["vertex"] != vertex:
                        raise ValueError("Checkpoint staged witness points to the wrong marking")
            pending = active["pending"]
            if pending is not None:
                if (len(pending["actions"]) != self.prefixes[active["prefix"]]["length"]
                        or len(pending["vertices"]) != len(pending["actions"]) + 1):
                    raise ValueError("Checkpoint pending colored trace has the wrong length")
                for vertex in pending["vertices"]:
                    index(vertex, len(self.vertices))


def _report_cost_settings(report):
    """Validate declared units; packet mappings assign zero to internal names."""
    metric = report.get("cost_metric", "firings")
    if not isinstance(metric, str) or metric not in {"firings", "packets"}:
        raise ValueError("Report cost_metric must be 'firings' or 'packets'")
    supplied = report.get("transition_costs")
    if supplied is None and metric == "firings":
        supplied = {}
    if not isinstance(supplied, dict):
        raise ValueError("Packet reports require a transition_costs object")
    costs = {}
    for name, count in supplied.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Transition cost names must be nonempty strings")
        if type(count) is not int or count < 0:
            raise ValueError("Transition packet costs must be nonnegative integers")
        costs[name] = count
    return metric, costs


def _path_cost_label(report, cost, firing_count):
    if report.get("cost_metric", "firings") == "packets":
        return f"Path cost: {cost} (packets exchanged)"
    return f"Path cost: {firing_count} (transitions fired)"


class DistinctPaths:
    """Build schema-2 grouped reports for transition-sequence search results."""

    def __init__(self, initial_marking: dict, *, cost_metric="firings", transition_costs=None) -> None:
        self.cost_metric, self.transition_costs = _report_cost_settings(
            {"cost_metric": cost_metric, "transition_costs": transition_costs})
        self.initial_marking = deepcopy(initial_marking)
        self._paths: dict[int, dict[str, Any]] = {}
        self._sequences: set[tuple[str, ...]] = set()
        self._markings = {"M0": deepcopy(initial_marking)}
        self._marking_ids = {self._marking_key(initial_marking): "M0"}
        self._variant_count = 0

    @staticmethod
    def _marking_key(marking: dict) -> str:
        return json.dumps(marking, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _register_marking(self, marking: dict) -> str:
        key = self._marking_key(marking)
        identifier = self._marking_ids.get(key)
        if identifier is None:
            identifier = f"M{len(self._markings)}"
            self._marking_ids[key] = identifier
            self._markings[identifier] = deepcopy(marking)
        return identifier

    @staticmethod
    def _positive_integer(value: int, label: str) -> None:
        if type(value) is not int or value < 1:
            raise ValueError(f"{label} must be a positive integer")

    def add_sequence(self, path_rank: int, cost: int, transitions: list[str]) -> None:
        """Declare one distinct ordered transition-name sequence.

        An empty variant list is allowed temporarily so interrupted searches can
        still export an honest incomplete record. A sequence becomes complete
        only when finish_sequence(..., complete=True) is called.
        """
        self._positive_integer(path_rank, "Path rank")
        if path_rank in self._paths:
            raise ValueError("Every distinct path must have a unique rank")
        if type(cost) is not int or cost < 0:
            raise ValueError("Path cost must be a nonnegative integer")
        if any(not isinstance(name, str) or not name.strip() for name in transitions):
            raise ValueError("Transition names must be nonempty strings")
        if self.cost_metric == "packets":
            expected = sum(self.transition_costs.get(name, 0) for name in transitions)
            if cost != expected:
                raise ValueError("Path packet cost disagrees with configured transition costs")
        sequence = tuple(transitions)
        if sequence in self._sequences:
            raise ValueError("A transition sequence must have only one path entry")
        self._paths[path_rank] = {
            "rank": path_rank,
            "cost": cost,
            "transitions": list(transitions),
            "length": len(transitions),
            "variants_complete": False,
            "variants": [],
        }
        self._sequences.add(sequence)

    def add_variant(self, path_rank: int, variant_index: int,
                    actions: list[str], markings: list[dict]) -> dict:
        """Add one executable colored trace for a declared distinct path.

        The returned rank is globally unique across variants. variant_index is
        local to the structural path and is the number displayed in PNPRO.
        """
        path = self._paths.get(path_rank)
        if path is None:
            raise ValueError("Declare the distinct path before adding a variant")
        self._positive_integer(variant_index, "Variant index")
        if path["variants_complete"]:
            raise ValueError("Cannot add variants to a completed path")
        if any(variant["variant_index"] == variant_index for variant in path["variants"]):
            raise ValueError("Variant indices must be unique within a path")
        names = []
        for action in actions:
            if not isinstance(action, str) or not action.strip():
                raise ValueError("Every action must begin with a transition name")
            names.append(action.split(maxsplit=1)[0])
        if names != path["transitions"]:
            raise ValueError("Variant actions disagree with the declared transition sequence")
        if len(markings) != len(actions) + 1:
            raise ValueError("A trace needs the initial marking and one marking per firing")
        if not markings or markings[0] != self.initial_marking:
            raise ValueError("The trace must start with the search initial marking")
        if any(not isinstance(marking, dict) for marking in markings):
            raise ValueError("Every trace marking must be an object")
        identifiers = [self._register_marking(marking) for marking in markings]
        self._variant_count += 1
        variant = {
            "rank": self._variant_count,
            "variant_index": variant_index,
            "cost": path["cost"],
            "actions": list(actions),
            "marking_ids": identifiers,
        }
        path["variants"].append(variant)
        path.setdefault("first_rank", self._variant_count)
        return {**deepcopy(variant), "transitions": list(names), "path_rank": path_rank}

    def finish_sequence(self, path_rank: int, complete: bool) -> None:
        """Record whether every valid colored variant was enumerated."""
        if type(complete) is not bool:
            raise ValueError("Variant completeness must be a boolean")
        path = self._paths.get(path_rank)
        if path is None:
            raise ValueError("Unknown distinct path rank")
        if complete and not path["variants"]:
            raise ValueError("A completed result must have at least one valid variant")
        path["variants_complete"] = complete

    def data(self, summary: dict) -> dict:
        """Return a deep snapshot, ordered by firing length and path rank."""
        lengths: dict[int, list[dict]] = {}
        for stored in self._paths.values():
            path = deepcopy(stored)
            path["variants"].sort(key=lambda variant: variant["variant_index"])
            lengths.setdefault(path["length"], []).append(path)
        groups = []
        for length, paths in sorted(lengths.items()):
            paths.sort(key=lambda path: path["rank"])
            groups.append({
                "length": length,
                "path_count": len(paths),
                "variant_count": sum(len(path["variants"]) for path in paths),
                "paths": paths,
            })
        result_summary = deepcopy(summary)
        result_summary["found"] = len(self._paths)
        result_summary["variant_count"] = self._variant_count
        return {
            "schema_version": 2,
            "cost_metric": self.cost_metric,
            "transition_costs": deepcopy(self.transition_costs),
            "path_identity": "transition_sequence",
            "scope": "Distinct ordered transition sequences; each variant preserves one "
                     "complete correlated colored binding and marking trace. "
                     "variants_complete records whether all variants were enumerated.",
            "distinct_path_count": len(self._paths),
            "variant_count": self._variant_count,
            "initial_marking_id": "M0",
            "initial_marking": deepcopy(self.initial_marking),
            "markings": deepcopy(self._markings),
            "summary": result_summary,
            "length_groups": groups,
        }


# Start and goal marking constraints



_NAME = r"[A-Za-z_][A-Za-z0-9_]*"


_ASSIGNMENT = re.compile(rf"^\s*({_NAME})\s*(>=|=)\s*(.*?)\s*$", re.DOTALL)


_BARE = re.compile(rf"^\s*({_NAME})\s*$")


def _split_clause(specification: str) -> list[str]:
    """Split only top-level semicolons; leave bracketed expressions intact."""
    parts = []
    stack = []
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = None
    escaped = False
    begin = 0
    for i, char in enumerate(specification):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != pairs[char]:
                raise ValueError("Unbalanced brackets in marking pattern")
        elif char == ";" and not stack:
            parts.append(specification[begin:i].strip())
            begin = i + 1
    if quote is not None or stack:
        raise ValueError("Unbalanced brackets or quotes in marking pattern")
    parts.append(specification[begin:].strip())
    if any(not part for part in parts):
        raise ValueError("Empty marking-pattern clause/atom")
    return parts


@dataclass(frozen=True, slots=True)
class _Atom:
    name: str
    place: Any
    mode: str
    expression: str | None
    expected: Any = None


class PatternSet:
    def __init__(self, adapter, clauses):
        self._adapter = adapter
        self._clauses = tuple(tuple(clause) for clause in clauses)

    def matches(self, state) -> bool:
        def atom_matches(atom):
            if atom.mode == "occupied":
                return self._adapter.occupied(state, atom.place)
            return self._adapter.marking_matches(
                state, atom.place, atom.expected, mode=atom.mode
            )
        return any(all(atom_matches(atom) for atom in clause) for clause in self._clauses)

    def metadata(self) -> list[list[dict]]:
        return [[{"place": atom.name, "mode": atom.mode, "expression": atom.expression}
                 for atom in clause] for clause in self._clauses]

    @property
    def place_names(self) -> frozenset[str]:
        """All explicitly named places, including zero constraints and OR clauses."""
        return frozenset(atom.name for clause in self._clauses for atom in clause)

    @property
    def legacy_place(self) -> str | None:
        """Preserve old JSON metadata for an unchanged single-place query."""
        if len(self._clauses) == 1 and len(self._clauses[0]) == 1:
            atom = self._clauses[0][0]
            if atom.mode == "occupied":
                return atom.name
        return None


def compile_patterns(adapter, specs: str | list[str] | list[list[str]], label: str) -> PatternSet:
    """Resolve/evaluate ALL alternatives once before starting any search.

    This function does not change tokens in the supplied adapter's initial state.
    Color and multiset expression semantics are delegated to the native adapter.
    """
    if isinstance(specs, str):
        specs = [specs]
    if not isinstance(specs, (list, tuple)) or not specs:
        raise ValueError(f"{label}: at least one marking pattern is required")
    # argparse's nargs='+' collects one AND set per option occurrence. Keep
    # the original string/list-of-strings programmatic API as OR alternatives.
    if all(isinstance(group, (list, tuple)) for group in specs):
        normalized = []
        for index, group in enumerate(specs, 1):
            if not group or any(not isinstance(atom, str) or not atom.strip() for atom in group):
                raise ValueError(f"{label} alternative {index}: place sets must contain nonempty strings")
            normalized.append(";".join(group))
        specs = normalized
    elif not all(isinstance(spec, str) for spec in specs):
        raise ValueError(f"{label}: use strings or complete lists of place strings, not mixed formats")
    clauses = []
    for index, specification in enumerate(specs, 1):
        try:
            if not isinstance(specification, str):
                raise ValueError("A marking pattern must be a string")
            atoms = []
            seen = set()
            for text in _split_clause(specification):
                assigned = _ASSIGNMENT.fullmatch(text)
                bare = _BARE.fullmatch(text) if assigned is None else None
                if assigned is not None:
                    name, operator, expression = assigned.groups()
                    expression = expression.strip()
                    if not expression or expression.startswith("="):
                        raise ValueError(f"Invalid marking expression in {text!r}; use PLACE=EXPR or PLACE>=EXPR")
                    mode = "exact" if operator == "=" else "contains"
                elif bare is not None:
                    name, mode, expression = bare.group(1), "occupied", None
                else:
                    raise ValueError(f"Invalid atom {text!r}; use PLACE, PLACE=EXPR, or PLACE>=EXPR")
                if name in seen:
                    raise ValueError(f"Place {name!r} occurs more than once in the same clause")
                seen.add(name)
                place = adapter.require_place(name)
                expected = None if mode == "occupied" else adapter.evaluate_marking(place, expression)
                atoms.append(_Atom(name, place, mode, expression, expected))
            clauses.append(atoms)
        except Exception as exc:
            raise ValueError(f"{label} alternative {index}: {exc}") from exc
    return PatternSet(adapter, clauses)


# GreatSPN native parser and firing adapter



class NativeCheckpointMixin:
    def _checkpoint_expression(self, state: Any, place: Any) -> str:
        """Produce a parser-checked expression equal to one native marking.

        Native display text is only a candidate, never trusted as a portable
        representation. Every accepted expression is evaluated in the place's
        actual color domain and checked against the complete native value.
        """
        value = state.getMarkingOfPlace(place)
        name = str(place.getUniqueName())
        if bool(value.equalsZero()):
            candidates = ["0"]
        elif bool(place.isInNeutralDomain()):
            if not bool(value.isScalarInt()):
                raise ValueError(f"Cannot checkpoint noninteger marking in {name!r}")
            candidates = [str(int(value.getScalarInt()))]
        else:
            candidates = [str(value)]
            # Some releases print a whole multiset differently from an editable
            # expression. Build explicit terms from the native elements as an
            # additional candidate, then subject them to the same exact check.
            if bool(value.isMultiSetInt()):
                printed_terms = []
                bracketed_terms = []
                for index in range(int(value.numElements())):
                    multiplicity = value.getValue(index)
                    if not bool(multiplicity.isScalarInt()):
                        raise ValueError(f"Cannot checkpoint noninteger multiplicity in {name!r}")
                    count = int(multiplicity.getScalarInt())
                    if count < 0:
                        raise ValueError(f"Cannot checkpoint negative tokens in {name!r}")
                    if not count:
                        continue
                    element = str(value.getElement(index)).strip()
                    coefficient = "" if count == 1 else str(count)
                    printed_terms.append(coefficient + element)
                    literal = element if element.startswith("<") and element.endswith(">") else f"<{element}>"
                    bracketed_terms.append(coefficient + literal)
                candidates.extend([" + ".join(printed_terms), " + ".join(bracketed_terms)])
        last_error = None
        for expression in dict.fromkeys(candidates):
            if not expression.strip():
                continue
            try:
                expected = self.evaluate_marking(place, expression)
                if self.marking_matches(state, place, expected, mode="exact"):
                    return expression
            except Exception as exc:
                last_error = exc
        raise ValueError(
            f"Cannot safely save the complete colored marking of place {name!r} "
            "as a GreatSPN expression; no exact parser-checked representation was available"
        ) from last_error

    def checkpoint_marking(self, state: Any) -> dict[str, str]:
        """Serialize every place with a verified native marking expression."""
        self._require_valid_state(state, "checkpoint marking")
        return {str(place.getUniqueName()): self._checkpoint_expression(state, place)
                for place in self._places}

    def state_from_marking(self, marking: dict[str, str]) -> Any:
        """Hydrate a saved complete marking and recompute enabled bindings.

        Rebuilding through getInitialState avoids stale Java enabled caches.
        Temporary edits are always rolled back; neither the input model on disk
        nor this adapter's original initial_state is changed. This is untimed
        state restoration, not replay of previously explored transitions.
        """
        if not isinstance(marking, dict):
            raise ValueError("Checkpoint marking must be an object mapping every place to an expression")
        by_name = {str(place.getUniqueName()): place for place in self._places}
        if set(marking) != set(by_name):
            missing = sorted(set(by_name) - set(marking))
            extra = sorted(set(marking) - set(by_name), key=str)
            raise ValueError(f"Checkpoint marking does not match this net's places; missing={missing}, extra={extra}")
        expected = []
        for name, place in by_name.items():
            expression = marking[name]
            if not isinstance(expression, str) or not expression.strip():
                raise ValueError(f"Checkpoint marking for {name!r} must be nonempty text")
            # Validate every value before touching any editable expression.
            expected.append((place, expression, self.evaluate_marking(place, expression)))
        saved = []
        for place in self._places:
            cell = place.getInitMarkingEditable()
            saved.append((cell, cell.getValue()))
        changed = []
        try:
            for (cell, original), (_, expression, _) in zip(saved, expected):
                changed.append((cell, original))
                cell.setValue(self._project, self._net, expression)
            if changed:
                self._compile_parsed_info()
            state = self._native_call(self._classes["Engine"].getInitialState,
                                      self._net, self._template_binding, None, None, False)
            self._require_valid_state(state, "restored checkpoint marking")
            for place, _, compiled in expected:
                if not self.marking_matches(state, place, compiled, mode="exact"):
                    raise ValueError(
                        "GreatSPN restored a different marking for checkpoint place "
                        f"{str(place.getUniqueName())!r}; refusing to reuse this checkpoint"
                    )
            return state
        finally:
            restoration_error = None
            for cell, original in reversed(changed):
                try:
                    cell.setValue(self._project, self._net, original)
                except Exception as exc:
                    if restoration_error is None:
                        restoration_error = exc
            if changed:
                try:
                    self._compile_parsed_info()
                except Exception as exc:
                    if restoration_error is None:
                        restoration_error = exc
            if restoration_error is not None:
                raise RuntimeError(
                    "Cannot restore the model's original initial expressions after hydrating a checkpoint state"
                ) from restoration_error


_CHECKPOINT_VISUAL_NODE_ATTRIBUTES = frozenset({
    "x", "y", "width", "height", "rotation", "name-x", "name-y",
    "alt-name-fn", "shown-as", "label-x", "label-y", "tag-x", "tag-y",
    "domain-x", "domain-y", "marking-x", "marking-y", "delay-x", "delay-y",
    "priority-x", "priority-y", "weight-x", "weight-y", "servers-x", "servers-y",
    "guard-x", "guard-y", "color-x", "color-y",
})


_CHECKPOINT_VISUAL_ARC_ATTRIBUTES = frozenset({
    "x", "y", "head-magnet", "tail-magnet", "mult-x", "mult-y",
    "label-x", "label-y", "broken", "arrow-length", "arrow-width",
})


_CHECKPOINT_VISUAL_PAGE_ATTRIBUTES = frozenset({
    "zoom", "show-timed-cmd", "show-color-cmd", "show-fluid-cmd", "view-rates",
    "view-priorities", "view-guards", "view-names", "view-superpos-tags",
    "view-names", "show-timed-cmd", "viewport-x", "viewport-y",
})


_CHECKPOINT_NODE_TAGS = frozenset({
    "place", "transition", "color-class", "color-var", "constant", "clock-var",
    "template", "template-variable",
})


def _checkpoint_xml_semantics(element: ET.Element, parent_tag: str = "") -> Any:
    """Remove only recognized display data; unknown XML remains significant."""
    tag = element.tag.rsplit("}", 1)[-1]
    if parent_tag == "nodes" and tag == "text-box":
        return None
    if parent_tag == "arc" and tag == "point":
        return None
    if parent_tag == "gspn" and tag == "view-profile":
        return None
    ignored = frozenset()
    if tag in _CHECKPOINT_NODE_TAGS and parent_tag == "nodes":
        ignored = _CHECKPOINT_VISUAL_NODE_ATTRIBUTES
    elif tag == "arc" and parent_tag == "edges":
        ignored = _CHECKPOINT_VISUAL_ARC_ATTRIBUTES
    elif tag == "gspn":
        ignored = _CHECKPOINT_VISUAL_PAGE_ATTRIBUTES
    elif tag == "project":
        ignored = frozenset({"name"})
    attributes = sorted((key, value) for key, value in element.attrib.items() if key not in ignored)
    children = [result for child in element
                if (result := _checkpoint_xml_semantics(child, tag)) is not None]
    # Nodes/arcs are named graph objects; serialization order is presentation.
    # Preserve order in expression/unknown subtrees, where it may be semantic.
    if tag in {"nodes", "edges"}:
        children.sort(key=lambda item: json.dumps(item, ensure_ascii=False, separators=(",", ":")))
    return [element.tag, attributes, (element.text or "").strip(), children]


def checkpoint_model_fingerprint(model: Path, page_name: str | None) -> str:
    """Hash critical model content while tolerating recognized visual edits.

    All PNPRO pages and unknown project data are retained conservatively; an
    unrelated semantic page edit may therefore require a fresh search too.
    Legacy net/def pairs use exact bytes because their layout/semantics cannot
    safely be separated by this XML projection.
    """
    model = Path(model).expanduser().resolve()
    if model.suffix.lower() == ".pnpro":
        root = ET.parse(model).getroot()
        payload = {"format": "pnpro-semantic-v1", "page": page_name,
                   "project": _checkpoint_xml_semantics(root)}
    elif model.suffix.lower() in {".net", ".def"}:
        payload = {"format": "greatspn-legacy-exact-v1", "page": page_name,
                   "files": {suffix: hashlib.sha256(model.with_suffix(suffix).read_bytes()).hexdigest()
                             for suffix in (".net", ".def")}}
    else:
        raise ValueError("Checkpoint model must be a .PNPRO, .net, or .def file")
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def checkpoint_engine_fingerprint(classpath: Iterable[str | Path]) -> str:
    """Hash native JAR contents and precedence, independently of their paths."""
    precedence = []
    for supplied in classpath:
        path = Path(supplied).expanduser().resolve()
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        precedence.append([path.name, digest.hexdigest()])
    payload = {"format": "greatspn-classpath-v1", "jars": sorted(precedence),
               "precedence": precedence}
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


ENGINE_MARKER = "editor/domain/play/GspnDtaPlayEngine.class"


def discover_classpath(paths: Iterable[str | Path]) -> list[str]:
    """Find one Editor JAR plus dependencies under supplied files/directories.

    An explicit JAR also includes sibling JARs and its sibling ``lib`` tree.
    Point at one installation/dist directory to avoid mixing Editor versions.
    """
    jars: set[Path] = set()
    for supplied in paths:
        location = Path(supplied).expanduser().resolve()
        if location.is_file() and location.suffix.lower() == ".jar":
            jars.add(location)
            jars.update(location.parent.glob("*.jar"))
            lib = location.parent / "lib"
            if lib.is_dir():
                jars.update(lib.rglob("*.jar"))
        elif location.is_dir():
            jars.update(location.rglob("*.jar"))
        else:
            raise ValueError(f"Not a JAR file or directory: {location}")
    jars = {jar.resolve() for jar in jars}
    editors = []
    for jar in sorted(jars):
        try:
            with zipfile.ZipFile(jar) as archive:
                if ENGINE_MARKER in archive.namelist():
                    editors.append(jar)
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Invalid JAR archive: {jar}") from exc
    if not editors:
        raise ValueError(
            "No GreatSPN Editor JAR containing GspnDtaPlayEngine was found. "
            "Pass the Editor/dist directory including lib, or the installed "
            "Editor JAR. Native solver binaries alone are insufficient."
        )
    if len(editors) != 1:
        raise ValueError(
            "Multiple Editor JARs found; select one installation/dist directory: "
            + ", ".join(map(str, editors))
        )
    return [str(editors[0]), *(str(jar) for jar in sorted(jars) if jar not in editors)]


@dataclass(frozen=True, eq=False, slots=True)
class _FormulaKey:
    """Exact immutable GreatSPN value equality, independent of printed text.

    EvaluatedFormula is documented as immutable and defines equals/hashCode.
    Calling those methods explicitly avoids assumptions about how a particular
    JPype version maps Python equality and hashing for Java wrapper objects.
    """

    value: Any = field(repr=False)
    _hash: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_hash", int(self.value.hashCode()))

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _FormulaKey):
            return NotImplemented
        return bool(self.value.equals(other.value))


@dataclass(frozen=True, slots=True)
class _RequiredMarking:
    """A checked native expression with its positive color counts cached."""

    value: Any = field(repr=False)
    components: tuple[tuple[Any, int], ...] = field(repr=False)
    neutral: bool
    scalar_count: int = 0


class GreatSpnAdapter(NativeCheckpointMixin):
    """Single-threaded adapter to native GreatSPN readers and token-game engine.

    ``initial_state`` preserves the marking saved in the model. Rates/delays do
    not become edge costs. Native unit steps receive objective weights in the search. Immediate priorities are left
    to GreatSPN. General-time, continuous, clock, and uninstantiated template
    constructs are rejected rather than approximated.

    Never mutate a returned state or its Java marking values. The
    ``initial_state_for_places`` method temporarily edits initial expressions
    while asking the native engine to build a new state, then restores them.
    Python 3.10+, JPype1, a compatible JVM, and the Editor JARs are required.
    """

    def __init__(
        self,
        input: Path,
        page: str | None,
        classpath: list[str],
        jvm_path: str | None = None,
        heap: str = "2g",
        debug: bool = False,
    ) -> None:
        model = Path(input).expanduser().resolve()
        if not model.is_file():
            raise ValueError(f"Cannot read model: {model}")
        if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]?", heap):
            raise ValueError("JVM heap must be a positive size such as 512m or 2g")
        self._native_debug = debug
        self._checkpoint_classpath = tuple(str(path) for path in classpath)
        try:
            import jpype
        except ImportError as exc:
            raise RuntimeError("Install JPype with: python3 -m pip install JPype1") from exc

        try:
            if not jpype.isJVMStarted():
                jpype.startJVM(
                    f"-Xmx{heap}",
                    "-Djava.awt.headless=true",
                    jvmpath=jvm_path,
                    classpath=classpath,
                    convertStrings=False,
                )
            # GreatSPN's graphical launcher normally performs this setup.
            # It is also required for headless imports: page validation queries
            # zoom/UI preferences, and native errors must not open a JFrame.
            self._bootstrap_jvm(jpype)
            self._classes = self._load_classes(jpype)
        except Exception as exc:
            raise RuntimeError(
                "Cannot initialize/load the GreatSPN Java engine. Supply the Editor "
                "JAR and dependency JARs, and a JVM matching Python's architecture. "
                "If a JVM is already running, restart Python with this classpath. "
                f"Details: {exc}"
            ) from exc

        c = self._classes
        self.warnings: list[str] = []
        self._template_binding = c["TemplateBinding"]()
        self._net, self._project = self._read(model, page)
        self.page_name = str(self._net.getPageName())
        self._places: list[Any] = []
        self._check_supported_features()
        self._validate()

        context = c["ParserContext"](self._net)
        context.templateVarsBinding = self._template_binding
        self._net.compileParsedInfo(context)
        self._places.sort(key=lambda place: str(place.getUniqueName()))
        self.initial_state = self._native_call(c["Engine"].getInitialState,
            self._net, self._template_binding, None, None, False
        )
        self._require_valid_state(self.initial_state, "initial marking")

    @staticmethod
    def _bootstrap_jvm(jpype: Any) -> None:
        """Initialize native global state before any model classes are used.

        Without initApplication, Util.getPreferences passes a null root to
        java.util.prefs when validation computes label sizes/zoom. Without the
        logging switch, a native validation exception attempts to open a Swing
        log window and raises a second HeadlessException.
        """
        jpype.JClass("java.lang.System").setProperty("java.awt.headless", "true")
        jpype.JClass("editor.Main").useGuiLogWindowForExceptions = False
        jpype.JClass("common.Util").initApplication(
            "GreatSPN Python search", "GreatSPN Python search"
        )
        jpype.JClass("latex.DummyLatexProvider").initializeProvider()

    @staticmethod
    def _load_classes(jpype: Any) -> dict[str, Any]:
        names = {
            "File": "java.io.File",
            "System": "java.lang.System",
            "ByteArrayOutputStream": "java.io.ByteArrayOutputStream",
            "PrintStream": "java.io.PrintStream",
            "ArrayList": "java.util.ArrayList",
            "HashSet": "java.util.HashSet",
            "ProjectData": "editor.domain.ProjectData",
            "GspnPage": "editor.domain.elements.GspnPage",
            "Place": "editor.domain.elements.Place",
            "Transition": "editor.domain.elements.Transition",
            "ClockVar": "editor.domain.elements.ClockVar",
            "TemplateVariable": "editor.domain.elements.TemplateVariable",
            "TemplateBinding": "editor.domain.grammar.TemplateBinding",
            "ParserContext": "editor.domain.grammar.ParserContext",
            "ParserEntryPoint": "editor.domain.grammar.ParserContext$ParserEntryPoint",
            "EvaluationArguments": "editor.domain.grammar.EvaluationArguments",
            "PnProFormat": "editor.domain.io.PnProFormat",
            "GreatSpnFormat": "editor.domain.io.GreatSpnFormat",
            "Engine": "editor.domain.play.GspnDtaPlayEngine",
            "DummyLatexProvider": "latex.DummyLatexProvider",
        }
        return {name: jpype.JClass(java_name) for name, java_name in names.items()}

    def _native_call(self, operation, *args):
        """Filter one repetitive Java diagnostic without hiding other output.

        Python redirect_stdout does not intercept Java System.out. Capture only
        this synchronous engine call, then relay every other byte unchanged.
        The adapter is single-threaded; System.err is never redirected.
        Missing stream classes allow lightweight programmatic test backends.
        """
        c = self._classes
        if getattr(self, "_native_debug", False) or "ByteArrayOutputStream" not in c:
            return operation(*args)
        if getattr(self, "_native_stdout_buffer", None) is None:
            self._native_stdout_buffer = c["ByteArrayOutputStream"]()
            self._native_stdout_stream = c["PrintStream"](self._native_stdout_buffer, True)
        buffer = self._native_stdout_buffer
        captured = self._native_stdout_stream
        system = c["System"]
        original = system.out
        original.flush()
        buffer.reset()
        system.setOut(captured)
        try:
            return operation(*args)
        finally:
            try:
                captured.flush()
            finally:
                system.setOut(original)
            raw = bytes(buffer.toByteArray())
            suppressed = False
            for line in raw.splitlines(keepends=True):
                if line.rstrip(b"\r\n") == b"Next time bound is -1.0":
                    suppressed = True
                else:
                    original.write(line)
            original.flush()
            if suppressed and not getattr(self, "_native_output_notice", False):
                self._native_output_notice = True
                print("GreatSPN timing note: 'Next time bound is -1.0' is native timing output, "
                      "not a path cost. The search does not use this timing value; repeated copies "
                      "are hidden. Use --debug to show them.", file=sys.stderr)

    def _read(self, model: Path, page_name: str | None) -> tuple[Any, Any]:
        c = self._classes
        suffix = model.suffix.lower()
        if suffix == ".pnpro":
            project_file = c["PnProFormat"].readXML(c["File"](str(model)))
            project = project_file.getCurrent()
            pages = [
                project.getPageAt(i)
                for i in range(int(project.getPageCount()))
                if isinstance(project.getPageAt(i), c["GspnPage"])
            ]
            if page_name is not None:
                for candidate in pages:
                    if str(candidate.getPageName()) == page_name:
                        return candidate, project
                raise ValueError(f"No GSPN page named: {page_name}")
            if len(pages) != 1:
                names = [str(candidate.getPageName()) for candidate in pages]
                raise ValueError(f"Specify --page; GSPN pages: {names}")
            return pages[0], project

        if suffix not in {".net", ".def"}:
            raise ValueError("Expected a .PNPRO, .net, or .def file")
        net_file, def_file = model.with_suffix(".net"), model.with_suffix(".def")
        if not net_file.is_file() or not def_file.is_file():
            raise ValueError(f"Both files are required: {net_file} and {def_file}")
        net = c["GspnPage"]()
        net.setPageName(page_name if page_name is not None else model.stem)
        diagnostics = c["GreatSpnFormat"].importGspn(
            net, c["File"](str(net_file)), c["File"](str(def_file))
        )
        if diagnostics is not None and str(diagnostics).strip():
            # A warning may describe a construct that the importer dropped.
            raise ValueError(
                "GreatSPN import reported diagnostics. Open the pair in the "
                "editor and save a checked PNPRO before searching:\n"
                + str(diagnostics)
            )
        pages = c["ArrayList"]()
        pages.add(net)
        project = c["ProjectData"](model.stem, pages)
        return net, project

    def _check_supported_features(self) -> None:
        c = self._classes
        exponential = False
        for node in self._net.nodes:
            name = str(node.getUniqueName())
            if isinstance(node, c["Place"]):
                if not node.isDiscrete():
                    raise ValueError(f"Continuous place unsupported: {name}")
                self._places.append(node)
            elif isinstance(node, c["Transition"]):
                if node.isContinuous() or node.isGeneral():
                    raise ValueError(
                        "Continuous/general-time transition unsupported by this "
                        f"discrete untimed search: {name}"
                    )
                exponential = exponential or bool(node.isExponential())
            elif isinstance(node, c["ClockVar"]):
                raise ValueError(f"Clock variables require timed-state search: {name}")
            elif isinstance(node, c["TemplateVariable"]):
                raise ValueError(
                    f"Instantiate template variable {name} in the editor first"
                )
        if exponential:
            self.warnings.append(
                "Untimed search: exponential rates/delays do not affect costs; "
                "the search selects the cost metric. Native immediate priorities apply."
            )

    def _validate(self) -> None:
        changed = self._classes["HashSet"]()
        changed.add(self._net)
        self._net.preparePageCheck()
        self._net.checkPage(self._project, changed, None, None)
        errors = []
        for diagnostic in self._net.getAllErrorsAndWarnings():
            description = str(diagnostic.getDescription())
            if diagnostic.isWarning():
                self.warnings.append(description)
            else:
                errors.append(description)
        if errors or not self._net.isPageCorrect():
            raise ValueError("Invalid GreatSPN net:\n" + "\n".join(errors))

    def require_place(self, name: str) -> Any:
        node = self._net.getNodeByUniqueName(name)
        if not isinstance(node, self._classes["Place"]):
            raise ValueError(f"No place named: {name}")
        return node

    def initial_state_for_places(self, place_names: Iterable[str]) -> Any:
        """Build a fresh start state, empty outside the named places.

        Named places retain their saved initial colored tokens and counts.
        Every other place starts at native zero, even if the input file has
        tokens there. Subsequent firings use ordinary GreatSPN semantics and
        may put tokens into any place.

        A JointState also stores enabled transitions and their color bindings.
        Editing its marking map would leave those caches stale. Instead, use
        Place.getInitMarkingEditable() / EditableValue.getValue(), setValue()
        to temporarily zero the other places and call Engine.getInitialState()
        again. These are the public GreatSPN editing and simulation APIs.
        Restore the original expressions and compiled net information before
        returning; ``initial_state`` and the file on disk are never changed.
        This method, like the adapter, is single-threaded.
        """
        selected = frozenset(place_names)
        # Resolve every name before changing anything, including when called
        # directly instead of through the CLI's checked marking patterns.
        for name in selected:
            self.require_place(name)

        saved = []
        for place in self._places:
            if str(place.getUniqueName()) not in selected:
                cell = place.getInitMarkingEditable()
                saved.append((cell, cell.getValue()))

        changed = []
        try:
            for cell, expression in saved:
                # Include a setter that fails after partially changing its
                # value in the rollback, too.
                changed.append((cell, expression))
                cell.setValue(self._project, self._net, "0")
            if changed:
                self._compile_parsed_info()
            state = self._native_call(self._classes["Engine"].getInitialState,
                self._net, self._template_binding, None, None, False
            )
            self._require_valid_state(state, "start marking with other places empty")
            return state
        finally:
            # Recompile after restoration as well: editable expressions can
            # invalidate parsed information. Never leave a partially changed
            # source model behind if compilation or simulation fails.
            restoration_error = None
            for cell, expression in reversed(changed):
                try:
                    cell.setValue(self._project, self._net, expression)
                except Exception as exc:
                    if restoration_error is None:
                        restoration_error = exc
            if changed:
                try:
                    self._compile_parsed_info()
                except Exception as exc:
                    if restoration_error is None:
                        restoration_error = exc
            if restoration_error is not None:
                raise RuntimeError(
                    "Cannot restore GreatSPN's saved initial expressions after "
                    "constructing the search start state"
                ) from restoration_error

    def _compile_parsed_info(self) -> None:
        context = self._classes["ParserContext"](self._net)
        context.templateVarsBinding = self._template_binding
        self._net.compileParsedInfo(context)

    def evaluate_marking(self, place: Any, expr: str) -> _RequiredMarking:
        """Compile a constant marking expression in this place's color domain.

        This creates a fresh parser context. It never changes a place's saved
        initial expression, the loaded net, or the simulator's initial state.
        """
        if not isinstance(expr, str) or not expr.strip():
            raise ValueError("A marking expression must be nonempty text")
        text = expr.strip()
        name = str(place.getUniqueName())
        neutral = bool(place.isInNeutralDomain())
        label = f"marking pattern for {name}"
        c = self._classes
        if text == "0":
            # GreatSPN's initial-expression parser has special handling for a
            # colored zero. Preserve the engine's own zero representation.
            value = self.initial_state.getMarkingOfPlace(place).makeZero()
        else:
            context = c["ParserContext"](self._net)
            context.templateVarsBinding = self._template_binding
            context.colorDomainOfExpr = place.getColorDomain()
            entry = (
                c["ParserEntryPoint"].INT_EXPR
                if neutral else c["ParserEntryPoint"].INT_MULTISET_EXPR
            )
            flags = int(c["ParserContext"].PF_CONST_EXPR)
            try:
                context.parseFormula(text, entry, label, flags)
                if context.hasParseErrors():
                    diagnostics = context.formatErrors(self._net, place)
                    details = "; ".join(
                        str(error.getDescription()) for error in diagnostics
                    )
                    raise ValueError(f"Invalid {label}: {details or text}")
                value = context.evaluate(
                    text, entry, c["EvaluationArguments"].NO_ARGS, label, flags
                )
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError(f"Cannot evaluate {label} {text!r}: {exc}") from exc

        if value is None:
            raise ValueError(f"No value produced for {label}")
        if neutral:
            if not value.isScalarInt():
                raise ValueError(f"{label} must be a nonnegative integer count")
            count = int(value.getScalarInt())
            if count < 0:
                raise ValueError(f"{label} cannot contain a negative token count")
            return _RequiredMarking(value, (), True, count)

        if not value.isMultiSetInt():
            raise ValueError(f"{label} must be an integer colored multiset")
        domain = value.getDomain()
        if domain is None or not bool(domain.equals(place.getColorDomain())):
            raise ValueError(f"{label} has the wrong color domain")
        components = []
        for i in range(int(value.numElements())):
            multiplicity = value.getValue(i)
            if not multiplicity.isScalarInt():
                raise ValueError(f"{label} contains a noninteger multiplicity")
            count = int(multiplicity.getScalarInt())
            if count < 0:
                raise ValueError(f"{label} cannot contain negative multiplicities")
            if count:
                components.append((value.getElement(i), count))
        return _RequiredMarking(value, tuple(components), False)

    @staticmethod
    def marking_matches(
        state: Any,
        place: Any,
        expected: _RequiredMarking,
        mode: str = "exact",
    ) -> bool:
        """Match one specified place; the caller combines places with AND.

        ``exact`` requires precisely the specified multiset in that place.
        ``contains`` permits additional tokens and colors. Other places are
        outside this method and remain unconstrained.
        """
        if mode not in {"exact", "contains"}:
            raise ValueError("Marking match mode must be 'exact' or 'contains'")
        if not isinstance(expected, _RequiredMarking):
            raise TypeError("Use evaluate_marking() to compile the expected marking")
        actual = state.getMarkingOfPlace(place)
        if expected.neutral:
            if not actual.isScalarInt():
                return False
            count = int(actual.getScalarInt())
            return count == expected.scalar_count if mode == "exact" else count >= expected.scalar_count

        # This handles empty multisets without depending on their internal
        # sparse representation; contains-zero is true for every marking.
        if not expected.components:
            return mode == "contains" or bool(actual.equalsZero())
        if actual.equalsZero() or not actual.isMultiSetInt():
            return False
        actual_domain = actual.getDomain()
        if actual_domain is None or not bool(actual_domain.equals(expected.value.getDomain())):
            return False
        for element, needed in expected.components:
            present = int(actual.getMultiSetColorCard(element).getScalarInt())
            if present < needed:
                return False
        return mode == "contains" or bool(expected.value.equals(actual))

    @staticmethod
    def occupied(state: Any, place: Any) -> bool:
        return not bool(state.getMarkingOfPlace(place).equalsZero())

    def key(self, state: Any) -> tuple[_FormulaKey, ...]:
        """Complete colored marking key; no display number, timing or text key."""
        return tuple(_FormulaKey(state.getMarkingOfPlace(place)) for place in self._places)

    def transition_names(self):
        """Return native transition identifiers for explicit packet classification."""
        return sorted(str(node.getUniqueName()) for node in self._net.nodes
                      if isinstance(node, self._classes["Transition"]))

    def successors(self, state: Any) -> Iterator[tuple[str, Any, int]]:
        """Fire alternatives lazily; each firing starts from the supplied state."""
        self._require_valid_state(state, "source marking")
        choices = [
            (str(enabled.firable.getUniqueName()) + " " + str(binding),
             enabled.firable, binding)
            for enabled in state.enabledTransitions
            for binding in enabled.bindings
        ]
        choices.sort(key=lambda choice: choice[0])
        for action, transition, binding in choices:
            observer = getattr(self, "_exploration_observer", None)
            if observer is not None:
                observer(action)
            firing = self._native_call(self._classes["Engine"].fireTransition,
                self._net, self._template_binding, None, None, state,
                transition, binding, None, 0.0, 1.0,
            )
            reached = firing.reachedState
            self._require_valid_state(reached, action)
            yield action, reached, 1

    def marking_values(self, state: Any) -> dict[str, str]:
        """Serialize complete markings with a canonical display for native zero.

        An empty colored multiset need not print as the numeric string ``0``.
        Ask the native value instead of guessing from its text, so exporters
        can hide empty places without dropping a real token whose color is 0.
        This changes display strings only; native state values stay intact.
        """
        markings = {}
        for place in self._places:
            value = state.getMarkingOfPlace(place)
            markings[str(place.getUniqueName())] = "0" if bool(value.equalsZero()) else str(value)
        return markings

    def describe_marking(self, state: Any) -> str:
        return str(self.marking_values(state))

    @staticmethod
    def _require_valid_state(state: Any, action: str) -> None:
        if state is None or state.isErrorState():
            description = "" if state is None else ": " + str(state.errorDescription)
            raise RuntimeError(f"GreatSPN simulation failed at {action}{description}")


# PNPRO visualization export



@dataclass(frozen=True)
class _Path:
    length: int
    first_rank: int
    rank: int
    cost: int
    transitions: tuple[str, ...]
    actions: tuple[str, ...]
    marking_ids: tuple[str, ...]
    structural_rank: int = 0
    variant_index: int = 0
    variants_complete: bool = False


@dataclass
class _TrieNode:
    marking_id: str
    depth: int
    action: str = ""
    children: dict[tuple[str, str], int] = field(default_factory=dict)
    ranks: list[int] = field(default_factory=list)
    final_labels: list[str] = field(default_factory=list)
    x: float = 0.0
    path_cost: int = 0


def _all_paths_page(root: ET.Element, paths: list[_Path], report: dict,
                    *, entry: dict | None = None) -> None:
    """A prefix trie preserves the recorded language without spurious joins.

    Nodes with an equal marking remain separate whenever their histories differ.
    A shared edge requires the same full action (including binding) and the same
    reached marking ID at the same prefix.  Loops are unrolled occurrences.
    """
    metric, weights = _report_cost_settings(report)
    trie = [_TrieNode(report["initial_marking_id"], 0)]
    for path in paths:
        current = 0
        for action, marking_id in zip(path.actions, path.marking_ids[1:]):
            key = action, marking_id
            child = trie[current].children.get(key)
            if child is None:
                child = len(trie)
                trie[current].children[key] = child
                increment = weights.get(action.split(maxsplit=1)[0], 0) if metric == "packets" else 1
                trie.append(_TrieNode(marking_id, trie[current].depth + 1, action,
                                      path_cost=trie[current].path_cost + increment))
            current = child
        trie[current].ranks.append(path.rank)
        if report["schema_version"] == 2:
            trie[current].final_labels.append(
                f"Path {path.structural_rank} / variant {path.variant_index}")

    # Iterative traversal keeps long firing sequences independent of Python's
    # recursion limit.  Leaf slots and subtree midpoints give disjoint siblings.
    pending = [0]
    next_leaf = 0
    while pending:
        current = pending.pop()
        if trie[current].children:
            pending.extend(reversed(tuple(trie[current].children.values())))
        else:
            trie[current].x = 4.0 + next_leaf * 46.0
            next_leaf += 1
    for node in reversed(trie):
        if node.children:
            xs = [trie[child].x for child in node.children.values()]
            node.x = (min(xs) + max(xs)) / 2.0

    page_name = ("AllDiscoveredPaths" if entry is None
                 else f"Path_L{entry['length']:04d}_P{entry['rank']:06d}")
    nodes, edges = _page(root, page_name)
    header = [
        f"All discovered shortest paths: {len(paths)} recorded concrete variants",
        "Shared prefixes have identical transition bindings and full markings.",
        "The root shows the initial marking; final ranks identify returned paths.",
        "Repeated markings after different histories stay separate.",
        "Every state shows the original places with nonzero token counts.",
        "Unlisted original CPN places have zero tokens in that state.",
    ]
    if report["schema_version"] == 2:
        entries = [path for group in report["length_groups"] for path in group["paths"]]
        if entry is None:
            header[:4] = [
                f"All discovered shortest paths: {len(entries)} distinct firing sequences / "
                f"{len(paths)} colored variants",
                "One path is an ordered transition-name sequence; colors do not create new paths.",
                "Shared prefixes have identical transition bindings and full markings.",
                "Colored choices remain correlated along each recorded variant.",
            ]
            complete_count = sum(item["variants_complete"] for item in entries)
            header.append(f"Colored variant enumeration: {complete_count} paths complete / "
                          f"{len(entries) - complete_count} incomplete.")
        else:
            completeness = "complete" if entry["variants_complete"] else "incomplete"
            sequence = " -> ".join(entry["transitions"]) or "(empty sequence)"
            header[:4] = [
                f"Path {entry['rank']}: {entry['length']} firings / {len(paths)} colored variants",
                _path_cost_label(report, entry.get("cost", entry["length"]), entry["length"]),
                *_lines(f"Transition sequence: {sequence}", width=76),
                f"Colored variant enumeration: {completeness}.",
                "Each complete route preserves a valid correlated binding and marking trace.",
            ]
            if not paths:
                header.append("No colored variants were recorded before interruption.")
    if entry is None:
        if metric == "packets":
            header.append("Path cost counts packets exchanged using the recorded transition costs.")
            if report.get("packet_cost_rule"):
                header.append("Each PACKET_SEND_ transition firing costs 1 packet; every other firing costs 0.")
            header.append("Internal transitions can cost zero; transition firing count is separate.")
        else:
            header.append("Path cost counts transition firings (one per fired transition).")
    status = report["summary"].get("status")
    if status is not None:
        header.extend(_lines(f"Search status: {status}; this shows returned paths only."))
    header_height = _note(nodes, "AllPathsInfo" if entry is None else "PathInfo", header, 2.0, 2.0,
                          width=68.0, fill="#fff7df")
    state_lines = []
    action_lines = []
    depth_count = max(node.depth for node in trie) + 1
    state_heights = [2.0] * depth_count
    action_heights = [2.0] * depth_count
    for index, node in enumerate(trie):
        lines = ["INITIAL" if node.depth == 0 else f"AFTER FIRING {node.depth}"]
        lines.extend(_marked_place_lines(report["markings"][node.marking_id], width=44))
        if node.final_labels:
            for final_label in node.final_labels:
                lines.extend(_lines(final_label, width=44))
        elif node.ranks:
            lines.extend(_lines("Final ranks: " + ", ".join(map(str, sorted(node.ranks))), width=44))
        if node.ranks:
            lines.append(_path_cost_label(report, node.path_cost, node.depth))
        state_lines.append(lines)
        state_heights[node.depth] = max(state_heights[node.depth], 1.1 * len(lines) + 1.0)
        firing = _lines(node.action, width=44)
        action_lines.append(firing)
        action_heights[node.depth] = max(action_heights[node.depth], 1.1 * len(firing) + 1.0)
    state_y = [2.0 + header_height + 4.0]
    firing_y = [0.0]
    for depth in range(1, depth_count):
        firing_y.append(state_y[-1] + state_heights[depth - 1] + 3.0)
        state_y.append(firing_y[-1] + action_heights[depth] + 3.0)
    for index, node in enumerate(trie):
        ET.SubElement(nodes, "place", {
            "name": f"V{index}", "marking": "1" if index == 0 else "0",
            # Names remain valid XML arc endpoints. Native alternative labels
            # hide those internal IDs; the adjacent note shows actual tokens.
            "alt-name-fn": "LATEX_TEXT", "shown-as": r"\phantom{X}",
            "x": f"{node.x:.2f}", "y": f"{state_y[node.depth]:.2f}",
        })
        _note(nodes, f"StateNote{index}", state_lines[index], node.x + 3.0,
              state_y[node.depth] - 0.5, width=40.0,
              fill="#eaf8ed" if node.ranks else "#f3f6ff")
        for child_index in node.children.values():
            child = trie[child_index]
            transition = f"E{child_index}"
            ET.SubElement(nodes, "transition", {
                "name": transition, "type": "EXP", "delay": "1.0",
                "alt-name-fn": "LATEX_TEXT", "shown-as": r"\phantom{X}",
                "x": f"{child.x + 0.55:.2f}", "y": f"{firing_y[child.depth]:.2f}",
            })
            _note(nodes, f"EdgeNote{child_index}", action_lines[child_index], child.x + 3.0,
                  firing_y[child.depth] - 0.5, width=40.0, fill="#eaf8ed")
            incoming = ET.SubElement(edges, "arc", {
                "tail": f"V{index}", "head": transition, "kind": "INPUT", "mult": "1",
            })
            # Route the fan-out below the parent's label box.  Direct diagonal
            # arcs would pass through the marking/rank annotations to its right.
            if abs(node.x - child.x) > 0.01:
                bus_y = state_y[node.depth] + state_heights[node.depth] + 1.5
                ET.SubElement(incoming, "point", {"x": f"{node.x + 1.0:.2f}", "y": f"{bus_y:.2f}"})
                ET.SubElement(incoming, "point", {"x": f"{child.x + 1.0:.2f}", "y": f"{bus_y:.2f}"})
            ET.SubElement(edges, "arc", {
                "tail": transition, "head": f"V{child_index}", "kind": "OUTPUT", "mult": "1",
            })


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _mapping(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    values = _list(value, label)
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{label} must contain nonempty strings")
    return tuple(values)


def _marking(value: Any, label: str) -> dict[str, str]:
    result = _mapping(value, label)
    if any(not isinstance(name, str) or not name or not isinstance(tokens, str)
           for name, tokens in result.items()):
        raise ValueError(f"{label} must map place names to marking strings")
    return result


def _validated(report: dict) -> tuple[dict[str, dict[str, str]], list[_Path]]:
    """Reject broken traces before creating or replacing the destination."""
    _mapping(report, "Grouped report")
    if type(report.get("schema_version")) is not int or report["schema_version"] not in (1, 2):
        raise ValueError("Expected grouped path report schema_version 1 or 2")
    metric, weights = _report_cost_settings(report)
    distinct = report["schema_version"] == 2
    if distinct and report.get("path_identity") != "transition_sequence":
        raise ValueError("Schema 2 requires path_identity='transition_sequence'")
    markings = _mapping(report.get("markings"), "markings")
    for identifier, marking in markings.items():
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("Marking IDs must be nonempty strings")
        _marking(marking, f"markings[{identifier!r}]")
    initial_id = report.get("initial_marking_id")
    if not isinstance(initial_id, str) or initial_id not in markings:
        raise ValueError("initial_marking_id must reference a registered marking")
    if _marking(report.get("initial_marking"), "initial_marking") != markings[initial_id]:
        raise ValueError("initial_marking disagrees with initial_marking_id")
    summary = _mapping(report.get("summary"), "summary")
    paths: list[_Path] = []
    seen_ranks: set[int] = set()
    seen_lengths: set[int] = set()
    structural_ranks: set[int] = set()
    structural_count = 0
    for group_index, group in enumerate(_list(report.get("length_groups"), "length_groups")):
        label = f"length_groups[{group_index}]"
        _mapping(group, label)
        length = _integer(group.get("length"), f"{label}.length")
        if length in seen_lengths:
            raise ValueError("Each firing length must appear in exactly one group")
        seen_lengths.add(length)
        entries = _list(group.get("paths"), f"{label}.paths")
        if _integer(group.get("path_count"), f"{label}.path_count") != len(entries):
            raise ValueError(f"{label}.path_count disagrees with its paths")
        variant_count = 0
        seen_transitions: set[tuple[str, ...]] = set()
        for entry_index, entry in enumerate(entries):
            entry_label = f"{label}.paths[{entry_index}]"
            _mapping(entry, entry_label)
            transitions = _strings(entry.get("transitions"), f"{entry_label}.transitions")
            if (len(transitions) != length
                    or _integer(entry.get("length"), f"{entry_label}.length") != length):
                raise ValueError(f"{entry_label} has an inconsistent firing length")
            expected_packet_cost = sum(weights.get(name, 0) for name in transitions)
            if metric == "packets" and distinct:
                if _integer(entry.get("cost"), f"{entry_label}.cost") != expected_packet_cost:
                    raise ValueError("Path packet cost disagrees with configured transition costs")
            if transitions in seen_transitions:
                raise ValueError("A transition sequence must have only one grouped path entry")
            seen_transitions.add(transitions)
            structural_count += 1
            structural_rank = 0
            variants_complete = False
            if distinct:
                structural_rank = _integer(entry.get("rank"), f"{entry_label}.rank", 1)
                if structural_rank in structural_ranks:
                    raise ValueError("Every distinct path must have a unique rank")
                structural_ranks.add(structural_rank)
                variants_complete = entry.get("variants_complete")
                if type(variants_complete) is not bool:
                    raise ValueError("variants_complete must be a boolean")
            variants = _list(entry.get("variants"), f"{entry_label}.variants")
            if not variants and (not distinct or variants_complete):
                raise ValueError(f"{entry_label}.variants cannot be empty")
            first_rank_value = entry.get("first_rank")
            if distinct and first_rank_value is None:
                supplied_ranks = [
                    _integer(_mapping(variant, "Variant").get("rank"), "Variant rank", 1)
                    for variant in variants
                ]
                first_rank_value = min(supplied_ranks, default=1)
            first_rank = _integer(first_rank_value, f"{entry_label}.first_rank", 1)
            ranks = []
            variant_indices: set[int] = set()
            for variant in variants:
                _mapping(variant, f"{entry_label} variant")
                rank = _integer(variant.get("rank"), "Variant rank", 1)
                if rank in seen_ranks:
                    raise ValueError("Every concrete variant must have a unique rank")
                seen_ranks.add(rank)
                ranks.append(rank)
                variant_index = 0
                if distinct:
                    variant_index = _integer(variant.get("variant_index"), "Variant index", 1)
                    if variant_index in variant_indices:
                        raise ValueError("Variant indices must be unique within each path")
                    variant_indices.add(variant_index)
                cost = _integer(variant.get("cost"), "Variant cost")
                if metric == "packets" and cost != expected_packet_cost:
                    raise ValueError("Variant packet cost disagrees with configured transition costs")
                actions = _strings(variant.get("actions"), "Variant actions")
                identifiers = _strings(variant.get("marking_ids"), "Variant marking_ids")
                if len(actions) != length or len(identifiers) != length + 1:
                    raise ValueError("Each variant needs one action per firing and one more marking")
                if tuple(action.split(maxsplit=1)[0] for action in actions) != transitions:
                    raise ValueError("Variant actions disagree with the grouped transition sequence")
                if identifiers[0] != initial_id:
                    raise ValueError("Every variant must start at initial_marking_id")
                if any(identifier not in markings for identifier in identifiers):
                    raise ValueError("Variant marking_ids reference an unknown marking")
                paths.append(_Path(length, first_rank, rank, cost, transitions, actions, identifiers,
                                   structural_rank, variant_index, variants_complete))
            if ranks and first_rank != min(ranks):
                raise ValueError("A grouped path's first_rank must be its minimum variant rank")
            variant_count += len(variants)
        if _integer(group.get("variant_count"), f"{label}.variant_count") != variant_count:
            raise ValueError(f"{label}.variant_count disagrees with its variants")
    expected_found = structural_count if distinct else len(paths)
    if "found" in summary and _integer(summary["found"], "summary.found") != expected_found:
        raise ValueError("summary.found disagrees with the number of recorded paths")
    if distinct:
        for container, key, expected in [(summary, "variant_count", len(paths)),
                                          (report, "variant_count", len(paths)),
                                          (report, "distinct_path_count", structural_count)]:
            if key in container and _integer(container[key], key) != expected:
                raise ValueError(f"{key} disagrees with the recorded paths or variants")
    paths.sort(key=lambda path: (path.cost if metric == "packets" else path.length,
                                path.length,
                                path.structural_rank if distinct else path.first_rank,
                                path.variant_index if distinct else path.rank))
    return markings, paths


def _literal(text: str) -> str:
    """Escape model-provided text for GreatSPN's LaTeX text-box renderer.

    Text boxes accept plain text with inline $...$ mathematics.  Escape user
    delimiters and TeX special characters; use self-contained inline math for
    the three symbols without portable text-mode escapes in JLaTeXMath.
    XML escaping is then performed independently by ElementTree.
    """
    if any(not (char in "\t\n\r" or "\x20" <= char <= "\ud7ff"
                or "\ue000" <= char <= "\ufffd" or "\U00010000" <= char <= "\U0010ffff")
           for char in text):
        raise ValueError("Annotation text contains a character forbidden by XML 1.0")
    escapes = {
        "\\": r"$\backslash$", "$": r"\$", "{": r"\{", "}": r"\}",
        "%": r"\%", "&": r"\&", "#": r"\#", "_": r"\_",
        "^": r"$\wedge$", "~": r"$\sim$",
    }
    return "".join(escapes.get(char, char) for char in text)


def _lines(text: str, width: int = 76) -> list[str]:
    # Wrap before inserting escape commands, so no command is split in half.
    # Never drop text, even when an individual marking expression is very long.
    return [wrapped for line in text.splitlines() or [""]
            for wrapped in textwrap.wrap(line, width=width, replace_whitespace=False,
                                         drop_whitespace=False, break_on_hyphens=False) or [""]]


def _marked_place_lines(marking: dict[str, str], *, width: int = 76) -> list[str]:
    """Display only nonzero places, without altering the complete source marking.

    The adapter normalizes native empty values to numeric zero. Match the
    whole numeric value, rather than searching for the character '0', so token
    colors such as <0> and positive multiplicities such as 10<red> survive.
    Unknown representations are retained conservatively.
    """
    lines = []
    for place_name, tokens in sorted(marking.items()):
        try:
            empty = Decimal(tokens.strip()).is_zero()
        except InvalidOperation:
            empty = False
        if not empty:
            lines.extend(_lines(f"{place_name} = {tokens}", width=width))
    return lines or ["(No marked places.)"]


def _note(nodes: ET.Element, name: str, lines: list[str], x: float, y: float,
          *, width: float = 60.0, fill: str = "#f3f6ff") -> float:
    height = max(2.0, 1.1 * len(lines) + 1.0)
    box = ET.SubElement(nodes, "text-box", {
        "name": name, "x": f"{x:.2f}", "y": f"{y:.2f}",
        "width": f"{width:.2f}", "height": f"{height:.2f}",
        "shape": "ROUND_RECTANGLE", "border-color": "#bac5d6",
        "fill-color": fill, "text-color": "#000000",
        "horiz-pos": "2", "vert-pos": "1", "shadow": "false",
    })
    box.text = "\n".join(_literal(line) for line in lines)
    return height


def _page(root: ET.Element, name: str) -> tuple[ET.Element, ET.Element]:
    page = ET.SubElement(root, "gspn", {
        "name": name, "show-timed-cmd": "false", "view-rates": "false",
        "show-color-cmd": "false", "show-fluid-cmd": "false",
    })
    return ET.SubElement(page, "nodes"), ET.SubElement(page, "edges")


def _path_page(root: ET.Element, path: _Path, markings: dict[str, dict[str, str]],
               report: dict) -> None:
    nodes, edges = _page(root, f"Path_L{path.length:04d}_R{path.rank:06d}")
    header = [
        f"Recorded firing path - rank {path.rank}, length {path.length}, cost {path.cost}",
        _path_cost_label(report, path.cost, path.length),
        "S0, S1, ... represent complete CPN marking occurrences.",
        "F1, F2, ... represent the recorded transition + color binding.",
        "One control token follows this recorded sequence in the token game.",
        "Nonzero original CPN markings appear beside the occurrence places.",
        "Unlisted original CPN places have zero tokens in that state.",
    ]
    status = report["summary"].get("status")
    if status is not None:
        header.extend(_lines(f"Search status: {status}; only returned variants are included."))
    y = 2.0 + _note(nodes, "PathInfo", header, 2.0, 2.0, width=68.0, fill="#fff7df") + 3.0
    for index, identifier in enumerate(path.marking_ids):
        ET.SubElement(nodes, "place", {
            "name": f"S{index}", "marking": "1" if index == 0 else "0",
            "x": "5.00", "y": f"{y:.2f}",
        })
        position = "INITIAL" if index == 0 else "AFTER FIRING " + str(index)
        if index == path.length:
            position += " / FINAL"
        marking_lines = [f"S{index}: original marking {identifier} ({position})"]
        marking_lines.extend(_marked_place_lines(markings[identifier]))
        y += _note(nodes, f"MarkingNote{index}", marking_lines, 10.0, y - 0.5) + 2.0
        if index == path.length:
            continue
        firing_name = f"F{index + 1}"
        ET.SubElement(nodes, "transition", {
            "name": firing_name, "type": "EXP", "delay": "1.0",
            "x": "5.55", "y": f"{y:.2f}",
        })
        # Ordinary unit arcs create exactly one executable chain.  In particular,
        # repeated original markings are separate occurrences, never merged.
        ET.SubElement(edges, "arc", {
            "tail": f"S{index}", "head": firing_name, "kind": "INPUT", "mult": "1",
        })
        ET.SubElement(edges, "arc", {
            "tail": firing_name, "head": f"S{index + 1}", "kind": "OUTPUT", "mult": "1",
        })
        action_lines = [f"Firing {index + 1}: {path.transitions[index]}"]
        action_lines.extend(_lines(path.actions[index]))
        y += _note(nodes, f"FiringNote{index + 1}", action_lines, 10.0, y - 0.5,
                   fill="#eaf8ed") + 2.0


def _overview_page(root: ET.Element, report: dict) -> None:
    nodes, _ = _page(root, "NoRecordedPaths")
    lines = [
        "No firing paths were recorded in this report.",
        "This project is a visualization of recorded search results.",
        "It does not replace or modify the original colored Petri net.",
        "An incomplete search does not prove that the goal is unreachable.",
    ]
    for key, value in sorted(report["summary"].items()):
        lines.extend(_lines(f"{key}: {value}"))
    _note(nodes, "Overview", lines, 2.0, 2.0, width=68.0, fill="#fff7df")


def write_pnpro(report: dict, destination: Path, overwrite: bool = False) -> int:
    """Write native PNPRO pages from a schema-1 or schema-2 grouped report.

    Return the number of generated pages. The first page combines all variants
    in a prefix tree. Schema 2 adds one page per distinct transition sequence;
    schema 1 adds one page per concrete variant. A report without results
    produces one explanatory overview page.
    Existing files are protected unless overwrite=True.  Validation finishes
    before any file is opened, so a malformed report cannot replace output.
    """
    destination = Path(destination).expanduser()
    if destination.suffix.lower() != ".pnpro":
        raise ValueError("PNPRO output must have a .PNPRO extension")
    markings, paths = _validated(report)
    metric = report.get("cost_metric", "firings")
    root = ET.Element("project", {"name": "Recorded shortest firing paths", "version": "121"})
    distinct_entries = ([] if report["schema_version"] != 2 else
                        sorted((entry for group in report["length_groups"] for entry in group["paths"]),
                               key=lambda entry: ((entry["cost"] if metric == "packets" else entry["length"]),
                                                  entry["length"], entry["rank"])))
    if distinct_entries:
        _all_paths_page(root, paths, report)
        for entry in distinct_entries:
            variants = [path for path in paths if path.structural_rank == entry["rank"]]
            _all_paths_page(root, variants, report, entry=entry)
    elif paths:
        _all_paths_page(root, paths, report)
        for path in paths:
            _path_page(root, path, markings, report)
    else:
        _overview_page(root, report)
    ET.indent(root, space="  ")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb" if overwrite else "xb") as stream:
        ET.ElementTree(root).write(stream, encoding="utf-8", xml_declaration=True)
        stream.write(b"\n")
    return len(distinct_entries if report["schema_version"] == 2 else paths) + 1


# Publication figures (standard-library SVG; no Java or plotting dependency)


def _exchange_actor(name):
    """Read an explicit leading actor tag; TCP flags never determine direction."""
    name = name.removeprefix(PACKET_SEND_PREFIX).upper()
    if re.match(r'^(ATTACKER|CLIENT|A)(?:[_:\s-]|$)', name):
        return 'attacker'
    if re.match(r'^(SERVER|LINUX|S|R)(?:[_:\s-]|$)', name):
        return 'server'
    return 'unknown'


def _packet_caption(name):
    label = name.removeprefix(PACKET_SEND_PREFIX)
    label = re.sub(r'^(ATTACKER|CLIENT|SERVER|LINUX|A|S|R)(?:[_:\s-]+|$)', '', label, flags=re.I)
    return label.replace('_', ' ').strip() or name


def write_images(report: dict, destination: Path, overwrite: bool = False) -> int:
    """Packet-first sequence diagrams, full trace appendices and a spatial tree.

    The main diagram contains packet sends only. Exact internal firings and
    correlated markings remain in each variant's trace appendix. The combined
    trie groups packet transition names, retaining every firing-path terminal.
    """
    markings, concrete = _validated(report)
    if report['schema_version'] != 2:
        raise ValueError('Image export requires a schema-2 grouped report')
    entries = sorted((e for g in report['length_groups'] for e in g['paths']),
                     key=lambda e: (e['cost'], e['length'], e['rank']))
    destination = Path(destination).expanduser()
    if destination.is_symlink():
        raise ValueError('Image directory must not be a symbolic link')
    if destination.exists() and (not destination.is_dir() or (any(destination.iterdir()) and not overwrite)):
        raise FileExistsError(f'Image output exists: {destination}; use --overwrite or another --images-dir')
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    old_files = []
    try:
        old_files = json.loads((destination/'manifest.json').read_text(encoding='utf-8')).get('files', [])
    except (ValueError, OSError, AttributeError):
        pass
    ns = 'http://www.w3.org/2000/svg'
    ET.register_namespace('', ns)
    ink, muted, blue, orange, green = '#19364b', '#526675', '#0072b2', '#b65b00', '#087b65'
    metric, costs = _report_cost_settings(report)
    unit = 'packets' if metric == 'packets' else 'firings'
    status = report.get('summary', {}).get('status', 'unknown')
    grouped = defaultdict(list)
    for path in concrete:
        grouped[path.structural_rank].append(path)
    unknown = set()
    files = []

    def node(parent, tag, attrs=None, value=None):
        element = ET.SubElement(parent, '{'+ns+'}'+tag, {k: str(v) for k, v in (attrs or {}).items()})
        element.text = value
        return element

    def text(parent, x, y, value, size=15, color=ink, bold=False, mono=False, anchor=None):
        attrs = {'x':x, 'y':y, 'font-size':size, 'fill':color, 'font-weight':'700' if bold else '400',
                 'font-family':'DejaVu Sans Mono, monospace' if mono else 'Arial, DejaVu Sans, sans-serif'}
        if anchor:
            attrs['text-anchor'] = anchor
        return node(parent, 'text', attrs, str(value))

    def rect(parent, x, y, w, h, fill, stroke='none', radius=10):
        return node(parent, 'rect', dict(x=x, y=y, width=w, height=h, rx=radius, fill=fill, stroke=stroke))

    def wrapped(parent, x, y, value, width=120, size=14, color=ink, mono=False, bold=False, anchor=None):
        values = _lines(str(value), width=width)
        leading = size+7
        for i, value in enumerate(values):
            text(parent, x, y+i*leading, value, size, color, bold, mono, anchor)
        return len(values)*leading

    def line(parent, x1, y1, x2, y2, color=muted, weight=2, dashed=False):
        attrs = {'x1':x1, 'y1':y1, 'x2':x2, 'y2':y2, 'stroke':color, 'stroke-width':weight}
        if dashed:
            attrs['stroke-dasharray'] = '6 7'
        return node(parent, 'line', attrs)

    def canvas(title, width=1280):
        root = ET.Element('{'+ns+'}svg', {'width':str(width), 'role':'img', 'data-layout-version':'11'})
        node(root, 'title', value=title)
        node(root, 'desc', value='Attacker and Linux server packet-exchange diagrams. Directional arrowheads show explicit sender tags. Detailed appendices preserve colored bindings and nonzero markings. Tree branches represent alternative packet prefixes.')
        rect(root, 0, 0, width, '100%', '#ffffff', radius=0)
        return root

    def save(root, filename, height, width=1280):
        root.set('height', str(height))
        root.set('viewBox', f'0 0 {width} {height}')
        _atomic_output(destination/filename, lambda p:ET.ElementTree(root).write(p, encoding='utf-8', xml_declaration=True), '.svg')
        files.append(filename)

    def packet_arrow(parent, name, y, ax, sx, weight=4):
        actor = _exchange_actor(name)
        if actor == 'unknown':
            unknown.add(name)
        group = node(parent, 'g', {'data-kind':'packet-arrow', 'data-sender':actor, 'data-transition':name})
        node(group, 'title', value=name)
        color = orange if actor == 'attacker' else blue if actor == 'server' else muted
        start, end = (sx, ax) if actor == 'server' else (ax, sx)
        line(group, start, y, end, y, color, weight, actor == 'unknown')
        if actor != 'unknown':
            direction = 1 if end > start else -1
            tip = max(12, weight*4)
            node(group, 'polygon', {'data-kind':'arrowhead', 'points':f'{end},{y} {end-tip*direction},{y-8} {end-tip*direction},{y+8}', 'fill':color})
            node(group, 'circle', {'cx':start, 'cy':y, 'r':4, 'fill':color})
        return color

    def lifelines(parent, y, bottom, ax=250, sx=1030, compact=False):
        font = 13 if compact else 22
        w = 134 if compact else 242
        h = 32 if compact else 50
        for x, label, color in [(ax, 'ATTACKER', orange), (sx, 'LINUX SERVER', blue)]:
            rect(parent, x-w/2, y, w, h, color, radius=7)
            text(parent, x, y+h/2+font*.35, label, font, '#ffffff', True, anchor='middle')
            line(parent, x, y+h, x, bottom, color, 1.5, True)

    def mark_text(marking):
        return '; '.join(_marked_place_lines(marking, width=100000))

    def summary(entry, variants, parent):
        group = node(parent, 'g', {'data-kind':'summary'})
        text(group, 40, 35, f'PATH {entry["rank"]:06d}  /  PACKET EXCHANGE', 14, muted, True)
        text(group, 40, 76, 'Attacker ↔ Linux server', 32, ink, True)
        complete = 'complete' if entry['variants_complete'] else 'INCOMPLETE'
        packets = [name for name in entry['transitions'] if name.startswith(PACKET_SEND_PREFIX)]
        badges = [(f'{entry["cost"]} {unit}', 'PATH COST'),
                  (str(entry['length']), 'TRANSITION FIRINGS'),
                  (str(len(variants)), 'COLORED VARIANTS'), (complete, 'VARIANT ENUMERATION')]
        for i, (value, label) in enumerate(badges):
            x = 40+i*300
            rect(group, x, 104, 280, 73, '#edf4f8')
            text(group, x+16, 130, label, 11, muted, True)
            text(group, x+16, 158, value, 23, green if i == 3 and complete == 'complete' else ink, True)
        details = node(group, 'g')
        y = 211
        text(details, 58, y, 'PATH SUMMARY', 13, muted, True)
        y += 27
        packet_word = []
        for name in packets:
            actor = _exchange_actor(name)
            direction = 'Attacker → Server' if actor == 'attacker' else 'Server → Attacker' if actor == 'server' else 'Sender unknown'
            packet_word.append(direction+': '+_packet_caption(name))
        records = [('Packet sequence', '  /  '.join(packet_word) or '(no packet sends)'),
                   ('Transition sequence', ' → '.join(entry['transitions']) or '(empty firing sequence)'),
                   ('Initial marking', mark_text(report['initial_marking']))]
        final_states = OrderedDict()
        for path in variants:
            value = mark_text(markings[path.marking_ids[-1]])
            final_states.setdefault(value, []).append(path.variant_index)
        if len(final_states) <= 6:
            for value, indexes in final_states.items():
                records.append(('Final marking / variants '+', '.join(map(str, indexes)), value))
        else:
            records.append(('Final markings', f'{len(final_states)} distinct nonzero markings; full values are in the variant trace appendix.'))
        if not variants:
            records.append(('Final markings', 'Not recorded yet; colored variant enumeration is incomplete.'))
        for label, value in records:
            y += wrapped(details, 58, y, label+': '+value, width=139, size=13, mono=True)+10
        y += wrapped(details, 58, y, f'Colored variant enumeration: {complete}. Each variant preserves one correlated sequence of bindings and markings. Search status: {status}.', width=139, size=13, color=muted)
        y += 12
        rect(group, 40, 191, 1200, y-191, '#f8fafb', '#dbe5eb')
        # Place the background behind the text without relying on CSS layering.
        group.remove(details)
        group.append(details)
        return y+36

    for entry in entries:
        variants = sorted(grouped[entry['rank']], key=lambda p:p.variant_index)
        root = canvas(f'Path {entry["rank"]} / attacker–server packet exchange')
        y = summary(entry, variants, root)
        packet_steps = [i for i, name in enumerate(entry['transitions']) if name.startswith(PACKET_SEND_PREFIX)]
        internal_count = entry['length']-len(packet_steps)
        text(root, 40, y, 'PACKET EXCHANGE', 18, ink, True)
        text(root, 40, y+25, f'Packet order runs downward. {internal_count} internal firings are listed in the trace appendix below.', 14, muted)
        y += 56
        if not variants:
            text(root, 40, y, 'No colored trace recorded yet. See the path summary for the selected firing sequence.', 15, muted)
            y += 50
        for path in variants:
            group = node(root, 'g', {'data-kind':'exchange-panel', 'data-variant':path.variant_index})
            rect(group, 40, y, 1200, 39, '#edf4f8')
            text(group, 58, y+26, f'VARIANT {path.variant_index}  /  correlated colored binding trace', 15, ink, True)
            y += 60
            background = node(group, 'g')
            foreground = node(group, 'g')
            lane_top = y
            y += 115
            running = 0
            cumulative = []
            for name in entry['transitions']:
                running += costs.get(name, 0) if metric == 'packets' else 1
                cumulative.append(running)
            for number, step in enumerate(packet_steps, 1):
                name = entry['transitions'][step]
                action = path.actions[step]
                binding = action[len(name):].strip() if action.startswith(name) else action
                caption = _packet_caption(name)
                caption_lines = _lines(caption, width=54)
                text(foreground, 640, y-17, f'PACKET {number}', 12, muted, True, anchor='middle')
                for index, value in enumerate(caption_lines):
                    text(foreground, 640, y+14+index*26, value, 21, ink, True, anchor='middle')
                arrow_y = y+39+(len(caption_lines)-1)*26
                color = packet_arrow(foreground, name, arrow_y, 250, 1030)
                text(foreground, 220, arrow_y+5, str(number), 14, color, True, anchor='end')
                by = arrow_y+28
                if binding:
                    by += wrapped(foreground, 640, by, binding, width=83, size=13, color=muted, mono=True, anchor='middle')
                text(foreground, 640, by+7, f'Firing {step+1} / cumulative cost {cumulative[step]} {unit}', 12, muted, anchor='middle')
                if _exchange_actor(name) == 'unknown':
                    text(foreground, 640, by+30, 'Sender unlabelled: direction is unknown.', 13, muted, True, anchor='middle')
                    by += 25
                y = by+78
            if not packet_steps:
                text(foreground, 640, y, 'No packet sends in this firing sequence.', 18, muted, anchor='middle')
                y += 80
            rect(foreground, 468, y-20, 344, 42, '#e5f3ee', '#b8dbd0')
            text(foreground, 640, y+6, 'RECORDED GOAL MARKING', 14, green, True, anchor='middle')
            lifelines(background, lane_top, y+36)
            y += 78
        appendix = node(root, 'g', {'data-kind':'trace-appendix'})
        text(appendix, 40, y, 'TRACE ANNOTATIONS', 18, ink, True)
        text(appendix, 40, y+25, 'Exact firing bindings and nonzero markings for every recorded variant. Unlisted places have zero tokens.', 14, muted)
        y += 56
        for path in variants:
            text(appendix, 40, y, f'Variant {path.variant_index} / complete recorded firing trace', 15, ink, True)
            y += 25
            rect(appendix, 40, y, 1200, 32, ink)
            for x, label in [(52, 'STEP / COST'), (170, 'TRANSITION & COLORED BINDING'), (680, 'NONZERO MARKING')]:
                text(appendix, x, y+21, label, 11, '#ffffff', True)
            y += 32
            cumulative = 0
            for step, marking_id in enumerate(path.marking_ids):
                action = 'Initial marking' if step == 0 else path.actions[step-1]
                if step:
                    cumulative += costs.get(entry['transitions'][step-1], 0) if metric == 'packets' else 1
                action_lines = _lines(action, width=57)
                marking_lines = _marked_place_lines(markings[marking_id], width=61)
                h = max(len(action_lines), len(marking_lines))*20+22
                rect(appendix, 40, y, 1200, h, '#f4f8fb' if step%2 == 0 else '#ffffff', radius=0)
                text(appendix, 52, y+23, f'{step:02d} / {cumulative}', 12, muted, mono=True)
                for i, value in enumerate(action_lines):
                    text(appendix, 170, y+23+i*20, value, 12, mono=True)
                for i, value in enumerate(marking_lines):
                    text(appendix, 680, y+23+i*20, value, 12, green if step == path.length else ink, mono=True)
                y += h
            y += 38
        save(root, f'path_{entry["rank"]:06d}.svg', y+20)

    # Actual spatial trie: one mini packet exchange per node, with siblings
    # positioned in disjoint leaf intervals and the shared prefix above them.
    tree = [{'parent':None, 'name':None, 'depth':0, 'children':{}, 'ends':[], 'count':0}]
    for entry in entries:
        current = 0
        tree[0]['count'] += 1
        for name in entry['transitions']:
            if not name.startswith(PACKET_SEND_PREFIX):
                continue
            child = tree[current]['children'].get(name)
            if child is None:
                child = len(tree)
                tree[current]['children'][name] = child
                tree.append({'parent':current, 'name':name, 'depth':tree[current]['depth']+1, 'children':{}, 'ends':[], 'count':0})
            current = child
            tree[current]['count'] += 1
        tree[current]['ends'].append(entry)
    pending = [0]
    slot = 0
    while pending:
        index = pending.pop()
        children = tuple(tree[index]['children'].values())
        if children:
            pending.extend(reversed(children))
        else:
            tree[index]['x'] = 320+slot*620
            slot += 1
    level_heights = defaultdict(int)
    for item in reversed(tree):
        if item['children']:
            xs = [tree[i]['x'] for i in item['children'].values()]
            item['x'] = (min(xs)+max(xs))/2
        raw_lines = len(_lines(item['name'] or 'Saved initial marking', width=54))
        pretty_lines = len(_lines(_packet_caption(item['name']), width=38)) if item['name'] else 1
        item['height'] = (max(194, 160+pretty_lines*23)+raw_lines*18+len(item['ends'])*48+24
                          if item['name'] else 234+len(item['ends'])*48)
        level_heights[item['depth']] = max(level_heights[item['depth']], item['height'])
    level_y = {}
    current_y = 250
    for depth in sorted(level_heights):
        level_y[depth] = current_y
        current_y += level_heights[depth]+105
    tree_width = max(1280, slot*620+20)
    offset = tree_width/2-320-(slot-1)*310
    for item in tree:
        item['x'] += offset
    combined = canvas('All discovered paths / packet-exchange tree', tree_width)
    text(combined, 40, 42, 'PACKET-EXCHANGE TREE', 28, ink, True)
    text(combined, 40, 78, f'{len(entries)} firing paths / {len(concrete)} colored variants / ranked by {unit} / search status: {status}', 16, muted)
    text(combined, 40, 110, 'Follow one root-to-terminal branch. Each node shows one send between attacker and Linux server.', 15, ink)
    text(combined, 40, 139, 'Shared packet prefixes are drawn once. Sibling branches are alternatives. Terminal links open the complete path figures.', 14, muted)
    text(combined, 40, 166, 'Grouping is visual: distinct firing paths keep separate terminal links; correlated colored bindings and markings remain in the path figures.', 14, muted)
    edge_layer = node(combined, 'g')
    node_layer = node(combined, 'g')
    for index, item in enumerate(tree):
        x, top = item['x'], level_y[item['depth']]
        if item['parent'] is not None:
            parent = tree[item['parent']]
            px = parent['x']
            py = level_y[parent['depth']]+parent['height']
            middle = top-53
            edge = node(edge_layer, 'path', {'data-kind':'tree-edge', 'data-parent':item['parent'], 'data-child':index,
                        'd':f'M {px} {py} V {middle} H {x} V {top}', 'stroke':'#7b94a5', 'stroke-width':2.5, 'fill':'none'})
            node(edge_layer, 'polygon', {'points':f'{x},{top} {x-6},{top-10} {x+6},{top-10}', 'fill':'#7b94a5'})
        group = node(node_layer, 'g', {'data-kind':'tree-node', 'data-index':index, 'data-depth':item['depth'],
                                      'data-x':x, 'data-y':top, 'transform':f'translate({x-280},{top})'})
        rect(group, 0, 0, 560, item['height'], '#ffffff', '#c9d9e3')
        rect(group, 0, 0, 560, 39, '#eaf2f7')
        text(group, 20, 26, 'START' if index == 0 else f'PACKET {item["depth"]}', 13, ink, True)
        text(group, 540, 26, f'{item["count"]} firing paths', 12, muted, anchor='end')
        if item['name']:
            caption = _packet_caption(item['name'])
            size_height = wrapped(group, 280, 111, caption, width=38, size=16, bold=True, anchor='middle')
            arrow_y = 111+size_height+5
            lifelines(group, 58, max(176, arrow_y+28), 100, 460, True)
            packet_arrow(group, item['name'], arrow_y, 100, 460, 3)
            if _exchange_actor(item['name']) == 'unknown':
                text(group, 280, arrow_y+25, 'Sender unknown', 12, muted, True, anchor='middle')
            yy = max(194, arrow_y+44)
            yy += wrapped(group, 20, yy, item['name'], width=54, size=11, color=muted, mono=True)
        else:
            lifelines(group, 58, 176, 100, 460, True)
            text(group, 280, 130, 'Saved initial marking', 17, ink, True, anchor='middle')
            yy = 210
        for entry in item['ends']:
            link = node(group, 'a', {'href':f'path_{entry["rank"]:06d}.svg', 'data-kind':'path-terminal'})
            rect(link, 14, yy-16, 532, 42, '#e6f3ed')
            complete = 'complete' if entry['variants_complete'] else 'INCOMPLETE'
            text(link, 25, yy+1, f'PATH {entry["rank"]} / {entry["cost"]} {unit} / {entry["length"]} firings', 13, green, True)
            text(link, 25, yy+19, f'{len(entry["variants"])} colored variants ({complete})', 11, muted)
            yy += 48
    if not entries:
        text(combined, 40, 213, 'No paths recorded. Search may be incomplete; consult the JSON summary.', 16, muted)
    save(combined, 'all_paths.svg', current_y, tree_width)
    overview = deepcopy(combined)
    overview.find('{'+ns+'}title').text = 'Packet exchange overview / spatial shared-prefix tree'
    save(overview, 'overview.svg', current_y, tree_width)
    manifest = {'format':'SVG', 'layout':'packet_first_lifelines_and_spatial_prefix_tree', 'layout_version':11,
                'files':files, 'paths':len(entries), 'status':status, 'unknown_packet_senders':sorted(unknown),
                'actor_tags':'Explicit leading A/ATTACKER/CLIENT or S/R/SERVER/LINUX after PACKET_SEND_, delimited by underscore, colon, space or hyphen.',
                'description':'Top summaries and packet-only sequence diagrams; exact correlated firing traces in appendices. Combined images form a spatial packet-prefix tree.'}
    for name in old_files if isinstance(old_files, list) else []:
        if isinstance(name, str) and re.fullmatch(r'path_[0-9]{6,}\.svg', name) and name not in files:
            (destination/name).unlink(missing_ok=True)
    _atomic_output(destination/'manifest.json', lambda p:p.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8'))
    if unknown:
        print(f'SVG warning: {len(unknown)} packet transition(s) have no explicit sender tag. '
              'Their direction is marked unknown; use PACKET_SEND_A_ or PACKET_SEND_S_ actor tags in the model.', file=sys.stderr)
    return len(files)


# Command-line interface



class PathCostPolicy:
    """Packet cost is one per firing of a PACKET_SEND_-prefixed transition."""

    def __init__(self, metric, transition_costs=None, packet_cost_rule=None):
        self.metric = metric
        self.transition_costs = dict(transition_costs or {})
        self.packet_cost_rule = packet_cost_rule

    def cost(self, name):
        if self.metric == "firings":
            return 1
        if name not in self.transition_costs:
            raise ValueError(f"Transition {name!r} is missing from the packet-cost map")
        return self.transition_costs[name]

    @classmethod
    def configure(cls, adapter, args, saved=None):
        metric = getattr(args, "cost_metric", "packets")
        if metric == "firings":
            return cls("firings")
        method = getattr(adapter, "transition_names", None)
        if method is None:
            raise ValueError("The backend must expose native transition names for the PACKET_SEND_ cost rule")
        names = sorted(set(method()))
        # Recompute from native names on every run. Resume checks the complete
        # map before reusing a frontier, including maps saved by older versions.
        costs = {name: int(name.startswith(PACKET_SEND_PREFIX)) for name in names}
        rule = {
            "cost_metric": "packets", "method": "transition_name_prefix_v1",
            "prefix": PACKET_SEND_PREFIX, "case_sensitive": True,
            "matching_transition_cost": 1, "other_transition_cost": 0,
            "packet_transitions": [name for name in names if costs[name]],
            "transition_costs": costs,
            "rule": "Each firing of a transition whose native name starts with PACKET_SEND_ costs 1 packet; every other firing costs 0.",
        }
        return cls("packets", costs, rule)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION} (SVG path figures)")
    result.add_argument("model", type=Path, nargs="?", help=".PNPRO, .net, or .def file")
    result.add_argument("--greatspn", type=Path, action="append", default=[],
                        help="Editor JAR or directory of JARs; may be repeated")
    result.add_argument("--start", nargs="+", action="append", metavar="PLACE",
                        help="Optional: keep saved tokens in these places and initialize unlisted places to zero. When omitted, use the complete initial marking saved in the model. Repeated sets are OR alternatives; their union is retained. Explicit marking constraints still work")
    result.add_argument("--end", nargs="+", action="append", metavar="PLACE",
                        help="Goal set: every named place contains >=1 token of any valid color. Unlisted places are unconstrained; repeat for OR sets")
    result.add_argument("--page", help="GSPN page name in a multipage PNPRO")
    result.add_argument("--cost-metric", choices=("packets", "firings"), default="packets",
                        help="Path objective (default: packets, 1 per PACKET_SEND_ transition firing and 0 otherwise; firings uses 1 per firing)")
    result.add_argument("--inspect-costs", action="store_true",
                        help="Print the PACKET_SEND_ prefix rule and complete transition-cost map without searching")
    result.add_argument("--list-transitions", action="store_true",
                        help="List native transition names, then exit")
    result.add_argument("--k", type=int, default=1000,
                        help="Number of distinct ordered transition sequences; colored bindings are variants of one path")
    result.add_argument("--results-dir", type=Path, default=Path("results"), metavar="FOLDER",
                        help="Folder for result filenames (default: results/ in the current working directory)")
    result.add_argument("--out", type=Path, default=Path("paths.jsonl"),
                        help="JSONL filename in --results-dir (default: paths.jsonl); a path with a parent directory or an absolute path overrides that folder")
    pnpro_options = result.add_mutually_exclusive_group()
    pnpro_options.add_argument("--pnpro-out", "--pnpro", dest="pnpro", type=Path, metavar="FILE",
                               help="Optional legacy PNPRO visualization; SVG images are the default")
    pnpro_options.add_argument("--no-pnpro", action="store_true",
                               help="Disable legacy PNPRO output (already off unless --pnpro-out is supplied)")
    result.add_argument("--images-dir", type=Path, metavar="FOLDER",
                        help="SVG figure folder (default: <JSONL stem>_images beside JSONL)")
    result.add_argument("--no-images", action="store_true", help="Disable SVG figure output")
    result.add_argument("--export-images", type=Path, metavar="REPORT",
                        help="Export SVG figures from grouped JSON without Java; optionally set --images-dir")
    result.add_argument("--seconds", type=float, default=60,
                        help="Cooperative search limit, excluding import; 0 unlimited")
    result.add_argument("--max-expansions", type=int, default=500_000,
                        help="Expanded transition-sequence prefixes; 0 unlimited")
    result.add_argument("--max-queue", type=int, default=1_000_000,
                        help="Pending and staged transition-sequence prefixes; 0 unlimited")
    result.add_argument("--cache-states", type=int, default=10_000,
                        help="Bounded LRU successor cache; 0 disabled")
    result.add_argument("--java-heap", default="2g", help="Java engine heap limit")
    result.add_argument("--jvm", help="Optional absolute libjvm.so/jvm.dll path")
    result.add_argument("--inspect", action="store_true", help="Print places and saved marking")
    result.add_argument("--overwrite", action="store_true")
    result.add_argument("--debug", action="store_true",
                        help="Show raw native timing messages and Python error tracebacks")
    result.add_argument("--checkpoint", type=Path, metavar="FILE",
                        help="Automatic resume checkpoint (default: JSONL path + .checkpoint.json.gz)")
    result.add_argument("--checkpoint-every", type=float, default=30.0, metavar="SECONDS",
                        help="Checkpoint interval during search (default: 30; 0 saves only before search and at stops)")
    result.add_argument("--fresh", action="store_true",
                        help="Start over and replace the output/checkpoint instead of reusing saved work")
    result.add_argument("--no-prompt", action="store_true",
                        help="Save and stop at the time limit without asking for additional seconds")
    result.add_argument("--export-pnpro", type=Path, metavar="REPORT",
                        help="Export a grouped JSON report with --pnpro-out FILE; no Java required")
    return result


def _output_path(filename: Path, folder: Path) -> Path:
    """Put bare filenames in the result folder and honor explicit paths."""
    path = filename.expanduser()
    if not path.is_absolute() and path.parent == Path("."):
        path = folder.expanduser() / path
    return path.resolve()


def json_line(stream, value):
    stream.write(json.dumps(value, ensure_ascii=False) + "\n")
    stream.flush()


def _atomic_output(path, writer, suffix=".tmp"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=suffix, dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        writer(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _save_checkpoint(path, data):
    def write(temporary):
        with temporary.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=1, mtime=0) as packed:
                with io.TextIOWrapper(packed, encoding="utf-8") as stream:
                    json.dump(data, stream, ensure_ascii=False, separators=(",", ":"))
            raw.flush()
            os.fsync(raw.fileno())
    _atomic_output(path, write)


def _read_checkpoint(path):
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            saved = json.load(stream)
        if not isinstance(saved, dict) or saved.get("checkpoint_schema") != 1:
            raise ValueError("unsupported checkpoint format")
        return saved
    except (OSError, ValueError, EOFError) as exc:
        raise ValueError(f"Cannot read checkpoint {path}: {exc}. Use --fresh to start a new search, "
                         "or choose another --results-dir.") from exc


def _restore_report(report):
    if report.get("schema_version") != 2:
        raise ValueError("Checkpoint needs a schema-2 distinct-path report")
    _validated(report)
    collector = DistinctPaths(report["initial_marking"], cost_metric=report.get("cost_metric", "firings"),
                              transition_costs=report.get("transition_costs"))
    collector._markings = deepcopy(report["markings"])
    collector._marking_ids = {collector._marking_key(marking): identifier
                              for identifier, marking in collector._markings.items()}
    collector._paths = {entry["rank"]: deepcopy(entry)
                        for group in report["length_groups"] for entry in group["paths"]}
    collector._sequences = {tuple(entry["transitions"]) for entry in collector._paths.values()}
    collector._variant_count = sum(len(entry["variants"]) for entry in collector._paths.values())
    return collector


def _check_session_report(session, collector):
    if session.stats.found != len(collector._paths) or session.stats.variant_count != collector._variant_count:
        raise ValueError("Checkpoint search counters disagree with its recorded paths")
    active = session.active
    partial = (active["rank"] if active is not None and active["phase"] == "variants" else None)
    for rank, entry in collector._paths.items():
        if rank == partial:
            if entry["variants_complete"] or len(entry["variants"]) != active["variant_index"]:
                raise ValueError("Checkpoint's partial colored variant cursor disagrees with its report")
        elif not entry["variants_complete"]:
            raise ValueError("Checkpoint contains an unfinished path without its search cursor")


def _write_reports(out, summary_path, grouped_path, pnpro_path, metadata, report):
    def flat(temporary):
        with temporary.open("w", encoding="utf-8") as stream:
            json_line(stream, metadata)
            entries = sorted((entry for group in report["length_groups"] for entry in group["paths"]),
                             key=lambda entry: entry["rank"])
            for entry in entries:
                json_line(stream, {"type": "path", "rank": entry["rank"], "cost": entry["cost"],
                                   "firings": entry["length"], "transitions": entry["transitions"]})
                for variant in entry["variants"]:
                    json_line(stream, {"type": "variant", "path_rank": entry["rank"],
                                       "variant_index": variant["variant_index"], "rank": variant["rank"],
                                       "cost": variant["cost"], "firings": entry["length"],
                                       "actions": variant["actions"], "transitions": entry["transitions"],
                                       "marking_ids": variant["marking_ids"],
                                       "final_marking": report["markings"][variant["marking_ids"][-1]]})
                json_line(stream, {"type": "path_summary", "path_rank": entry["rank"],
                                   "variant_count": len(entry["variants"]),
                                   "variants_complete": entry["variants_complete"]})
            json_line(stream, {"type": "summary", "data": report["summary"]})
    _atomic_output(out, flat)
    for destination, content in ((summary_path, report["summary"]), (grouped_path, report)):
        def write(temporary, content=content):
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(content, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        _atomic_output(destination, write)
    if metadata.get("images_output"):
        write_images(report, Path(metadata["images_output"]), overwrite=True)
    if pnpro_path is not None:
        _atomic_output(pnpro_path, lambda temporary: write_pnpro(report, temporary, overwrite=True), ".PNPRO")


def _extra_seconds(default):
    """Ask only in an interactive terminal; EOF/interruption means stop safely."""
    while True:
        try:
            answer = input(f"Time limit reached; checkpoint saved. Add how many seconds? "
                           f"[Enter = stop, 0 = unlimited; previous allowance {default:g}s]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nStopped safely; resume the saved search next time.", file=sys.stderr)
            return None
        if not answer:
            return None
        try:
            seconds = float(answer)
            if not isfinite(seconds) or seconds < 0:
                raise ValueError
            return seconds
        except ValueError:
            print("Enter a nonnegative number of seconds, or press Enter to stop.", file=sys.stderr)


def _progress_lines(details, requested, cost_metric="firings"):
    """Keep packet costs, firing counts and unconfirmed ranks distinct."""
    if details is None:
        return ["Current candidate: none (frontier empty)."]
    unit = "packets" if cost_metric == "packets" else "firings"
    rank = details["result_rank"]
    result = [f"Current candidate #{details['candidate_id']} | path cost: {details['cost']} {unit}"]
    if cost_metric == "packets":
        result.append(f"Transition firings in this sequence: {details.get('length', len(details['transitions']))}")
    if rank is None:
        result.append(f"Result rank: unassigned; next result slot: {details['next_result_rank']}/{requested} "
                      "if a goal is reached.")
    else:
        result.append(f"Result rank: {rank}/{requested} (base transition sequence).")
    phases = {"variants": "Checking goal / collecting valid colored variants",
              "expand": "Exploring enabled transitions", "enqueue": "Queueing extended transition sequences",
              "queued": "Waiting for the next candidate"}
    result.append("Search phase: " + phases.get(details["phase"], details["phase"]))
    result.append("Transition sequence: " + (" -> ".join(details["transitions"]) or "(empty sequence)"))
    action = details["action_outgoing"]
    if action is not None:
        label = "Trying native firing" if details["action_source"] == "native" else "Processing recorded firing"
        result.append(f"{label}: {action}")
        increment = details.get("action_cost", 1)
        extension = details.get("extension_cost", details["cost"] + increment)
        if cost_metric == "packets":
            result.append(f"Packet increment of this firing: {increment}")
        result.append(f"Extension cost: {extension} {unit}; extension result rank: unassigned.")
    return result


def run_query(adapter, args) -> dict:
    initial = adapter.initial_state
    if getattr(args, "inspect_costs", False):
        policy = PathCostPolicy.configure(adapter, args)
        evidence = policy.packet_cost_rule if policy.packet_cost_rule is not None else {
            "cost_metric": "firings", "transition_costs": {name: 1 for name in adapter.transition_names()}}
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
        return {"status": "inspected", "complete": True}
    if getattr(args, "list_transitions", False):
        print(json.dumps({"page": adapter.page_name, "transitions": adapter.transition_names()},
                         ensure_ascii=False, indent=2))
        return {"status": "inspected", "complete": True}
    if args.inspect:
        print(json.dumps({"page": adapter.page_name, "initial_marking": adapter.marking_values(initial)},
                         ensure_ascii=False, indent=2))
        return {"status": "inspected", "complete": True}
    start = None if args.start is None else compile_patterns(adapter, args.start, "--start")
    end = compile_patterns(adapter, args.end, "--end")
    saved_initial = initial
    if start is not None:
        initial = adapter.initial_state_for_places(start.place_names)
        if not start.matches(initial):
            if start.legacy_place is not None:
                raise ValueError(f"Start place {start.legacy_place!r} is empty in the saved marking. "
                                 "Set its colored tokens in GreatSPN and save first.")
            raise ValueError("The adjusted initial marking does not satisfy any --start pattern.")
    limits = Limits(args.k, args.max_expansions, args.max_queue, args.seconds, args.cache_states)
    every = getattr(args, "checkpoint_every", 30.0)
    if not isfinite(every) or every < 0:
        raise ValueError("--checkpoint-every must be finite and nonnegative")
    out = _output_path(args.out, args.results_dir)
    summary_path = Path(str(out) + ".summary.json")
    grouped_path = Path(str(out) + ".grouped.json")
    pnpro_path = (_output_path(args.pnpro, out.parent)
                  if args.pnpro is not None and not args.no_pnpro else None)
    images_dir = None if getattr(args, "no_images", False) else (
        _output_path(args.images_dir, out.parent) if getattr(args, "images_dir", None) is not None
        else out.with_name(out.stem + "_images"))
    selected_checkpoint = getattr(args, "checkpoint", None)
    checkpoint_path = (_output_path(selected_checkpoint, out.parent) if selected_checkpoint is not None
                       else Path(str(out) + ".checkpoint.json.gz"))
    packet_costs_path = Path(str(out) + ".packet_costs.json")
    output_paths = [out, summary_path, grouped_path, checkpoint_path]
    if getattr(args, "cost_metric", "packets") == "packets":
        output_paths.append(packet_costs_path)
    if pnpro_path is not None:
        if pnpro_path.suffix.lower() != ".pnpro":
            raise ValueError("--pnpro-out/--pnpro must name a .PNPRO file")
        output_paths.append(pnpro_path)
    model_inputs = {args.model.resolve()}
    if args.model.suffix.lower() in {".net", ".def"}:
        model_inputs.update(args.model.resolve().with_suffix(suffix) for suffix in (".net", ".def"))
    if len(set(output_paths)) != len(output_paths) or model_inputs.intersection(output_paths):
        raise ValueError("Result and checkpoint files must be separate from each other and the input model")
    fresh = getattr(args, "fresh", False)
    saved = _read_checkpoint(checkpoint_path) if checkpoint_path.exists() and not fresh else None
    if saved is None and not (args.overwrite or fresh) and any(path.exists() for path in output_paths):
        raise FileExistsError("Output exists; choose another --out/--results-dir or use --overwrite. "
                              "Use --fresh to discard an existing checkpoint.")
    if images_dir is not None:
        if images_dir.is_symlink():
            raise ValueError("Image directory must not be a symbolic link")
        if any(images_dir == path or images_dir in path.parents for path in [*output_paths, *model_inputs]):
            raise ValueError("Image directory must be separate from model, reports and checkpoint files")
        if saved is None and not (args.overwrite or fresh) and images_dir.exists() and any(images_dir.iterdir()):
            raise FileExistsError("Images exist; choose another --images-dir or use --overwrite/--fresh")
    initial_marking = adapter.marking_values(initial)
    policy = PathCostPolicy.configure(adapter, args, saved)
    engine_signature = getattr(adapter, "_checkpoint_engine_signature", None)
    if engine_signature is None:
        classpath = getattr(adapter, "_checkpoint_classpath", None)
        engine_signature = (checkpoint_engine_fingerprint(classpath) if classpath is not None else
                            {"adapter": type(adapter).__module__ + "." + type(adapter).__qualname__})
    identity = {"algorithm": ("weighted_first_hit_transition_words_v2" if policy.metric == "packets"
                              else "distinct_first_hit_firing_sequences_v1"),
                "model": checkpoint_model_fingerprint(args.model, adapter.page_name),
                "engine": engine_signature, "page": adapter.page_name,
                "start_patterns": start.metadata() if start is not None else [],
                "end_patterns": end.metadata(), "initial_marking": initial_marking}
    if policy.metric == "packets":
        identity.update(cost_metric="packets", transition_costs=policy.transition_costs)
    if saved is not None and saved.get("compatibility") != identity:
        old = saved.get("compatibility", {})
        changed = [key for key in identity if old.get(key) != identity[key]]
        raise ValueError("Checkpoint is incompatible with this search (changed: " + ", ".join(changed) +
                         "). Results were preserved. Use --fresh for a new search or another --results-dir.")
    out.parent.mkdir(parents=True, exist_ok=True)
    marking_cache = {id(initial): (initial, initial_marking)}
    portable_cache = {}

    def marking_values(state):
        cached = marking_cache.get(id(state))
        if cached is None or cached[0] is not state:
            cached = (state, adapter.marking_values(state))
            marking_cache[id(state)] = cached
        return cached[1]

    def encode(state):
        cached = portable_cache.get(id(state))
        if cached is None or cached[0] is not state:
            method = getattr(adapter, "checkpoint_marking", None)
            value = method(state) if method is not None else marking_values(state)
            cached = (state, value)
            portable_cache[id(state)] = cached
        return cached[1]

    restored = 0
    restore_started = perf_counter()

    def decode(value):
        nonlocal restored
        method = getattr(adapter, "state_from_marking", None)
        if method is None:
            raise ValueError("This adapter cannot restore saved markings")
        state = method(value)
        portable_cache[id(state)] = (state, value)
        restored += 1
        if restored % 500 == 0:
            print(f"Restoring checkpoint: {restored} markings ({perf_counter() - restore_started:.1f}s).",
                  file=sys.stderr, flush=True)
        return state

    if saved is not None:
        grouped = _restore_report(saved["report"])
        if grouped.initial_marking != initial_marking:
            raise ValueError("Checkpoint initial marking does not match the current query")
        found = saved["session"].get("stats", {}).get("found", 0)
        if args.k < found:
            raise ValueError(f"Checkpoint already contains {found} paths; request --k {found} or more, "
                             "or use --fresh for a separate smaller search.")
        print(f"Resuming checkpoint: {checkpoint_path}", file=sys.stderr)
        session = SequenceSearchSession.load(saved["session"], adapter.successors, adapter.key, end.matches, decode,
                                             transition_cost=policy.cost if policy.metric == "packets" else None)
        if adapter.key(session.vertices[0]["state"]) != adapter.key(initial):
            raise ValueError("Checkpoint search graph starts from a different initial marking")
        _check_session_report(session, grouped)
        print(f"Reused {session.stats.found} distinct paths and {session.stats.variant_count} colored variants; "
              f"restored {restored} markings. Continuing the saved frontier.", file=sys.stderr)
    else:
        grouped = DistinctPaths(initial_marking, cost_metric=policy.metric, transition_costs=policy.transition_costs)
        session = SequenceSearchSession(initial, adapter.successors, adapter.key, end.matches,
                                        transition_cost=policy.cost if policy.metric == "packets" else None)
    metadata = {
        "type": "metadata", "model": str(args.model.resolve()), "page": adapter.page_name,
        "program_version": VERSION, "schema_version": 2, "path_identity": "transition_sequence",
        "k_counts": "distinct_ordered_transition_sequences",
        "start_place": start.legacy_place if start is not None else None, "end_place": end.legacy_place,
        "start_patterns": start.metadata() if start is not None else [], "end_patterns": end.metadata(),
        "unlisted_places": {"start": "zero_initially" if start is not None else "preserve_saved_markings",
                            "end": "unconstrained"},
        "start_behavior": "retain_named_start_places_zero_others" if start is not None else "use_saved_initial_marking",
        "start_place_names": sorted(start.place_names) if start is not None else [],
        "saved_initial_marking": adapter.marking_values(saved_initial), "initial_marking": initial_marking,
        "cost": policy.metric, "cost_metric": policy.metric, "transition_costs": policy.transition_costs,
        "packet_cost_rule": policy.packet_cost_rule,
        "packet_costs_output": str(packet_costs_path) if policy.packet_cost_rule is not None else None,
        "result_ordering": ["cost", "firing_length", "rank"], "grouped_output": str(grouped_path),
        "pnpro_output": str(pnpro_path) if pnpro_path is not None else None,
        "images_output": str(images_dir) if images_dir is not None else None,
        "checkpoint_output": str(checkpoint_path), "checkpoint_reused": saved is not None,
        "grouped_by": ["firing_length", "transition_sequence"],
        "variant_scope": "all executable first-hit colored binding and marking traces for each selected transition sequence; see variants_complete",
        "cycles_allowed": True,
        "goal": "first marking with any token in end place" if end.legacy_place is not None
                else "first marking satisfying an end pattern",
    }
    last_checkpoint = perf_counter()

    def snapshot(stats, *, error=None):
        nonlocal last_checkpoint
        _check_session_report(session, grouped)
        summary = {**asdict(stats), "complete": stats.complete, "requested": args.k,
                   "checkpoint": str(checkpoint_path), "resumed": saved is not None}
        if error is not None:
            summary.update(status="error", complete=False, error=str(error))
        summary["variants_complete"] = all(entry["variants_complete"] for entry in grouped._paths.values())
        report = grouped.data(summary)
        if policy.packet_cost_rule is not None:
            report["packet_cost_rule"] = policy.packet_cost_rule
        payload = {"checkpoint_schema": 1, "compatibility": identity, "session": session.dump(encode),
                   "report": report, "packet_cost_rule": policy.packet_cost_rule}
        # The checkpoint is authoritative. Report files can always be rebuilt.
        _save_checkpoint(checkpoint_path, payload)
        _write_reports(out, summary_path, grouped_path, pnpro_path, metadata, report)
        if policy.packet_cost_rule is not None:
            def write_audit(temporary):
                with temporary.open("w", encoding="utf-8") as stream:
                    json.dump(policy.packet_cost_rule, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
            _atomic_output(packet_costs_path, write_audit)
        last_checkpoint = perf_counter()
        return report["summary"]

    def emit_sequence(rank, cost, transitions):
        grouped.add_sequence(rank, cost, transitions)
        if rank <= 5 or rank % 100 == 0:
            unit = "packets" if policy.metric == "packets" else "firings"
            suffix = f" ({len(transitions)} transition firings)" if policy.metric == "packets" else ""
            print(f"Found distinct path {rank}: {cost} {unit}{suffix}", file=sys.stderr)
            show_current(force=True)

    def emit_variant(rank, index, actions, states):
        grouped.add_variant(rank, index, actions, [marking_values(state) for state in states])

    def finish_sequence(rank, complete):
        grouped.finish_sequence(rank, complete)
        if rank <= 5 or rank % 100 == 0:
            state = "complete" if complete else "incomplete"
            print(f"Path {rank}: {len(grouped._paths[rank]['variants'])} valid colored variants ({state}).",
                  file=sys.stderr)

    last_live = None

    def show_current(action=None, *, force=False):
        nonlocal last_live
        now = perf_counter()
        if not force and last_live is not None and now - last_live < 2.0:
            return
        last_live = now
        for line in _progress_lines(session.progress_details(action), args.k, policy.metric):
            print(textwrap.fill(line, width=110, subsequent_indent="  "), file=sys.stderr)
        sys.stderr.flush()

    def progress(stats, queued):
        print(f"Progress: {stats.elapsed_seconds:.1f}s search time; {stats.found}/{args.k} distinct paths; "
              f"{stats.variant_count} colored variants; {stats.unique_states} markings; "
              f"{stats.expanded} prefixes expanded; {queued} pending.", file=sys.stderr, flush=True)
        show_current(force=True)
        if every and perf_counter() - last_checkpoint >= every:
            snapshot(stats)
            print(f"Checkpoint saved: {checkpoint_path}", file=sys.stderr)

    print(f"Searching for up to {args.k} distinct transition sequences. "
          f"Path cost: {policy.metric} (timing and rates are not used).", file=sys.stderr)
    if policy.metric == "packets":
        counted = ", ".join(f"{name}={cost}" for name, cost in sorted(policy.transition_costs.items()) if cost)
        print("Packet cost rule: each PACKET_SEND_ transition firing costs 1; all other firings cost 0 "
              "(case-sensitive prefix).", file=sys.stderr)
        if counted:
            print(textwrap.fill("Packet exchange transitions: " + counted, width=110), file=sys.stderr)
        else:
            print("Warning: no transition name starts with PACKET_SEND_; every path has packet cost 0.",
                  file=sys.stderr)
        print(f"Packet cost map: {packet_costs_path}", file=sys.stderr)
    # Save before starting as well, so output/restore failures never rely on a
    # partially written report as the only description of a search.
    session.stats.status = "running"
    snapshot(session.stats)
    while True:
        try:
            # This display-only hook runs before each native firing, including
            # slow atomic binding batches. It never checkpoints a partial batch.
            missing = object()
            previous = getattr(adapter, "_exploration_observer", missing)
            can_observe = hasattr(adapter, "__dict__")

            def observe(action):
                if previous is not missing and callable(previous):
                    previous(action)
                show_current(action)

            if can_observe:
                adapter._exploration_observer = observe
            try:
                stats = session.run(limits, on_sequence=emit_sequence, on_variant=emit_variant,
                                    on_sequence_complete=finish_sequence, on_progress=progress)
            finally:
                if can_observe:
                    if previous is missing:
                        del adapter._exploration_observer
                    else:
                        adapter._exploration_observer = previous
        except Exception as exc:
            try:
                snapshot(session.stats, error=exc)
            except Exception as saving_error:
                # A failed output callback can leave the engine one record
                # ahead of the collector. Keep the last coherent checkpoint,
                # but still publish an honest error report for recorded work.
                error_summary = {**asdict(session.stats), "status": "error", "complete": False,
                                 "requested": args.k, "error": str(exc),
                                 "checkpoint": str(checkpoint_path), "resumed": saved is not None,
                                 "variants_complete": all(entry["variants_complete"]
                                                          for entry in grouped._paths.values())}
                try:
                    _write_reports(out, summary_path, grouped_path, pnpro_path, metadata,
                                   grouped.data(error_summary))
                except Exception as report_error:
                    print(f"Could not write the error report: {report_error}", file=sys.stderr)
                print(f"Could not update checkpoint after the error: {saving_error}. "
                      "The last valid checkpoint was preserved.", file=sys.stderr)
            raise
        summary = snapshot(stats)
        if not stats.complete:
            show_current(force=True)
        print(f"Checkpoint saved: {checkpoint_path}", file=sys.stderr)
        if stats.status != "time_limit" or getattr(args, "no_prompt", False) or not sys.stdin.isatty():
            break
        extra = _extra_seconds(limits.seconds)
        if extra is None:
            break
        if checkpoint_model_fingerprint(args.model, adapter.page_name) != identity["model"]:
            print("The input model changed critically while the search was paused. "
                  "The saved search was preserved; use --fresh with the edited model to start over.",
                  file=sys.stderr)
            break
        limits = Limits(args.k, args.max_expansions, args.max_queue, extra, args.cache_states)
        print("Continuing the same search in memory; no frontier or colored variants were discarded.",
              file=sys.stderr)
    explanation = {
        "found_k": "Complete: the requested number of distinct paths was found.",
        "exhausted": "Complete: all reachable distinct first-hit paths were returned.",
        "time_limit": "Stopped at the search time limit; progress is saved for resuming.",
        "expansion_limit": "Stopped at the sequence expansion limit; progress is saved for resuming.",
        "queue_limit": "Stopped at the queue limit; progress is saved for resuming.",
        "interrupted": "Search interrupted; progress is saved for resuming.",
    }.get(summary["status"], f"Search status: {summary['status']}.")
    print(explanation, file=sys.stderr)
    print(f"Status: {summary['status']}; found={summary['found']}; colored variants={summary['variant_count']}; "
          f"discovered markings={summary['unique_states']}; expanded sequence prefixes={summary['expanded']}",
          file=sys.stderr)
    print(f"Output: {out}\nSummary: {summary_path}\nGrouped paths and markings: {grouped_path}", file=sys.stderr)
    if pnpro_path is not None:
        print(f"PNPRO path visualizations: {pnpro_path}", file=sys.stderr)
    if images_dir is not None:
        print(f"SVG figures: {images_dir} (overview.svg, all_paths.svg and path_*.svg)", file=sys.stderr)
    print("Run the same model/query/output again to resume automatically; increase --k for more total paths. "
          "Use --fresh to start over.", file=sys.stderr)
    return summary

def main(argv=None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        if args.export_images is not None:
            if args.model is not None or args.export_pnpro is not None or args.no_images:
                cli.error("Use --export-images without a model, --export-pnpro or --no-images")
            source = args.export_images.expanduser().resolve()
            target = (_output_path(args.images_dir, args.results_dir) if args.images_dir is not None
                      else source.with_name(source.name.removesuffix(".grouped.json") + "_images"))
            if target == source or target in source.parents:
                raise ValueError("Image output must be separate from the input report")
            with source.open(encoding="utf-8") as stream:
                report = json.load(stream)
            figures = write_images(report, target, overwrite=args.overwrite)
            print(f"SVG figures: {target} ({figures} images)")
            return 0
        if args.export_pnpro is not None:
            if args.model is not None or args.inspect:
                cli.error("Use --export-pnpro without a model argument or --inspect")
            if args.pnpro is None:
                cli.error("Use --pnpro-out FILE with --export-pnpro")
            source = args.export_pnpro.expanduser().resolve()
            target = _output_path(args.pnpro, args.results_dir)
            if source == target:
                raise ValueError("PNPRO output must not replace the input grouped report")
            with source.open(encoding="utf-8") as stream:
                report = json.load(stream)
            pages = write_pnpro(report, target, overwrite=args.overwrite)
            print(f"PNPRO: {target} ({pages} pages)")
            return 0
        if args.model is None or not args.model.is_file():
            cli.error("Supply an existing .PNPRO, .net, or .def model")
        if not args.inspect and not args.list_transitions and not args.inspect_costs and not args.end:
            cli.error("--end is required")
        Limits(args.k, args.max_expansions, args.max_queue, args.seconds, args.cache_states)
        locations = args.greatspn
        if not locations and os.environ.get("GREATSPN_HOME"):
            locations = [Path(os.environ["GREATSPN_HOME"])]
        if not locations:
            cli.error("Pass --greatspn /path/to/editor/dist or set GREATSPN_HOME")
        print(f"Loading GreatSPN model: {args.model}", file=sys.stderr)
        adapter = GreatSpnAdapter(args.model, args.page, discover_classpath(locations),
                                 jvm_path=args.jvm, heap=args.java_heap, debug=args.debug)
        for warning in adapter.warnings:
            print(f"Warning: {warning}", file=sys.stderr)
        summary = run_query(adapter, args)
        return 0 if summary["complete"] else 2
    except KeyboardInterrupt:
        print("Interrupted; inspect the output summary before using results.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

