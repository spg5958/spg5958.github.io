#!/usr/bin/env python3
"""Offline complete-prefix weighted enumeration. Never creates network sockets.

The restricted pilot grammar and per-(goal,family) quotas are explicit
approximations. No visited[Linux_marking] or state dominance pruning is used.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import heapq
import itertools
import json
from collections import Counter
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from time import perf_counter

from endpoint import Action, initial_state, ordinary_actions, step


@dataclass(frozen=True)
class Prefix:
    state: object
    actions: tuple = ()
    history: tuple = ()
    labels: frozenset = frozenset()
    established: tuple = ()
    left: frozenset = frozenset()
    N: int = 0
    A: int = 0
    W: int = 0
    T: int = 0

    def cost(self, kappa=1):
        return self.N + self.A + 2*self.W + kappa*self.T


def phase(state, flow):
    return next(x for x in state.flows if x.name == flow)


def cost_dict(p, cfg):
    return {"N": p.N, "A": p.A, "W": p.W, "T": p.T,
            "kappa": cfg["kappa"], "total": p.cost(cfg["kappa"])}


def packet_count(events):
    return sum(e.get("kind", e.get("type")) == "packet" for e in events)


def extend(p, action, outcome, ordinary, label, cfg):
    labels = frozenset([label]) if label else frozenset()
    A = int(not ordinary and action.kind == "packet")
    W = int(A and not (labels - p.labels))
    events = []
    for event in outcome.events:
        e = dict(event)
        e["kind"] = e.get("kind", e.get("type", "internal"))
        e["ordinary_progress"] = ordinary
        e["action_index"] = len(p.actions)
        e["decision_label"] = label
        events.append(e)
    records = list(p.established)
    left = set(p.left)
    for old, new in zip(p.state.flows, outcome.state.flows):
        record = (new.name, new.generation)
        if new.phase == "ESTABLISHED" and record not in records:
            records.append(record)
        if old.phase == "ESTABLISHED" and new.phase != "ESTABLISHED":
            left.add((old.name, old.generation))
    waits = sum(e.get("units", 1) for e in events if e["kind"] == "wait")
    return Prefix(outcome.state, p.actions+(action,), p.history+tuple(events),
                  p.labels|labels, tuple(records), frozenset(left),
                  p.N+packet_count(events), p.A+A, p.W+W, p.T+waits)


def within(p, cfg):
    return (p.N <= cfg["max_packets_per_replay"] and p.T <= cfg["max_wait_units"]
            and p.A <= cfg["max_departures"] and len(p.actions) <= cfg["max_prefix_actions"])


def goal_checkpoint(p, goal):
    if not p.established:
        return None
    first = p.established[0]
    for f in p.state.flows:
        if f.phase != "ESTABLISHED":
            continue
        current = (f.name, f.generation)
        if goal == "establish" and current == first:
            return f
        if first in p.left and current != first:
            if goal == "reconnect_same" and f.name == first[0]:
                return f
            if goal == "reconnect_different" and f.name != first[0]:
                return f
    return None


def reference_actions(p, goal):
    """Small frozen reference automaton: passive setup, legal close variants/reopen."""
    result = []
    for a in ordinary_actions(p.state):
        f = phase(p.state, a.flow)
        # First incarnation belongs to f0, second selected by goal.
        if a.kind == "packet" and a.flags == "S" and f.phase in {"LISTEN", "CLOSED"}:
            if not p.established:
                if a.flow != "f0" or p.state.next_generation != 0 or a.client != "red":
                    continue
            else:
                target = "f0" if goal != "reconnect_different" else "f1"
                if a.flow != target or a.client != "blue" or ("f0", 0) not in p.left:
                    continue
        # Do not create an independent flow before leaving the first EST state.
        if a.flow == "f1" and not p.left:
            continue
        # The last checkpoint has no need for another normal termination in its prefix.
        if goal_checkpoint(p, goal) is not None:
            continue
        result.append(a)
    return result


def departure_actions(p, family, goal, cfg, decision_phase="any"):
    if family == "ordinary" or p.A >= (2 if family == "repeated_control" else 1):
        return []
    output = []
    for f in p.state.flows:
        requested = decision_phase.removeprefix("SECOND_")
        if requested != "any" and f.phase != requested:
            continue
        if decision_phase.startswith("SECOND_") and f.generation != 1:
            continue
        if f.name == "f1" and not p.left:
            continue
        if f.phase in {"CLOSED", "LISTEN"} and f.name == "f1" and goal != "reconnect_different":
            continue
        client = f.client or ("blue" if p.established else "red")
        base = Action(flow=f.name, client=client, server=f.server)
        live = f.phase not in {"CLOSED", "LISTEN", "TIME_WAIT"}
        known = (f.name, f.generation, f.server) in p.state.knowledge
        candidates = []
        if family == "allocation" and f.phase in {"LISTEN", "SYN_RECV"}:
            candidates = [replace(base, flags="A", ack="blind", server=None, seq="isn")]
            if f.phase == "SYN_RECV":
                candidates.append(replace(base, flags="S", ack="none", server=None, seq="isn"))
        elif family == "sequence_validation" and live and known:
            candidates = [replace(base, flags="A", seq=s, ack="exact") for s in ("in_window", "oow_left", "oow_right")]
        elif family == "acknowledgment_validation" and live and known:
            candidates = [replace(base, flags="A", ack=a) for a in ("behind", "beyond")]
        elif family == "reset" and live:
            candidates = [replace(base, flags="R", ack="none", server=None, seq=s) for s in ("exact", "in_window", "oow_left")]
        elif family == "early_fin" and live and known:
            candidates = [replace(base, flags="FA", seq=s, ack="exact") for s in ("in_window", "oow_left")]
        elif family in {"visibility", "checksum", "visibility_checksum", "repeated_control", "flow_identity"}:
            if family == "flow_identity" and f.generation != 1:
                continue
            flags = ("S", "R") if not known else ("S", "R", "FA", "A")
            for flag in flags:
                candidates.append(replace(base, flags=flag,
                    seq="isn" if f.phase == "LISTEN" or flag == "S" else "exact",
                    ack="exact" if "A" in flag and known else "none",
                    server=f.server if "A" in flag and known else None,
                    delivery="dpi_only" if family != "checksum" else "full",
                    checksum="invalid" if family in {"checksum", "visibility_checksum"} else "valid"))
        elif family == "incarnation" and f.generation == 1 and live:
            for old in p.state.retired:
                if old.generation == 0:
                    candidates += [replace(base, flags="R", seq="old", ack="none", client=old.client, server=None),
                                   replace(base, flags="A", seq="old", ack="old", client=old.client, server=old.server)]
        elif family == "deferred_reply" and f.phase in {"LISTEN", "CLOSED"}:
            if f.name == "f0" and not p.established and p.state.next_generation == 0:
                candidates = [replace(base, flags="S", ack="none", server=None, defer_reply=True)]
        for a in candidates:
            # Same semantic question repeated incurs W, even if raw syntax differs.
            label = "|".join([family, f.phase, a.flags, a.seq, a.ack,
                              "old" if a.client != f.client and f.client else "current",
                              a.delivery, a.checksum])
            if family == "repeated_control" and p.labels and label not in p.labels:
                continue
            output.append((a, label))
    return output


def candidate_copy(p, flow, delivery, cfg, pad_waits=0):
    """Append readout and cleanup only to a copy; never contaminate search prefix."""
    for _ in range(pad_waits):
        wait = Action(kind="wait", ack="none")
        p = extend(p, wait, step(p.state, wait)[0], True, None, cfg)
    a = Action(flow=flow.name, flags="PA", client=flow.client, server=flow.server,
               ack="exact", payload="readout", delivery=delivery)
    outcomes = step(p.state, a)
    if not outcomes:
        return None
    q = extend(p, a, outcomes[0], True, None, cfg)
    # Isolate a replay by cleaning *all* retained endpoint records, not just the
    # readout flow. Reset cannot remove the protected TIME_WAIT profile.
    for name in ("f0", "f1"):
        f = phase(q.state, name)
        if f.phase in {"LISTEN", "TIME_WAIT"}:
            continue
        cleanup = Action(flow=f.name, flags="R", ack="none", client=f.client,
                         server=None, seq="exact")
        outs = step(q.state, cleanup)
        if not outs:
            return None
        q = extend(q, cleanup, outs[0], True, None, cfg)
    if any(f.phase == "TIME_WAIT" for f in q.state.flows):
        wait = Action(kind="wait", ack="none")
        q = extend(q, wait, step(q.state, wait)[0], True, None, cfg)
    return q if within(q, cfg) else None


def enumerate_stratum(goal, family, cfg, deadline, decision_phase="any"):
    serial = itertools.count()
    initial = Prefix(initial_state())
    queue = [(0, 0, next(serial), initial)]
    found = []
    signatures = set()
    expanded = generated = bound_pruned = 0
    stop = "exhausted"
    while queue:
        if perf_counter() >= deadline:
            stop = "wall_time_limit"; break
        if expanded >= cfg["max_expansions_per_stratum"]:
            stop = "expansion_limit"; break
        _, _, _, p = heapq.heappop(queue)
        expanded += 1
        checkpoint = goal_checkpoint(p, goal)
        needed = (family == "ordinary" or bool(p.labels))
        if family == "repeated_control":
            needed = p.A == 2 and p.W >= 1
        if checkpoint and needed:
            for delivery in cfg["readout_deliveries"]:
                q = candidate_copy(p, checkpoint, delivery, cfg)
                if q is None:
                    bound_pruned += 1; continue
                signature = json.dumps([asdict(a) for a in q.actions], sort_keys=True)
                if signature not in signatures:
                    signatures.add(signature)
                    found.append((p, q, checkpoint, delivery))
            if len(found) >= cfg["plans_per_stratum"]:
                stop = "representative_quota"; break
        action_list = [(a, None, True) for a in reference_actions(p, goal)]
        action_list += [(a, label, False) for a, label in departure_actions(p, family, goal, cfg, decision_phase)]
        for a, label, ordinary in action_list:
            for outcome in step(p.state, a):
                q = extend(p, a, outcome, ordinary, label, cfg)
                if not within(q, cfg):
                    bound_pruned += 1; continue
                heapq.heappush(queue, (q.cost(cfg["kappa"]), len(q.actions), next(serial), q))
                generated += 1
        if len(queue) > cfg["max_frontier_per_stratum"]:
            # Stop rather than silently drop unknown histories.
            stop = "frontier_limit"; break
    found.sort(key=lambda x: x[1].cost(cfg["kappa"]))
    return found, {"goal": goal, "family": family, "decision_phase": decision_phase, "expanded": expanded,
        "generated": generated, "frontier_remaining": len(queue), "status": stop,
        "retained": len(found), "bound_pruned": bound_pruned,
        "global_optimality_claim": False}


def plan_record(identifier, family, goal, decision_phase, p, q, checkpoint, delivery, ordinary, cfg):
    ref_prefix, ref_flow = ordinary[goal, delivery]
    # Equal abstract readout time. Semantically necessary waits stay in their history;
    # the shorter control gets an explicit idle pad before its fixed readout.
    target_T = max(p.T, ref_prefix.T)
    baseline = candidate_copy(ref_prefix, ref_flow, delivery, cfg, target_T-ref_prefix.T)
    q = candidate_copy(p, checkpoint, delivery, cfg, target_T-p.T)
    if baseline is None or q is None:
        raise ValueError("matched control/readout/cleanup exceeds pilot bounds")
    # Match post-readout cleanup intervals independently of the readout deadline.
    total_T = max(baseline.T, q.T)
    def pad_suffix(trace):
        while trace.T < total_T:
            wait = Action(kind="wait", ack="none")
            trace = extend(trace, wait, step(trace.state, wait)[0], True, None, cfg)
        if not within(trace,cfg):
            raise ValueError("matched suffix wait exceeds bounds")
        return trace
    baseline, q = pad_suffix(baseline), pad_suffix(q)
    conditions = []
    for history_name, trace in (("ordinary", baseline), ("candidate", q)):
        for hostname in ("benign", "blocked"):
            conditions.append({"id": history_name+"_"+hostname, "history": history_name,
                "hostname_class": hostname, "Y": None, "status": "unmeasured",
                "cost": cost_dict(trace, cfg), "events": list(trace.history),
                "actions": [asdict(a) for a in trace.actions],
                "final_marking": asdict(trace.state),
                "readout_delivery": delivery, "readout_segmentation": "one fixed TLS ClientHello segment",
                "request_framing": "equal-length hostname substitution; all TLS lengths fixed",
                "timing_profile": "matched readout wait deadline and total wait units; paired hostnames replay identical timing",
                "quality_metadata": {"calibration_passed": None, "delivery_confirmed": None,
                    "observable_signal": None, "repeat_stability": None}})
    # Execution resource proxy does not include artificial A/W penalties.
    execution = cfg["trial_repetitions"]*sum(c["cost"]["N"]+cfg["kappa"]*c["cost"]["T"] for c in conditions)
    return {"id": identifier, "title": family.replace("_", " ")+" / "+goal.replace("_", " "),
        "family": family, "goal": goal, "decision_phase":decision_phase, "cost": cost_dict(q, cfg),
        "prefix_cost": cost_dict(p, cfg), "history": list(q.history), "prefix_history": list(p.history),
        "actions": [asdict(a) for a in q.actions], "prefix_actions": [asdict(a) for a in p.actions],
        "labels": sorted(p.labels), "checkpoint": asdict(checkpoint),
        "checkpoint_marking": asdict(p.state), "final_marking": asdict(q.state),
        "conditions": conditions, "readout_delivery": delivery,
        "Y": None, "outcome_status": "unmeasured", "bundle_ids": [],
        "trial_repetitions": cfg["trial_repetitions"], "execution_resource_proxy": execution,
        "empirical_separated_pairs": None, "empirical_information_gain": None,
        "readout": {"fixture":"fixtures/clienthello.json", "length_symbol":"L_readout", "length_bound_bytes":32768,
            "segmentation":"one segment", "hostnames_are_placeholders":True,
            "ahead_inwindow_sequence_constraint":"RCV.NXT + 32768; no accepted pilot data fills the gap"},
        "hypothesis": ("Reference calibration" if family == "ordinary" else
            "Candidate opportunity concerning "+family.replace("_", " ")+"; no DPI behavior predicted"),
        "readout_evaluability": ("Requires calibrated attributable SNI-dependent side effect; missing server response is not Y=1"
            if delivery == "dpi_only" else "Requires calibrated SNI-dependent censorship signal and evaluable interval"),
        "signature": hashlib.sha256(json.dumps([asdict(a) for a in q.actions],sort_keys=True).encode()).hexdigest()}


def make_bundles(plans, cfg):
    bundles = []
    for goal in cfg["goals"]:
        rows = [p for p in plans if p["goal"] == goal]
        families = list(dict.fromkeys(f for p in rows for f in p.get("families",[p["family"]]) if f != "ordinary"))
        for i in range(0, len(families), 2):
            selected = []
            for family in families[i:i+2]:
                choices = [p for p in rows if family in p.get("families",[p["family"]]) and p not in selected]
                if choices:
                    selected.append(min(choices,key=lambda p:p["cost"]["total"]))
            # Calibration is already four-way per probe; third slot adds distinct visibility.
            alternate = next((p for p in rows if p["family"] == "visibility" and p not in selected),None)
            if alternate and len(selected)<cfg["max_bundle_size"]:
                selected.append(alternate)
            if len(selected)<2:
                continue
            bid = f"B{len(bundles)+1:03d}"
            for p in selected:
                p["bundle_ids"].append(bid)
            bundles.append({"id":bid,"goal":goal,"probe_ids":[p["id"] for p in selected],
                "size":len(selected),"selection":"offline semantic diversity; no empirical optimization",
                "families":list(dict.fromkeys(f for p in selected for f in p.get("families",[p["family"]]))),
                "execution_resource_proxy":sum(p["execution_resource_proxy"] for p in selected),
                "outcome_vector":[None for p in selected],"separated_reference_pairs":None})
    return bundles[:cfg["max_bundles"]]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config",type=Path,default=Path(__file__).with_name("pilot.json"))
    ap.add_argument("--output",type=Path,default=Path(__file__).with_name("results"))
    args = ap.parse_args()
    cfg = json.loads(args.config.read_text())
    args.output.mkdir(parents=True,exist_ok=True)
    from build_fixtures import build
    fixture_meta = build()
    start = perf_counter(); deadline = start+cfg["wall_seconds"]
    raw = []; stats = []; ordinary = {}
    # Reference strata first: controls are real modeled baseline histories for each goal.
    strata = [(g,"ordinary","any") for g in cfg["goals"]]
    strata += [(g,f,ph) for f in cfg["families"] if f != "ordinary" for ph in cfg["phase_strata"][f] for g in cfg["goals"]
               if not (g == "establish" and (ph not in {"LISTEN","SYN_RECV","ESTABLISHED"}))]
    for goal,family,decision_phase in strata:
        rows, st = enumerate_stratum(goal,family,cfg,deadline,decision_phase)
        stats.append(st)
        for p,q,checkpoint,delivery in rows:
            if family == "ordinary":
                old = ordinary.get((goal,delivery))
                if old is None or q.cost(cfg["kappa"])<old[0].cost(cfg["kappa"]):
                    ordinary[goal,delivery] = (p,checkpoint)
            raw.append((family,goal,decision_phase,p,q,checkpoint,delivery))
        print(f"{goal:22} {family:28} {decision_phase:20} {st['status']:22} plans={len(rows):3} expanded={st['expanded']}",flush=True)
    classified = [plan_record(f"P{i+1:04d}",*r,ordinary,cfg) for i,r in enumerate(raw)]
    # Classification quotas can rediscover the same physical experiment. Keep one
    # measurement and all its semantic classifications, never count it twice.
    by_signature = {}
    for plan in classified:
        classification = {"family":plan["family"],"decision_phase":plan["decision_phase"],"labels":plan["labels"]}
        old = by_signature.get(plan["signature"])
        if old is None:
            plan["families"] = [plan["family"]]
            plan["decision_phases"] = [plan["decision_phase"]]
            plan["proposal_classifications"] = [classification]
            by_signature[plan["signature"]] = plan
        else:
            if old["cost"] != plan["cost"]:
                raise ValueError("identical packet experiment has incompatible cost annotations")
            old["families"] = list(dict.fromkeys(old["families"]+[plan["family"]]))
            old["decision_phases"] = list(dict.fromkeys(old["decision_phases"]+[plan["decision_phase"]]))
            old["proposal_classifications"].append(classification)
    plans=list(by_signature.values())
    for i,plan in enumerate(plans):
        plan["id"]=f"P{i+1:04d}"
    bundles = make_bundles(plans,cfg)
    metadata = {"schema_version":"1.0", "engine":"offline symbolic full-prefix search",
        "configuration":cfg,"stats":stats,"plan_count":len(plans),"bundle_count":len(bundles),
        "classified_proposals_before_deduplication":len(classified),
        "exact_duplicate_proposals_merged":len(classified)-len(plans),
        "elapsed_seconds":round(perf_counter()-start,4),"bundles":bundles,
        "complete":False,"native_GreatSPN_executed":False,"packets_transmitted":0,
        "dpi_outcomes_measured":False,"cost_formula":"N + A + 2W + kappa*T",
        "status":"bounded pilot; restricted action grammar; per-stratum representative quotas",
        "limitations":["Named Markdown task specification and documented numeric pilot were unavailable.",
          "Symbolic TCP reference is a conservative Linux-inspired abstraction, not a version-complete kernel clone.",
          "Generation uses full prefixes; selected plans are not exhaustive or proven globally optimal.",
          "Two total incarnations, one pending reply; no segmentation/reassembly or arbitrary payload model.",
          "Wait units are abstract and require calibration; TIME_WAIT fast reuse and TCP options are excluded.",
          "Fresh disjoint ISN windows; attacker colors consumed without replacement. TCP_DEFER_ACCEPT disabled (baseline enabled it).",
          "Immediate modeled TCP readout ACK; no application/TLS response or censorship interference simulated.",
          "No empirical DPI labels, reference fingerprints, entropy, or pair separation can be inferred offline."],
        "coverage":dict(Counter(f for p in plans for f in p["families"]))}
    metadata["fixtures"] = fixture_meta
    metadata["enumeration_seconds"] = metadata["elapsed_seconds"]
    (args.output/"plans.json").write_text(json.dumps(plans,indent=2))
    (args.output/"plans.jsonl").write_text("".join(json.dumps(p)+"\n" for p in plans))
    (args.output/"bundles.json").write_text(json.dumps(bundles,indent=2))
    (args.output/"run_metadata.json").write_text(json.dumps(metadata,indent=2))
    with (args.output/"plans.csv").open("w",newline="") as f:
        w=csv.writer(f); w.writerow(["id","family","goal","delivery","N","A","W","T","cost","execution_resource_proxy","Y"])
        for p in plans:
            c=p["cost"]; w.writerow([p["id"],p["family"],p["goal"],p["readout_delivery"],c["N"],c["A"],c["W"],c["T"],c["total"],p["execution_resource_proxy"],""])
    from model_export import export_model
    model_summary = export_model(args.output.parent/"model",
        action_sequences=[c["actions"] for p in plans for c in p["conditions"]],
        max_states=1200,max_edges=12000,max_wait_units=cfg["max_wait_units"])
    metadata["cpn_export"] = model_summary
    from render_results import render_all
    render_all(args.output,plans,metadata)
    metadata["elapsed_seconds_including_export_and_render"] = round(perf_counter()-start,4)
    (args.output/"run_metadata.json").write_text(json.dumps(metadata,indent=2))
    print(json.dumps({"plans":len(plans),"bundles":len(bundles),"seconds":round(perf_counter()-start,3)}))


if __name__ == "__main__":
    main()
