#!/usr/bin/env python3
"""Independent result accounting, protocol fixtures and exported-net replay.

Uses endpoint.step only as the reference transition oracle. It does not import
the search engine, its goal predicate, its cost functions, or its exporter.
Run: python verify_results.py --results results --model model
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import traceback
import xml.etree.ElementTree as ET

from endpoint import Action, Flow, Pending, State, get_flow, initial_state, step


def normalized(value):
    return json.loads(json.dumps(value, sort_keys=True))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def require(value, message):
    if not value:
        raise AssertionError(message)


def one(state, action):
    outcomes = step(state, action)
    require(len(outcomes) == 1, f"expected one enabled successor: {action}")
    return outcomes[0]


def forbidden(state, action):
    try:
        outcomes = step(state, action)
    except ValueError:
        return
    require(not outcomes, f"knowledge-unsafe action allowed: {action}")


def groups(events):
    output = defaultdict(list)
    for event in events:
        require(type(event.get("action_index")) is int, "event lacks action index")
        output[event["action_index"]].append(event)
    if output:
        require(sorted(output) == list(range(max(output) + 1)), "noncontiguous event groups")
    return output


def recount(events, kappa):
    """Count physical packets and per-action departures from serialized history."""
    counts = dict(N=0, A=0, W=0, T=0, kappa=kappa)
    labels = set()
    for _, items in sorted(groups(events).items()):
        ordinary_values = {item["ordinary_progress"] for item in items}
        decision_values = {item["decision_label"] for item in items}
        require(len(ordinary_values) == len(decision_values) == 1, "mixed action annotations")
        packets = [item for item in items if item["kind"] == "packet"]
        counts["N"] += len(packets)
        counts["T"] += sum(item.get("units", 1) for item in items if item["kind"] == "wait")
        departure = not items[0]["ordinary_progress"] and any(e["actor"] == "attacker" for e in packets)
        label = items[0]["decision_label"]
        if departure:
            require(label is not None, "departure lacks semantic decision label")
            counts["A"] += 1
            counts["W"] += int(label in labels)
        if label is not None:
            labels.add(label)
    counts["total"] = counts["N"] + counts["A"] + 2 * counts["W"] + kappa * counts["T"]
    return counts


def replay(actions, events=None):
    state = initial_state()
    states = [state]
    event_groups = groups(events) if events is not None else None
    if event_groups is not None:
        require(len(event_groups) == len(actions), "action and event group counts differ")
    for index, raw in enumerate(actions):
        action = Action(**raw)
        before = state
        outcome = one(before, action)
        state = outcome.state
        if action.kind == "packet" and (action.delivery == "dpi_only" or action.checksum == "invalid"):
            require(state == before, "TTL/checksum packet changed endpoint state or knowledge")
            require(len(outcome.events) == 1 and outcome.events[0]["actor"] == "attacker", "rejected packet generated server reply")
        if action.kind == "deliver_pending":
            require(all(e["kind"] != "packet" for e in outcome.events), "observation retransmitted a reply")
        if event_groups is not None:
            recorded = event_groups[index]
            require(len(recorded) == len(outcome.events), f"wire events differ at action {index}")
            for expected, actual in zip(outcome.events, recorded):
                for key, val in expected.items():
                    require(normalized(val) == actual.get(key), f"event differs at action {index}: {key}")
                if actual["kind"] == "packet":
                    require(actual["dpi_processing"] == "unmeasured", "DPI behavior was synthesized")
        states.append(state)
    return state, states


def check_plan(plan, cfg):
    prefix, states = replay(plan["prefix_actions"], plan["prefix_history"])
    require(normalized(asdict(prefix)) == plan["checkpoint_marking"], "checkpoint marking differs from replay")
    require(not prefix.pending, "checkpoint retains undelivered server observation")
    checkpoint = plan["checkpoint"]
    require(checkpoint in normalized(asdict(prefix))["flows"], "checkpoint flow not in endpoint state")
    require(checkpoint["phase"] == "ESTABLISHED", "goal is not settled ESTABLISHED")
    require((checkpoint["name"], checkpoint["generation"], checkpoint["server"]) in prefix.knowledge, "checkpoint server ISN was not observed")
    established = []
    left = set()
    for before, after in zip(states, states[1:]):
        for old, new in zip(before.flows, after.flows):
            identity = (new.name, new.generation)
            if new.phase == "ESTABLISHED" and identity not in established:
                established.append(identity)
            if old.phase == "ESTABLISHED" and new.phase != "ESTABLISHED":
                left.add((old.name, old.generation))
    require(established, "no complete establishment occurred")
    target = (checkpoint["name"], checkpoint["generation"])
    if plan["goal"] == "establish":
        require(target == established[0], "establishment checkpoint identity differs")
    else:
        require(established[0] in left and target != established[0], "reconnection lacks departure from first established incarnation")
        require(checkpoint["client"] == "blue" and checkpoint["server"] == "purple", "second incarnation colors differ")
        require((target[0] == established[0][0]) == (plan["goal"] == "reconnect_same"), "same/different tuple goal differs")
    require(not any(a.get("payload") == "readout" for a in plan["prefix_actions"]), "readout contaminated search prefix")
    require(plan["actions"][:len(plan["prefix_actions"])] == plan["prefix_actions"], "probe prefix is not retained verbatim")
    final, _ = replay(plan["actions"], plan["history"])
    require(normalized(asdict(final)) == plan["final_marking"], "final marking differs from replay")
    require(not final.pending, "final marking retains reply observation")
    require(get_flow(final, checkpoint["name"]).phase == "LISTEN", "readout cleanup did not retire checkpoint connection")
    require(all(flow.phase == "LISTEN" for flow in final.flows), "cleanup retained a live connection/TIME_WAIT record")
    require(recount(plan["history"], cfg["kappa"]) == plan["cost"], "plan weighted cost differs")
    require(recount(plan["prefix_history"], cfg["kappa"]) == plan["prefix_cost"], "prefix weighted cost differs")
    labels = sorted({e["decision_label"] for e in plan["prefix_history"] if e.get("decision_label")})
    require(labels == plan["labels"], "serialized decision labels differ")
    for key in ("Y", "empirical_separated_pairs", "empirical_information_gain"):
        require(plan[key] is None, f"empirical field {key} was filled")
    require(plan["outcome_status"] == "unmeasured", "plan marked measured")
    conditions = {c["id"]: c for c in plan["conditions"]}
    require(set(conditions) == {"ordinary_benign", "ordinary_blocked", "candidate_benign", "candidate_blocked"}, "four-way conditions missing")
    total_waits = []
    for condition in conditions.values():
        require(condition["Y"] is None and condition["status"] == "unmeasured", "condition outcome filled")
        require(all(v is None for v in condition["quality_metadata"].values()), "calibration result was invented")
        cost = recount(condition["events"], cfg["kappa"])
        require(cost == condition["cost"], "condition weighted cost differs")
        total_waits.append(cost["T"])
        final_c, _ = replay(condition["actions"], condition["events"])
        require(normalized(asdict(final_c)) == condition["final_marking"], "condition final marking differs")
        require(not final_c.pending and all(flow.phase == "LISTEN" for flow in final_c.flows), "condition cleanup retained live state")
        readouts = [e for e in condition["events"] if e["kind"] == "packet" and e["actor"] == "attacker" and e["payload"] == "readout"]
        require(len(readouts) == 1, "condition does not contain exactly one fixed readout")
        require(readouts[0]["delivery"] == plan["readout_delivery"], "readout visibility differs")
        require(readouts[0]["checksum"] == "valid" and readouts[0]["flags"] == "PA", "readout framing differs")
    require(len(set(total_waits)) == 1, "four-way total wait/readout time not matched")
    for history in ("ordinary", "candidate"):
        benign, blocked = conditions[history + "_benign"], conditions[history + "_blocked"]
        for field in ("events", "actions", "cost", "readout_delivery", "readout_segmentation", "request_framing", "timing_profile"):
            require(benign[field] == blocked[field], f"hostname pair differs in {field}")
    for field in ("readout_delivery", "readout_segmentation", "request_framing", "timing_profile"):
        require(len({c[field] for c in conditions.values()}) == 1, f"four-way {field} mismatch")
    require(conditions["candidate_benign"]["actions"] == plan["actions"], "candidate condition differs from plan")
    require(conditions["candidate_benign"]["events"] == plan["history"], "candidate event history differs")
    expected_resource = plan["trial_repetitions"] * sum(recount(c["events"], cfg["kappa"])["N"] + cfg["kappa"] * recount(c["events"], cfg["kappa"])["T"] for c in conditions.values())
    require(expected_resource == plan["execution_resource_proxy"], "condition/repetition execution cost differs")
    require(plan["trial_repetitions"] == cfg["trial_repetitions"], "repetition count differs")
    return len(conditions)


def protocol_fixtures():
    s0 = initial_state()
    syn = Action(flags="S", seq="isn", ack="none", client="red")
    for action in (replace(syn, delivery="dpi_only"), replace(syn, checksum="invalid")):
        out = one(s0, action)
        require(out.state == s0 and len(out.events) == 1, "invisible/rejected SYN created request, knowledge or reply")
    deferred = one(s0, replace(syn, defer_reply=True))
    require(not deferred.state.knowledge and len(deferred.state.pending) == 1, "unobserved reply taught attacker")
    forbidden(deferred.state, Action(flags="A", client="red", server="pink"))
    delivered = one(deferred.state, Action(kind="deliver_pending"))
    require(not delivered.state.pending and delivered.state.knowledge == (("f0", 0, "pink"),), "queued observation failed to learn exact identity")
    require(not any(e["kind"] == "packet" for e in delivered.events), "queued observation counted as packet")
    request = one(s0, syn).state
    ack = Action(flags="A", client="red", server="pink")
    est = one(request, ack).state
    require(get_flow(est, "f0").phase == "ESTABLISHED", "ordinary handshake fixture failed")
    fin_handshake = one(request, replace(ack, flags="FA"))
    require(get_flow(fin_handshake.state, "f0").phase == "CLOSE_WAIT", "final-handshake FIN was falsely settled established")
    challenge = one(est, Action(flags="R", seq="in_window", ack="none", client="red"))
    require(get_flow(challenge.state, "f0").phase == "ESTABLISHED" and any(e.get("actor") == "server" and e.get("flags") == "A" for e in challenge.events), "nonexact RST reset connection")
    reset = one(est, Action(flags="R", seq="exact", ack="none", client="red"))
    require(get_flow(reset.state, "f0").phase == "LISTEN", "exact RST did not retire connection")
    second = one(reset.state, replace(syn, client="blue", defer_reply=True)).state
    forbidden(second, Action(flags="A", client="blue", server="pink", ack="exact"))
    forbidden(second, Action(flags="A", client="blue", server="purple", ack="exact"))
    stale = one(second, Action(flags="R", seq="old", ack="none", client="red"))
    require(stale.state == second, "stale incarnation reset current request")
    return 11


def decode_state(raw):
    return State(flows=tuple(Flow(**f) for f in raw["flows"]),
                 knowledge=tuple(tuple(item) for item in raw["knowledge"]),
                 pending=tuple(Pending(**p) for p in raw["pending"]),
                 retired=tuple(Flow(**f) for f in raw["retired"]),
                 next_generation=raw["next_generation"], elapsed_units=raw["elapsed_units"])


def clienthello_fixtures(fixture_dir):
    """Parse TLS framing independently of the fixture serializer."""
    metadata = json.loads((fixture_dir / "clienthello.json").read_text())
    parsed = {}
    for variant, entry in metadata["variants"].items():
        data = (fixture_dir / ("clienthello_" + variant + ".bin")).read_bytes()
        require(len(data) == entry["length_bytes"] and data.hex() == entry["hex"], "fixture bytes differ from manifest")
        require(hashlib.sha256(data).hexdigest() == entry["sha256"], "fixture checksum differs")
        require(data[:3] == b"\x16\x03\x03" and int.from_bytes(data[3:5], "big") == len(data) - 5, "TLS record framing invalid")
        require(data[5] == 1 and int.from_bytes(data[6:9], "big") == len(data) - 9, "ClientHello length invalid")
        require(data[9:11] == b"\x03\x03", "ClientHello is not TLS1.2")
        pos = 43  # record(5), handshake(4), version(2), random(32)
        session_length = data[pos]
        pos += 1 + session_length
        suites_length = int.from_bytes(data[pos:pos+2], "big")
        require(suites_length > 0 and suites_length % 2 == 0, "cipher suite vector invalid")
        pos += 2 + suites_length
        compression_length = data[pos]
        pos += 1 + compression_length
        extension_length = int.from_bytes(data[pos:pos+2], "big")
        pos += 2
        require(pos + extension_length == len(data), "extension vector length invalid")
        extensions = {}
        sni_range = None
        while pos < len(data):
            kind = int.from_bytes(data[pos:pos+2], "big")
            size = int.from_bytes(data[pos+2:pos+4], "big")
            pos += 4
            require(pos + size <= len(data) and kind not in extensions, "extension overrun/duplicate")
            extensions[kind] = data[pos:pos+size]
            if kind == 0:
                sni_range = (pos + 5, pos + size)
            pos += size
        require(0 in extensions, "SNI extension absent")
        sni = extensions[0]
        require(int.from_bytes(sni[:2], "big") == len(sni) - 2 and sni[2] == 0, "server-name list malformed")
        require(int.from_bytes(sni[3:5], "big") == len(sni) - 5, "server-name length malformed")
        require(sni[5:].decode("ascii") == entry["hostname"], "SNI hostname differs")
        parsed[variant] = (data, sni_range)
    benign, b_range = parsed["benign"]
    blocked, c_range = parsed["blocked"]
    require(len(benign) == len(blocked) and b_range == c_range, "paired fixture lengths/offsets differ")
    start, end = b_range
    require(benign[:start] == blocked[:start] and benign[end:] == blocked[end:], "paired bytes differ outside hostname")
    return {"variants": len(parsed), "length_bytes": len(benign), "equal_length_SNI_substitution": True}


def check_cpn(model_dir, plans):
    source = model_dir / "tcp_lifecycle.PNPRO"
    data = json.loads((model_dir / "cpn_state_map.json").read_text())
    root = ET.parse(source).getroot()
    page = root.find("gspn")
    nodes = {n.get("name"): n for n in page.find("nodes")}
    require(len(nodes) == len(page.find("nodes")), "duplicate PNPRO node names")
    inputs, outputs = defaultdict(list), defaultdict(list)
    for arc in page.find("edges"):
        require(arc.get("head") in nodes and arc.get("tail") in nodes, "dangling PNPRO arc")
        if arc.get("kind") == "INPUT":
            inputs[arc.get("head")].append(arc)
        elif arc.get("kind") == "OUTPUT":
            outputs[arc.get("tail")].append(arc)
    require(nodes["COMPLETE_ENDPOINT_MARKING"].get("marking") == "<s0>", "incorrect CPN initial token")
    states = data["states"]
    decoded = {key: decode_state(value) for key, value in states.items()}
    require(decoded["s0"] == initial_state(), "state-map initial state differs")
    transitions = defaultdict(list)
    for transition in data["transitions"]:
        name = transition["name"]
        require(name in nodes and nodes[name].tag == "transition", "mapped transition missing")
        control_in = [a for a in inputs[name] if a.get("tail") == "COMPLETE_ENDPOINT_MARKING"]
        control_out = [a for a in outputs[name] if a.get("head") == "COMPLETE_ENDPOINT_MARKING"]
        require(len(control_in) == len(control_out) == 1, "transition does not consume/produce one complete state token")
        require(control_in[0].get("mult") == f'<{transition["source"]}>', "input inscription differs")
        require(control_out[0].get("mult") == f'<{transition["target"]}>', "output inscription differs")
        transitions[transition["action_edge"]].append(transition)
        is_packet = transition["event"].get("kind") == "packet"
        require(transition["packet_cost"] == int(is_packet), "physical packet cost differs")
        require(name.startswith("PACKET_SEND_") == is_packet, "packet transition prefix differs")
    def projected_marking(state_id):
        raw = states[state_id]
        marking = Counter({("COMPLETE_ENDPOINT_MARKING", state_id): 1})
        for flow in raw["flows"]:
            prefix = flow["name"].upper()
            marking[prefix + "_TCP_PHASE", "TCP_" + flow["phase"]] += 1
            if flow["client"] is not None:
                marking[prefix + "_ATTACKER_ISN", flow["client"]] += 1
            if flow["server"] is not None:
                marking[prefix + "_SERVER_ISN_OPAQUE", flow["server"]] += 1
        for server in sorted({item[2] for item in raw["knowledge"]}):
            marking["ATTACKER_KNOWN_SERVER_ISNS", server] += 1
        for field, place in (("client", "RETAINED_OLD_ATTACKER_ISNS"), ("server", "RETAINED_OLD_SERVER_ISNS")):
            for color in {item[field] for item in raw["retired"] if item[field] is not None}:
                marking[place, color] += 1
        for color in {item["server"] for item in raw["pending"] if item["server"] is not None}:
            marking["PENDING_UNOBSERVED_SERVER_ISNS", color] += 1
        return marking

    def inscription(mult):
        # Export uses explicit sums of singleton colors, with no expressions.
        colors = []
        for term in mult.split("+"):
            term = term.strip()
            require(term.startswith("<") and term.endswith(">"), "unsupported exported color inscription")
            colors.append(term[1:-1])
        return colors

    def fire_xml(marking, name):
        marking = marking.copy()
        need = Counter((a.get("tail"), color) for a in inputs[name] for color in inscription(a.get("mult", "1")))
        require(all(marking[key] >= count for key, count in need.items()), "PNPRO transition not enabled under independent token replay")
        marking.subtract(need)
        marking.update((a.get("head"), color) for a in outputs[name] for color in inscription(a.get("mult", "1")))
        return +marking

    initial_xml = Counter()
    for node in nodes.values():
        if node.tag == "place" and node.get("marking"):
            initial_xml.update((node.get("name"), color) for color in inscription(node.get("marking")))
    require(initial_xml == projected_marking("s0"), "PNPRO initial projection differs")
    lookup = {}
    for edge in data["action_edges"]:
        outcome = one(decoded[edge["source"]], Action(**edge["action"]))
        require(outcome.state == decoded[edge["target"]], "mapped endpoint edge differs")
        require(outcome.effect == edge["effect"], "mapped edge effect differs")
        chain = transitions[edge["id"]]
        require(len(chain) == len(outcome.events), "wire-event expansion differs")
        token = edge["source"]
        xml_marking = projected_marking(token)
        for t, event in zip(chain, outcome.events):
            require(t["source"] == token and t["event"] == normalized(event), "expanded event chain differs")
            xml_marking = fire_xml(xml_marking, t["name"])
            token = t["target"]
        require(token == edge["target"], "expanded chain final token differs")
        require(xml_marking == projected_marking(edge["target"]), "PNPRO projected final marking differs")
        lookup[edge["source"], canonical(edge["action"])] = edge["target"]
    require(hashlib.sha256(source.read_bytes()).hexdigest() == data["summary"]["sha256"], "PNPRO hash differs")
    paths = 0
    for plan in plans:
        for condition in plan["conditions"]:
            token = "s0"
            for action in condition["actions"]:
                require((token, canonical(action)) in lookup, "condition action not exported to CPN")
                token = lookup[token, canonical(action)]
            require(states[token] == condition["final_marking"], "exported CPN condition final token differs")
            paths += 1
    return {"action_edges_replayed": len(data["action_edges"]), "wire_transitions_checked": len(data["transitions"]), "condition_paths_replayed": paths, "native_GreatSPN_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path(__file__).with_name("results"))
    parser.add_argument("--model", type=Path, default=Path(__file__).with_name("model"))
    args = parser.parse_args()
    metadata = json.loads((args.results / "run_metadata.json").read_text())
    plans = json.loads((args.results / "plans.json").read_text())
    bundles = json.loads((args.results / "bundles.json").read_text())
    cfg = metadata["configuration"]
    report = {"status": "PASS", "checks_passed": 0, "checks_failed": 0, "failures": [],
              "plans_checked": len(plans), "conditions_checked": 0, "protocol_fixtures": 0,
              "scope": "Independent accounting and offline reference replay; abstract framing/timer assumptions are not empirical calibration; no native GreatSPN execution."}

    def run(name, operation):
        try:
            result = operation()
            report["checks_passed"] += 1
            return result
        except Exception as error:
            report["checks_failed"] += 1
            report["failures"].append({"check": name, "error": str(error), "traceback": traceback.format_exc(limit=3)})
            report["status"] = "FAIL"
            return None

    run("metadata_offline", lambda: require(metadata["packets_transmitted"] == 0 and not metadata["dpi_outcomes_measured"] and not metadata["complete"], "offline/incompleteness metadata differs"))
    fixture_count = run("protocol_fixtures", protocol_fixtures)
    report["protocol_fixtures"] = fixture_count or 0
    tls_fixtures = run("TLS_ClientHello_fixtures", lambda: clienthello_fixtures(Path(__file__).with_name("fixtures")))
    if tls_fixtures:
        report["readout_fixtures"] = tls_fixtures
    for plan in plans:
        count = run(plan["id"], lambda p=plan: check_plan(p, cfg))
        report["conditions_checked"] += count or 0
        run(plan["id"] + "_diagram", lambda p=plan: ET.parse(args.results / "diagrams" / (p["id"] + ".svg")))
    by_id = {p["id"]: p for p in plans}
    for bundle in bundles:
        def check_bundle(bundle=bundle):
            require(2 <= bundle["size"] <= cfg["max_bundle_size"] and bundle["size"] == len(set(bundle["probe_ids"])), "bundle size/identity differs")
            require(all(p in by_id for p in bundle["probe_ids"]), "bundle references missing probe")
            require(bundle["execution_resource_proxy"] == sum(by_id[p]["execution_resource_proxy"] for p in bundle["probe_ids"]), "bundle cost differs")
            require(bundle["outcome_vector"] == [None] * bundle["size"] and bundle["separated_reference_pairs"] is None, "bundle outcomes filled")
            require(all(bundle["id"] in by_id[p]["bundle_ids"] for p in bundle["probe_ids"]), "bundle reverse link differs")
        run(bundle["id"], check_bundle)
    cpn_report = run("exported_cpn", lambda: check_cpn(args.model, plans))
    if cpn_report:
        report["cpn"] = cpn_report
    report["coverage"] = dict(Counter(p["family"] for p in plans))
    report["input_sha256"] = {name: hashlib.sha256((args.results / name).read_bytes()).hexdigest() for name in ("plans.json", "bundles.json", "run_metadata.json")}
    target = args.results / "verification.json"
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in {"coverage", "input_sha256", "failures"}}, indent=2))
    for failure in report["failures"][:10]:
        print(failure["check"], failure["error"])
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
