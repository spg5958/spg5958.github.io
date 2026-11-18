# Offline TCP lifecycle measurement generator

This package generates and ranks symbolic TCP measurement plans, four-way control/test replays, and small probe bundles. It includes an executable finite colored Petri net, machine-readable plans, packet-exchange SVGs, and a self-contained HTML browser. It sends no packets and contains no measurement-transmission implementation.

The pilot produced **212 distinct plans and 17 proposed bundles**. All censorship outcomes are `null` / unmeasured. See [REPORT.md](REPORT.md) for results, configuration assumptions, and incomplete exploration, and [model_notes.md](model_notes.md) for the endpoint profile.

## Browse the supplied results

Open [results/index.html](results/index.html) in a browser. Its plans, overview, and exchange diagrams are embedded, so it works from a local file without starting a web server. Filters expose lifecycle goal, decision family, visibility, and cost. Individual SVG and JSON downloads retain the underlying records. The Dark mode button at the top switches the entire browser, including packet diagrams, between light and dark themes. It follows your system preference initially and remembers your choice when browser storage is available.

## Reproduce

Use Python 3 with its standard library; no external Python packages or Java installation are required for this offline engine. From this directory:

```bash
python3 run_pilot.py --config pilot.json --output results
python3 verify_results.py --results results --model model
python3 verify_cpn.py
```

`search.py` regenerates plans, controls, bundles, the bounded CPN, SVGs, and HTML. `verify_results.py` independently checks accounting, reference replay, protocol fixtures, and the exported CPN and writes `results/verification.json`. Read that file for the verification result of the current output set. To redraw existing results without rerunning search:

```bash
python3 render_results.py results
```

The supplied `pilot.json` is an **assumed pilot**: the named `TCP_lifecycle_measurement_prompt.md` was unavailable among the attachments, and the supplied PDF gives no numeric pilot. Its bounds and assumptions are explicit rather than attributed to the missing document.

## Files

| Path | Content |
|---|---|
| `endpoint.py` | Linux-inspired symbolic endpoint, knowledge guards, ordered genuine replies, and visibility/checksum projection |
| `search.py`, `pilot.json` | Full-prefix weighted enumeration, frozen ordinary-progress grammar, controls and bundles |
| `model/tcp_lifecycle.PNPRO` | Executable bounded colored endpoint state machine with visible state/ISN/knowledge projections |
| `model/cpn_state_map.json` | Decoded endpoint states, action edges, and Petri transition mapping |
| `model/cpn_export_summary.json` | Export bounds, retained frontier, and provenance |
| `fixtures/` | Two framing-valid, fixed 100-byte TLS ClientHello fixtures with equal-length placeholder names |
| `results/plans.json`, `plans.jsonl`, `plans.csv` | Complete records and compact analysis formats |
| `results/bundles.json` | Proposed small multi-probe combinations with unmeasured outcome vectors |
| `results/diagrams/`, `overview.svg`, `index.html` | Per-plan exchanges, grouped overview, and offline results browser |
| `results/run_metadata.json`, `verification.json` | Actual configuration, search scope, limitations, and validation |

The CPN is generated from the same endpoint oracle used by search. Its XML and firing structure are checked locally; it has **not** been opened or simulated in native GreatSPN. The symbolic profile is not a complete current Linux implementation. Search quotas, restricted actions, fresh disjoint ISN windows, abstract waits, and finite export bounds prevent completeness or global optimality claims.

`allowed.example` and `blocked.example` are equal-length placeholders, with no claimed censorship behavior. Neither the fixtures nor an ordinary Linux ACK establishes an empirical censorship signal. Future measurements would require calibrated hostnames, delivery, timing, and an attributable policy action; this package leaves that work unimplemented.
