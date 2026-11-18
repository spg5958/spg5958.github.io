# Model-guided TCP handshake probes for dMAP

Open **index.html** to browse 1,000 distinct packet sequences. The browser is standalone. It includes dark mode, a Back button, and diagrams styled after the supplied S0993.svg. Controls and readout details appear immediately below each packet diagram.

This revision builds the CPN first and searches its actual markings. It uses the `SequenceSearchSession` implementation in the search code supplied at the start of this conversation, adapted for history-dependent weighted costs. The previous Python TCP endpoint oracle is not part of this implementation.

## Results

| Goal | Distinct complete packet sequences | Weighted cost range |
|---|---:|---:|
| First establishment | 334 | 5–9 |
| Reconnect on the same four-tuple | 333 | 10–13 |
| Reconnect on another four-tuple | 333 | 10–12 |
| Total | 1,000 | 5–13 |

Each path includes its readout and cleanup packets. Packet-sequence uniqueness compares ordered packet headers, direction, flow/incarnation, visibility, checksum and payload class; changing an internal firing or moving an idle wait does not manufacture a distinct packet sequence. Readout and cleanup variants count when the actual packet sequence differs. These results contain 601 distinct prefixes before readout, as well as complete readout/cleanup variants.

All 4,000 ordinary/candidate × benign/blocked conditions remain unmeasured. The four condition names are the same for every measurement. Their actual CPN histories, readout flow/incarnation/delivery, costs and execution resources depend on the selected measurement and can be expanded below its diagram. Ordinary controls use matching readout visibility, fixed framing, and matched abstract waits before readout and after cleanup.

## Reproduce

Use Python 3.10+ and its standard library. Run these commands from this directory:

```bash
python3 model_builder.py
python3 search_cpn.py --k 1000 --seconds 150
python3 assemble_results.py
python3 verify_revision.py --model model/model_guided_tcp_handshake.PNPRO --results results --expected-count 1000
```

The first command creates the source PNPRO. The search reads that file; it does not generate or replace it. Model hashes before and after search are recorded. The model has 75 places, 671 transitions, 5,807 arcs, and attacker/server ISN classes `{red, blue}` and `{pink, purple}`. Both native PNPRO and its readable structural overview are in `model/`.

`cpn_runtime.py` is a generic interpreter for the fixed literal-color arcs and integer guards used by this CPN. No TCP behavior is hard-coded in its firing engine. `annotations.json` attaches packet descriptions, cost labels and display information to native transitions. XML places, arcs and guards determine state changes and enabled firings.

The supplied search implementation remains in `greatspn_paths.py`; its original input is in `sources/greatspn_paths_original.py`. The exact source diff and hashes are provided in `greatspn_paths_weighted.patch` and `search_code_provenance.json`. See `SEARCH_CHANGES.md` for the adaptation.

## Weighted search

The measured-path generation cost is exactly:

`C = N + A + 2W + kappa*T`, with `kappa=1`.

`N` counts every transmitted packet, including genuine server replies, readout and cleanup. `A` counts attacker departures from ordinary protocol progress. `W` counts such departures when they add no new designated decision label within that prefix. `T` counts explicit abstract wait units. Wait units have no claimed physical duration.

To prioritize completion efficiently, reverse Dijkstra computes a remaining `N+T` lower bound `h` from the CPN's finite marking/readout-stage graph with history budgets and departure penalties relaxed. The modified supplied Dijkstra engine uses nonnegative edge weights `deltaC + h(child) - h(parent)`. At complete goals `h=0`, so completed paths retain their order by the original PDF cost. Complete ordered prefixes remain distinct, even when their Linux markings reconverge. Results are cost ordered within each lifecycle goal. The 334/333/333 allocation provides lifecycle coverage rather than one global cheapest list across different goals.

The first 1,000 paths happen to have `W=0`: repeated decisions are penalized enough to occur later. A separate actual-CPN repeated-probe fixture verifies `N=7,A=2,W=1,T=0,C=11`; the independent generic search fixture also checks different costs for repeated use of one transition name.

## Stopping rules and scope

The stopping target is 1,000 unique complete packet sequences, allocated as above. There is no two-plan decision-family quota. Safeguards are 150 seconds, 500,000 expansions and 160,000 queued prefixes per goal; each replay is bounded by 32 packets, 48 CPN firings, two wait units and two unusual attacker actions. The CPN permits two total incarnation identities across two four-tuples. All three goal searches reached their path targets, leaving unexplored prefixes. This is bounded exploration, not exhaustive Linux TCP coverage.

The source CPN uses a conservative symbolic passive-server profile. It includes setup, reset and ACK/SEQ validation representatives, FIN close variants, FIN_WAIT1/2, CLOSE_WAIT, LAST_ACK, CLOSING, TIME_WAIT, and same/different-four-tuple reconnection. Old state and learned identities remain in separate incarnation subnets. Mandatory reply banks serialize genuine server responses. It excludes simultaneous active open, arbitrary loss/reordering, PAWS/options/SACK, SYN cookies, backlog pressure, segmentation/reassembly, and TIME_WAIT fast reuse. In-window-ahead representatives leave a 32,768-byte gap that the fixed 100-byte readout cannot fill. Application close and abstract timeout expiry are explicit assumptions.

Both TLS fixtures are 100-byte framing-valid ClientHellos with equal-length placeholder names. Neither name has measured censorship status. All DPI outcomes, fingerprint information gains and pair separation remain null. Missing endpoint responses to TTL-limited readouts cannot establish censorship.

Independent validation replays all 1,000 paths and 4,000 conditions using separate XML token arithmetic and checks knowledge, endpoint-invisible traffic, costs, lifecycle checkpoints and cleanup. See `results/verification.json`. Native GreatSPN was unavailable: this environment did not validate its GUI/parser/runtime. The included PNPRO uses literal scalar colors, ordinary integer guards and standard input/output arcs; full GreatSPN expression syntax is outside the included interpreter's supported subset.

The Back button returns through safe same-origin browser history when available, otherwise to the parent research index. The default entry points are `index.html` and `results/index.html`.
