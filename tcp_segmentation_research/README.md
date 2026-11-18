# TCP segmentation experiment results

This package extends the TCP packet-sequence research with an offline ordered-interval backtracker based on the attached segmentation specification. It generates TLS SNI experiment plans, predicts binary outcomes under explicitly defined reference hypotheses, and selects small fingerprint bundles. The byte-level engine is separate from the earlier CPN/Dijkstra model.

No packets were transmitted. No DPI, Linux endpoint, route TTL, or censorship detector was measured. Every actual observation remains unmeasured. The reserved `.example` names express an illustrative exact-SNI policy rather than known Internet censorship targets.

## Open the results

Open `results/index.html` in a browser. It includes searchable experiment details, packet-exchange diagrams, interval and byte information, prediction vectors, small bundles, and validation/search information. The webpage runs locally without an Internet service.

The generated `results/search_summary.json` contains the authoritative counts and search cutoffs for this run. `results/results.json` is the full machine-readable dataset. `results/validation.json` records the independent offline checks. Individual vector diagrams are in `results/probe_images/`, and `results/combined.svg` gives an aggregate view. Additional CSV exports accompany the webpage.

Use the light/dark toggle at the top right. It follows your system setting initially and remembers your selection; tables and packet diagrams follow the selected theme.

## Reproduce the offline search

The Python programs use Python 3 and the standard library. Run commands from the extracted package directory:

```bash
python3 search.py --output results
python3 validate.py results/results.json
python3 export.py results/results.json
python3 render_results.py results/results.json results/index.html
```

The search generates candidate plans and bundles. The validator independently checks serialization, payloads, interval coverage, holes, model predictions, observations, and bundle costs. The exporter writes machine-readable tables, and the renderer regenerates the webpage and SVG figures.

Typical explicit search settings are:

```bash
python3 search.py --output results --keep 1000 --max-segments 6 --max-holes 2 --overhead 4 --repeats 3
```

Use `python3 search.py --help` for bounded search options. The default finite endpoint set uses selected SNI cuts; `--all-hostname-cuts` expands it and can increase runtime considerably. Node, geometry, and time limits are reported per budget. A changed target or benign hostname causes serialization and offsets to be regenerated. Hostnames must meet the profile's equal-length and label-structure constraints. The present framing profile requires the complete ClientHello to fit the supplied MSS/path payload bound; it refuses an unsupported bound instead of hiding extra framing packets.

## What one experiment means

Each ordered interval is a TCP payload slice of one serialized TLS ClientHello. Its sequence number is `CLIENT_ISN + 1 + start`, bound only after an ordinary genuine three-way handshake. ACK fields use the learned `SERVER_ISN + 1`. Framing, hostname pieces, duplicates, gap fills, and completion packets all count against the data-segment budget.

The default `ttl_valid` family gives every ClientHello data segment a calibrated TTL that reaches the DPI and expires before Linux, with a valid TCP checksum. `full_bad_checksum` and `ttl_bad_checksum` are separate experimental families. The former requires its invalid checksum to remain invalid at Linux. TTL and checksum classes describe intended delivery/acceptance controls; an unknown DPI may inspect or discard those packets differently.

The genuine server data receive/ACK frontier remains at `CLIENT_ISN + 1`. There is no server ACK for the trial bytes and no expected TLS response. The send schedule therefore does not wait for data ACKs. Planned cleanup uses the genuine frontier, not the trial's largest sequence offset.

The sole proposed measured symbol is `Y=1` for a calibrated censorship signal or `Y=0` for no such signal during an evaluable observation interval. Missing TLS responses, normal resets, ICMP expiry, and local timeouts do not by themselves establish censorship. Detector failure, route drift, or failed calibration excludes a run through metadata. A DPI that requires genuine data ACKs may correctly yield zero in this setup.

## Cost and repeated controls

The structural cost is `C = N_data + h × N_connections`, with default `h=4`: three ordinary handshake packets and one genuine-state reset cleanup, as a nominal estimate. Every candidate uses one connection.

The planned repeated procedure runs the mixed test, an all-target control with the same geometry, and an all-benign control with the same geometry. At the default three repetitions, this means nine fresh connections per retained probe and a nominal packet estimate of `9 × (N_data + 4)`. Bundle costs sum their constituent probes. Separate ordinary visibility/calibration trials, retransmissions, injected packets, route checks, and waits remain unknown; the estimate is not an actual wire count or elapsed-time measurement.

A same-geometry all-target control need not predict one under every hypothesis: ACK gating, segmentation restrictions, or checksum rejection can prevent inspection. Run-quality decisions also need independent ordinary target/benign visibility baselines and a calibrated detector.

## Read the conclusions carefully

The page-4 example reproduces the two fresh-connection trials `X,Y,G` and `Y,X,G`. In A-then-B order, the four simplified buffered overlap hypotheses predict first-arrival `10`, last-arrival `01`, lower-start `11`, and higher-start `00`. Six data packets therefore suffice for this illustrative four-way split. The generated bundles may list the same experiments in a different order, so read their vectors against the listed probe IDs.

The broader pool also includes separate conflicting SNI regions, a segment spanning multiple buffered regions, conflicts after or across an inspection frontier, checksum contrasts, and a coverage-driven exploratory pool. Twenty declared hypotheses supply model predictions. Fingerprint equivalence classes describe those hypotheses under the selected experiment domain; they are not measured implementation identities.

The retained set is selected for diversity and coverage. It is not the 1,000 globally shortest experiments or a globally cheapest suite. Geometry enumeration is exhaustive only for the reported completed budgets and finite endpoint domain; payload synthesis remains guided. The default larger budgets have disclosed cutoffs. Exact Figure 4 A–T letter mapping is unverified: nineteen descriptive fixtures provide generic local-geometry coverage, and no audited 20/20 A–T coverage claim is made.

See `RESEARCH_NOTES.md` for assumptions, interpretation, and sources.
