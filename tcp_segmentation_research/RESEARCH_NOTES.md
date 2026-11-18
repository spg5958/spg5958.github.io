# Research notes: TCP segmentation and binary DPI fingerprints

## Scope and relation to the earlier TCP model

The uploaded CPN archive provides context for the packet-sequence research and its ranked, inspectable results. That model does not implement arbitrary byte-stream overlap reconstruction. This extension instead implements the attached PDF's ordered-interval synthesis procedure. Its result is a reproducible collection of offline measurement plans with hypothetical binary predictions. No reachability claim about the earlier PNPRO model is used to validate byte-level reassembly behavior.

The experiment domain is one TLS 1.2 ClientHello in one TLS record. The serializer constructs the record and derives the hostname interval from its nested structure. Only hostname letters vary; record, handshake, extension, list, and hostname lengths remain consistent. `T` and `B` denote target/benign templates, and each data packet takes its payload from the selected template slice. This is TCP segmentation, with no added TLS record-fragmentation variable.

The principal illustrative pair is `abcdefgh.example` / `abcdxygh.example`. A second equal-length alternative, `ijklmnop.example`, supports seed histories with more widely separated conflicting regions. These names implement a hypothetical exact-match policy. Any practical replacement needs independently calibrated equal-length names and regenerated serialization.

## Backtracking, state, and limits

The backtracker descends through ordered half-open interval choices at increasing data-segment budgets and restores its prefix state when returning. It preserves arrival order, interval endpoints, payload choices, visibility and checksum family. An incomplete prefix needs at least one further packet; this yields a conservative completion lower bound. Prefixes exceeding the reference hole bound are rejected. Known-model agreement is not used to prune structural histories.

A reference hole is a maximal missing interval with received reference data beyond it. A future suffix does not count. Every emitted trial covers the complete TLS record, including framing and all gaps. The defaults allow up to six data segments and two simultaneous holes. Different histories with the same final union are kept distinct; duplicate suppression uses the packet program's identity.

The finite search endpoints and broader retained/fixture endpoints are recorded separately in the dataset. Under the default settings, geometry budgets up through three segments complete enumeration over the stated search endpoints; budgets four through six use disclosed resource cutoffs. This claim concerns geometry only. Payload witnesses are synthesized from ownership/provenance disagreements plus limited exploratory assignments, rather than exhaustively enumerated strings or template choices. Seed histories extend coverage beyond the enumerator's main endpoint set.

Retention favors families, budgets, geometry features, and prediction-vector diversity. The retained 1,000 plans are not a cost-sorted prefix of the complete experiment language. Neither candidate enumeration nor greedy bundle selection proves global minimality.

## Hypotheses and binary observations

The reference set contains twenty illustrative deterministic hypotheses:

- Sixteen combinations of four overlap ownership choices, two inspection modes, and two checksum-validation choices. The ownership choices are first arrival, last arrival, lower segment start, and higher segment start. Equal-start ties keep first arrival.
- A conflicting-overlap rejection hypothesis.
- A parser that needs the entire ClientHello in one packet beginning at stream offset zero.
- A parser gated on genuine server data ACK evidence.
- A hypothesis that rejects the calibrated server-expiring TTL class and validates full-TTL checksums.

The inspection modes either freeze a contiguous prefix as it becomes available or retain mutable buffered bytes until the first complete TLS record. Policy triggers latch irreversibly. A later conflicting segment cannot undo a previously predicted censorship action. Internal reconstructed hostname strings and provenance explain model behavior; they are not additional measured symbols.

The sole measurement is the calibrated censorship bit. This experiment family deliberately prevents ClientHello bytes from reaching or being accepted by Linux. The real server therefore supplies no data ACK evidence. A candidate model's inspection frontier and the real ACK frontier are separate state. Ordinary setup learns genuine ISNs; cleanup uses the actual acknowledged sequence frontier.

No live measurements were performed. Prediction vectors cannot identify deployed products, prove their overlap algorithms, or establish stable fingerprints. Matching finite vectors establishes only observational equivalence under the chosen reference models, policy rule, packet families, and retained plans. For example, ACK-gated and TTL-rejecting hypotheses can remain indistinguishable in this server-isolated domain.

## Two-connection diagnostic example

Let `u` be the serialized hostname start and `L` the record length. The PDF's packets are `X=[u+2,u+6)` from the target, `Y=[u+4,L)` from the benign template, and `G=[0,u+2)` from the target. A sends `X,Y,G`; B sends `Y,X,G`, on fresh connections. All six data packets use the default TTL/valid-checksum regime. The leading framing arrives last, and no individual packet contains the complete target hostname.

| Buffered overlap hypothesis | A | B |
| --- | ---: | ---: |
| First arrival | 1 | 0 |
| Last arrival | 0 | 1 |
| Lower segment start | 1 | 1 |
| Higher segment start | 0 | 0 |

This table is a verified reference-model prediction under the illustrative exact-SNI rule, not a measurement of four DPI products. A generated suite may choose a different trial order; its vector columns follow its probe list.

## Bundle selection and practical cost

The greedy selector scores each remaining candidate by newly separated model pairs divided by its planned repeated-control packet estimate. It updates unresolved pairs after each selection and stops when no candidate adds a split. It does not enumerate a Cartesian product of all multi-connection programs and does not claim an optimal suite.

Structural cost is `N_data + h × N_connections`; default `h=4` represents three handshake packets and one reset cleanup. Planned execution uses three repetitions of each mixed, all-target, and all-benign program: nine connections per candidate, or `9 × (N_data + 4)` nominal packets at the default settings. All payload-bearing framing, duplicates, gaps, and completion segments count. Actual calibration traffic, waits, retransmissions and policy-generated packets remain unknown. Failed controls are quality metadata, never a third fingerprint value.

The same-geometry controls preserve packet visibility and checksum classes. Their expected bits are supplied per hypothesis, rather than forced to target=1 and benign=0. Separate ordinary target/benign baselines must establish that an intended policy and detector are available before practical trial results are evaluated.

## Geometric coverage qualification

The source paper's Figure 4 A–T labels were not visually verified in this run. The supplied geometry file explicitly records this uncertainty and uses nineteen descriptive fixtures: exact/prefix/suffix/middle hole fill, both overlap directions, containment, duplicates, equal starts and ends, adjacency, multi-region bridge/span, and conflicts after/crossing an inspection frontier. The dataset records which retained plans realize each fixture. These are useful generic local geometries, not an audited mapping to all twenty source letters. The paper's particular normalization algorithm is not treated as an oracle for an unknown DPI.

## Validation and reproducibility

`validate.py` independently parses TLS structure, checks literal payload slices, recomputes interval coverage/holes, replays all declared model predictions and same-geometry controls, and recomputes bundle vectors and costs. Regression checks include the PDF's two-connection table and irreversible inspection/trigger behavior. The generated validation report describes completed checks. Offline agreement cannot replace live Linux, DPI, on-wire checksum, TTL, or detector validation.

Search bounds, seed/source tags, model definitions, per-budget cutoffs, planned costs, and unmeasured observation fields are preserved in JSON. The dataset and its generated search summary are authoritative for numerical counts in the delivered run.

## Sources

The attached `dmap_tcp_segmentation_algorithm(1).pdf` supplies the task's experiment and interpretation contract.

- Xue et al., *Fingerprinting Deep Packet Inspection Devices by Their Ambiguities*: https://diwenx.com/assets/files/dmap.pdf
- Dharmapurikar and Paxson, *Robust TCP Stream Reassembly In the Presence of Adversaries*, Figure 4: https://www.usenix.org/legacy/event/sec05/tech/full_papers/dharmapurikar/dharmapurikar.pdf
- Knuth, Algorithm B / Basic backtrack, publisher excerpt referenced by the specification: https://www.informit.com/articles/article.aspx?p=3150366&seqNum=5
- RFC 6066, Server Name Indication: https://www.rfc-editor.org/rfc/rfc6066.html
- RFC 791, Time to Live: https://www.rfc-editor.org/rfc/rfc791.html
- RFC 9293, TCP: https://www.rfc-editor.org/rfc/rfc9293.html
- Baggett, *IP Fragment Reassembly with Scapy*, diagnostic motivation referenced by the specification: https://www.giac.org/paper/gcia/4333/ip-fragment-reassembly-scapy/106563
