# Offline lifecycle pilot report

The extension generated **212 distinct candidate measurement plans**, four matched conditions per plan, **17 proposed three-probe bundles**, 212 packet-exchange SVGs, an overview, and an offline HTML browser. It also exported an executable bounded colored endpoint net. **Zero packets were transmitted; all DPI outcomes, information gains, and reference-pair separation values remain unmeasured.**

## Inputs and task scope

The supplied handshake PDF defines the observation contract on pages 2–4, weighted objective on page 5, full-prefix enumeration on page 6, and empirical suite selection on page 7. The attached ZIP supplied two executable source CPNs and the earlier establishment results; the attached `greatspn_paths(1).py` supplied the preceding search/export design. The new engine and browser extend the experiment offline.

`TCP_lifecycle_measurement_prompt.md` was absent from the three available attachments and from the ZIP. The PDF specifies two initial incarnations but no numeric pilot. Consequently, `pilot.json` records an **assumed pilot**, not a recovered documented configuration. This report identifies that substitution instead of claiming compliance with an unavailable specification. See the supplied baseline audit for the original nets and search settings.

## Results and coverage

| Goal | Plans | Completed-replay weighted cost |
|---|---:|---:|
| Establish the first incarnation | 44 | 5–12 |
| Leave first establishment, reconnect on the same four-tuple | 84 | 11–20 |
| Leave first establishment, establish on a different four-tuple | 84 | 10–18 |
| Total | 212 | 5–20 |

The first goal measures a settled first ESTABLISHED checkpoint and its separately appended readout/cleanup. It does not require a reconnection. The reconnect goals explicitly require leaving the first established state before reaching the second incarnation. Different-four-tuple establishment preserves the earlier flow's remaining state until independently costed trial cleanup.

Before exact-trace deduplication, 228 stratum proposals covered 13 families: ordinary calibration (6 plans), allocation (12), sequence validation (20), acknowledgment validation (20), reset (24), early FIN (16), visibility (38), checksum (34), combined visibility/checksum (24), incarnation (8), flow identity (4), repeated control (16), and deferred reply observation (6). These counts describe generated opportunities, not observed DPI classes. Family, phase, control meaning, SEQ/ACK relation, incarnation relation, visibility, and checksum form semantic labels; changing flags alone is not treated as demonstrated fingerprint value.

Identical complete action traces were merged into 212 experiments; all original family/phase classifications remain attached. Thus family counts overlap rather than defining additional experiments.

All **114 configured goal/family/phase strata** reached their quota of two plans, normally paired full and DPI-only readouts. The run popped 7,101 prefixes and generated 11,176 successors in about 0.57 seconds of search/control composition; model export and rendering occur afterward. The aggregated unexpanded search frontier was 4,189 prefixes. The short runtime reflects the restricted pilot grammar and quotas, rather than exhaustive exploration.

The 17 bundles group three plans each for complementary semantic coverage within a lifecycle goal. They are economical proposals under the recorded resource proxy. Their outcome vectors and separated-reference-pair values are null. The PDF's empirical greedy pair-separation rule cannot be evaluated without repeated reference-profile measurements.

## Frozen pilot and weighted objective

| Setting | Value |
|---|---|
| Genuine incarnations | At most 2 globally; attacker red then blue, server pink then purple |
| Four-tuple names | `f0`, `f1` |
| Per completed replay | At most 32 packets, 24 actions, and 2 explicit wait units |
| Departure bound | At most 2; the pilot generally permits one designated departure, or a repeated-control pair |
| Search quota | 2 plans per configured goal/family/phase stratum |
| Per-stratum safeguards | 12,000 expansions and 12,000 frontier entries |
| Wall-time safeguard | 120 seconds across search strata |
| Wait weight | `kappa=1`; abstract units, with no seconds mapping |
| Planned repetitions | 3 per condition; none executed |
| Bundle bound | At most 3 probes; configured maximum 24 bundles |

The generation objective is exactly `C = N + A + 2W + kappa*T`. `N` counts attacker packets, genuine server replies, readout, and cleanup. `A` counts attacker packet actions departing from the frozen reference automaton. `W` counts those departures adding no new designated label within that prefix. `T` counts explicit waits. Server replies add packet cost without an attacker-departure penalty. Repeating an already exercised decision therefore costs more than testing it once.

For example, plan P0191 repeats a DPI-only control decision. Its completed candidate replay has `N=7`, `A=2`, `W=1`, `T=0`, giving `C=11`. The cost includes its DPI-only readout and genuine endpoint cleanup; neither invisible SYN generates a Linux reply.

Each search object contains the complete ordered prefix, endpoint marking, retained knowledge, lifecycle progress, and prior decision labels. A min-priority queue orders prefixes by accumulated weighted cost. There is no `visited[Linux_marking]` or cheapest-state dominance pruning. Equal endpoint markings can retain distinct DPI-visible histories. Checkpoint readout and cleanup are appended to a copy and checked against bounds; they never contaminate a prefix continued toward reconnection.

Generation cost differs from the estimated physical execution burden. Every plan records all four conditions and three planned repetitions. `execution_resource_proxy = repetitions * sum_conditions(N + kappa*T)` counts those replays and their cleanup while omitting artificial `A/W` ranking penalties. Bundles sum their member proxies without assuming shared controls. This is an offline wire/wait proxy, not calibrated elapsed time or measured experiment cost.

## Controls, visibility, and readout

| Condition | Role |
|---|---|
| Ordinary history + benign SNI | Negative baseline |
| Ordinary history + blocked SNI | Positive censorship calibration |
| Candidate history + benign SNI | Detect effects unrelated to the triggering name |
| Candidate history + blocked SNI | Candidate censorship bit |

Paired conditions match readout visibility, fixed framing, abstract readout wait deadline, and total wait units; shorter reference histories receive explicit padding. Each condition retains its full actions, events, final marking, and cost. Calibration, delivery confirmation, observability, and repeat stability are null quality metadata. Failed observability or inconclusive trials would be excluded rather than assigned a third fingerprint value.

The fixed readout is one framing-valid 100-byte TLS ClientHello segment. Fixtures use equal-length `allowed.example` and `blocked.example` placeholders, reproducible random bytes, and checked TLS/SNI length fields. Neither name is known blocked or benign on a real path. The reference endpoint models a TCP ACK when it accepts a full-delivery readout; it does not simulate TLS negotiation or an application response.

Every packet separates DPI visibility, Linux IP arrival, accepted TCP effect, and unknown DPI processing. Full/valid packets run the endpoint profile. Full/invalid-checksum packets reach IP but have no accepted TCP effect or reply. DPI-only packets expire before Linux regardless of TCP checksum. The PDF's checksum alternatives are restored even though the prior experiment removed that dimension. IP checksums remain valid by assumption.

A DPI-only readout expects no Linux response. Missing responses, ordinary resets, ICMP expiry, checksum rejection, and timeouts cannot establish censorship. Only a separately calibrated, attributable SNI-dependent side effect would make its future binary outcome evaluable. The two server colors are opaque identities: knowledge appears only after observing a genuine revealing server packet. A DPI-only SYN cannot teach a server ISN.

## Endpoint and CPN interpretation

[model_notes.md](model_notes.md) defines the implemented Linux-inspired reference profile and its explicit differences from the supplied baseline. It includes passive establishment, close variants, FIN_WAIT1/2, CLOSING, CLOSE_WAIT, LAST_ACK, TIME_WAIT, reset, retained old incarnations, and one deferred server-reply observation. Server application close is an explicit environment trigger; genuine wire responses follow endpoint rules.

The new profile disables `TCP_DEFER_ACCEPT`, which the supplied baseline enabled. Two fresh attacker colors represent disjoint sequence windows and are consumed without replacement. Same-tuple reconnect waits for modeled TIME_WAIT expiry; Linux early reuse is omitted. Wait units are abstract. TIME_WAIT reset handling freezes `tcp_rfc1337=1`; challenge responses assume permissive/rearmed rate limits. The in-window-ahead representative is `RCV.NXT+32768`, and no admitted history fills that gap. Persistent arbitrary out-of-order queues are consequently outside this profile. A fixed server-response policy replaces application/timing variability.

The PNPRO contains a finite colored state machine generated from this endpoint oracle. A `CState` token encodes the full marking; ten live projection places expose flow state, ISNs, knowledge, retained identities, and pending observation. Ordered packet transitions count each wire event once, with intermediate states forcing genuine replies before the next macro-action. Prefix-dependent `A/W` accounting remains in search.

Export retained 844 endpoint states, 2,288 intermediate states, 12,000 action edges, and 14,288 transitions. It seeded all 848 control/test action traces, then expanded the endpoint graph until its edge bound. There are 572 frontier endpoint states. This is a bounded executable encoding with XML/structural and offline firing checks; native GreatSPN loading/simulation was unavailable and is not claimed. It is not a fidelity-preserving mechanical conversion of the old net or a complete current Linux clone.

The measured final generation run took 4.96 seconds including CPN export and HTML/SVG rendering, with about 289 MiB peak Python RSS on this Linux host. This is a host measurement, not an M2 benchmark. See `results/resource_usage.json`.

## Limits and reproducibility

The supplied README gives standard-library Python regeneration and verification commands. Final verification passed 445 checks across all 212 distinct plans and 848 matched conditions, including independently parsed TLS fixtures and complete replay of the exported action edges. The second independent CPN verifier fired all 14,288 transitions and replayed 1,060 plan/control sequences; see `results/verification.json` and `model/cpn_verification.json`. Diagrams were visually inspected after rendering; browser JavaScript, filters, and exports were checked, but Chromium UI rendering was blocked by the environment's socket restriction.

Search results and model exports each disclose their own incomplete frontier. Quotas, restricted flags and SEQ/ACK representatives, family-specific action grammar, at most two incarnations, and bounded waits prevent claims of exhaustive lifecycle coverage or global optimality. Increasing bounds alone does not remove alphabet/profile restrictions. This pilot reruns deterministically from the initial state; it does not save a resumable enumeration frontier.

This pilot excludes simultaneous active open, server-initiated SYN, arbitrary queues/reordering, loss, PAWS/options/SACK, SYN cookies/backlog pressure, segmentation/reassembly search, arbitrary payloads, unfilled-gap completion, and SYN_RECV idle timer exploration. It does not predict unknown DPI state, censorship interference, or fingerprint accuracy. Those limitations are material to interpreting generated feasibility.

Source basis: supplied `dmap_tcp_handshake_algorithm (1)(1).pdf`, pages 2–7; [upstream Linux receive/validation code](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_input.c); [request sockets and TIME_WAIT](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_minisocks.c); and [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html). The upstream links are explanatory primary references, not a pinned claim of exact implementation equivalence.
