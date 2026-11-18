# TCP segmentation search: computed results

1,000 distinct offline packet programs retained from 40,697 synthesized candidates.
9,000 planned fresh-connection trials including controls and repetitions. No real DPI observations.

## Bounds and computation

- Serialized TLS ClientHello: 103 bytes; hostname interval [63, 79).
- At most 6 data packets and 2 simultaneous holes; every framing/gap packet counted.
- Search time: 32.223 seconds on this host; this is not an Apple M2 benchmark.
- Ordered geometry enumeration is exhaustive at completed budgets marked exhaustive in search_summary.json. Payload assignments use a declared finite profile.
- Higher budgets use declared resource cutoffs. The selected library and greedy bundles are not globally optimal or globally shortest.

| Data packets | Retained programs |
|---:|---:|
| 1 | 6 |
| 2 | 118 |
| 3 | 527 |
| 4 | 205 |
| 5 | 81 |
| 6 | 63 |

## Measurement bundles

| Bundle | Connections | Data packets | Nominal repeated-control packets |
|---|---:|---:|---:|
| Two-connection example from the specification | 2 | 6 | 126 |
| Compact two-connection packet bundle | 2 | 5 | 117 |
| Six-connection measurement bundle | 6 | 14 | 342 |
| TTL-only measurement bundle | 5 | 11 | 279 |
| Two-connection bundle with split target SNI | 2 | 5 | 117 |

## Interpretation

- All actual observations remain null. The tables describe packet programs, costs and future measurement procedures.
- 19 descriptive geometry fixtures are represented. Exact Dharmapurikar–Paxson Figure 4 A–T mapping remains unverified; no audited 20/20 coverage claim.
- h=4 assumes a three-packet ordinary handshake plus a genuine-state client RST. Nominal cost includes three trial types and three repetitions.
- Actual execution totals additionally require measured calibration, retransmissions/injected traffic and waits. Those fields remain null.
- Server silence, ordinary resets, ICMP expiry and local timeouts do not by themselves establish censorship.

## Files

Open index.html. It contains all result data and works without a local web server or external assets. Figures and machine tables are included alongside it.
