# TCP segmentation search: computed results

1,000 distinct offline packet programs retained from 40,697 synthesized candidates.
20 illustrative hypotheses; 9,000 planned fresh-connection trials including matched controls and repetitions. No real DPI observations.

## Bounds and computation

- Serialized TLS ClientHello: 103 bytes; hostname interval [63, 79).
- At most 6 data packets and 2 simultaneous holes; every framing/gap packet counted.
- Search time: 32.223 seconds on this host; this is not an Apple M2 benchmark.
- Ordered geometry enumeration is exhaustive at completed budgets marked exhaustive in search_summary.json. Payload synthesis is model guided.
- Higher budgets use declared resource cutoffs. The selected library and greedy bundles are not globally optimal or globally shortest.

| Data packets | Retained programs |
|---:|---:|
| 1 | 6 |
| 2 | 118 |
| 3 | 527 |
| 4 | 205 |
| 5 | 81 |
| 6 | 63 |

## Binary fingerprint bundles

| Bundle | Connections | Data packets | Predicted vectors | Separated pairs | Nominal repeated-control packets |
|---|---:|---:|---:|---:|---:|
| PDF page 4: the two-connection reference | 2 | 6 | 4 | 6/6 | 126 |
| Small suite for four illustrative overlap choices | 2 | 5 | 4 | 6/6 | 117 |
| Greedy suite across declared reference hypotheses | 6 | 14 | 17 | 187/190 | 342 |
| Default TTL / valid-checksum suite | 5 | 11 | 10 | 177/190 | 279 |
| Four policies with no individual packet carrying the full target hostname | 2 | 5 | 4 | 6/6 | 117 |

## Interpretation

- The four-policy page-4 pair reproduces first=10, last=01, lower-start=11, higher-start=00 when read in A,B order.
- Real observations are null. A predicted bit is not a measured DPI result or a proven implementation identity.
- 19 descriptive geometry fixtures are represented. Exact Dharmapurikar–Paxson Figure 4 A–T mapping remains unverified; no audited 20/20 coverage claim.
- h=4 assumes a three-packet ordinary handshake plus a genuine-state client RST. Nominal cost includes three trial types and three repetitions.
- Actual execution totals additionally require measured calibration, retransmissions/injected traffic and waits. Those fields remain null.
- Server silence, ordinary resets, ICMP expiry and local timeouts do not by themselves establish censorship.

## Files

Open index.html. It contains all result data and works without a local web server or external assets. Figures and machine tables are included alongside it.
