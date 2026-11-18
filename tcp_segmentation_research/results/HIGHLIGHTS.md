# A compact computed fingerprint suite

This is an offline prediction under four explicitly defined overlap hypotheses, not a real DPI measurement. All data packets below use calibrated server-expiring TTLs and valid TCP checksums. Each trial starts with a fresh genuine three-packet handshake and ends with cleanup using the actual Linux frontier.

The serialized TLS record is 103 bytes. Its 16-byte SNI is at [63,79). T is `abcdefgh.example`; B is `abcdxygh.example`. Bytes outside the hostname are identical.

| Trial | Data packet order | Predicted first | Predicted last | Predicted lower start | Predicted higher start |
|---|---|---:|---:|---:|---:|
| S0296 | [65,69) from T; [0,103) from B | 1 | 0 | 0 | 1 |
| S0987 | [63,79) from B; [65,103) from T; [0,67) from T | 0 | 1 | 0 | 1 |
| Fingerprint in this trial order | One binary readout per fresh connection | **10** | **01** | **00** | **11** |

S0296 first buffers `cdef`, then fills the whole record with the benign template. The first-arrival and higher-start hypotheses retain the target's conflicting letters. The last-arrival and lower-start hypotheses use the benign letters.

S0987 reverses the relationship between arrival order and segment-start preference. Its leading framing gap closes last. Together, the two trials separate all six pairs among these four hypotheses. No individual segment contains the full target hostname.

There are five data packets across two test connections. At h=4, C=5+4*2=13 nominal packets, compared with 14 for the supplied page-4 example. Including both matched controls and three repetitions gives 18 planned connections and 117 nominal packets for the compact suite, versus 126 for that example. Calibration, injected traffic, retransmissions and detector waits remain unmeasured.

This is a useful candidate found by a bounded search, not a proof of global minimum. Other DPI parsers, overlap rejection, ACK dependence, and detector behavior can produce different outcomes. The browser's broader suite separates 17 predicted equivalence classes among 20 declared hypotheses; three model pairs remain unresolved in the selected library.
