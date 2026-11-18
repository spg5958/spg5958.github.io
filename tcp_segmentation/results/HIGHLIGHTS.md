# Example two-connection packet bundle

Programs S0296 and S0987 use five application-data packets across two fresh TCP connections. They are packet plans with unmeasured real outcomes.

The record is 103 bytes and its hostname interval is [63,79). T is `abcdefgh.example`; B is `abcdxygh.example`. Framing is identical in both templates.

| Program | Ordered data slices |
|---|---|
| S0296 | [65,69) from T; [0,103) from B |
| S0987 | [63,79) from B; [65,103) from T; [0,67) from T |

All data packets in this bundle use the server-expiring TTL class with valid TCP checksums. No individual packet contains the complete target hostname. Every framing byte and completion slice is included in the count.

At h=4 the nominal cost is 5+4*2=13 packets for the two mixed trials. Including both companion controls and three repetitions gives 18 planned connections and 117 nominal packets. Calibration, actual wire traffic and observation waits remain unmeasured.
