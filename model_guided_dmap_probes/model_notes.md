# Endpoint model and Petri net interpretation

`endpoint.py` is an offline symbolic reference profile. It does not invoke Linux,
access a network, instantiate a DPI, or generate measurement transmission code.
The independent artifact `tcp_lifecycle.PNPRO` is generated from this exact oracle
by `model_export.py` and encodes a bounded finite endpoint transition graph.

## Identity, state, and observation

There are two network four-tuple names, `f0` and `f1`, and at most two genuine
incarnations globally. The first genuine accepted SYN selects server identity
`pink`, the second `purple`. These are opaque symbolic identities, never guesses
from a two-element numeric keyspace. Real incarnations use the attacker identities
`red` and `blue` without replacement. Their modeled receive windows are disjoint;
the model does not claim that two arbitrary numeric ISNs always have disjoint
windows. The pilot search fixes red/pink first and blue/purple second as a symmetry
representative. Additional colors are not used.

Knowledge is retained as `(four_tuple, generation, server_identity)` records.
Only observing a genuine server reply with the server's own sequence number
adds knowledge. An ACK rejected by a listener can produce a reset echoing the
attacker's ACK, which does not reveal a chosen server ISN. A DPI-only SYN and a
checksum-rejected SYN produce no server reply and reveal nothing. Relation-based
ACK construction requires knowledge of the current incarnation. Old references
require previously retained knowledge. Deferred server replies are already
transmitted and counted; `deliver_pending` is an observation, not another send.
At most one such observation is pending. This pilot does not enumerate arbitrary
network queues, delays of attacker-to-server delivery, or arbitrary reorderings.

Retired incarnations retain their full endpoint record, even after close/reset.
A different four-tuple does not erase another flow's closing or TIME_WAIT state.
Pending observations survive closing and can refer to an old generation.

## Conservative endpoint profile

The reference automaton includes LISTEN, SYN_RECV, ESTABLISHED, CLOSE_WAIT,
LAST_ACK, FIN_WAIT1, FIN_WAIT2, CLOSING, and TIME_WAIT. A permanent passive listener
remains available after child close/reset. Server application close is an explicit
reference-environment trigger; attackers do not directly choose server wire
responses. Forced server replies are counted and causally ordered.

- `TCP_DEFER_ACCEPT` is disabled. This changes the attached old model's enabled
  defer-accept configuration. A valid pure third handshake ACK can establish.
- Exact receive-next reset acceptance, in-window challenge ACKs, out-of-window
  silent reset rejection, and the after-FIN receive-next-minus-one reset exception
  are represented. Challenge-ACK rate limits and SACK exceptions are omitted.
- Invalid/future ACKs do not acknowledge server FIN or accept accompanying data.
  An established future ACK is silently discarded in this profile; closing states
  can emit a challenge ACK. Request ACK failure generates a listener/request reset.
- Correct ACK with a valid in-window sequence can establish from SYN_RECV.
  Ahead FIN/data does not get consumed at the endpoint checkpoint.
- The in-window representative is `RCV.NXT+32768`, with a receive window exceeding
  that offset, and a fixed readout shorter than 32768 bytes. No admitted history
  fills the ahead gap. Real Linux can retain out-of-order traffic; inference
  beyond the bounded unfilled-gap regime is excluded.
- TIME_WAIT requires explicit expiry before a new connection on the same tuple.
  Eligible Linux early reuse by a newer sequence/timestamp is intentionally omitted.
  TIME_WAIT reset handling uses the protected (`tcp_rfc1337=1`) profile.
- Explicit waiting is in abstract units, not seconds. One unit includes expiration
  of a complete modeled TIME_WAIT interval. Physical duration and sufficient
  runtime quiet intervals remain uncalibrated. Waiting while a request remains
  SYN_RECV is excluded, avoiding unmodeled SYN-ACK retransmissions. Request
  retransmission/expiry search is therefore outside this pilot.
- Each fixed ClientHello occupies symbolic sequence length `L_readout`, not one
  TCP byte. Displayed ACK/SEQ expressions preserve this term. No TLS application
  response is simulated; the reference peer emits a TCP ACK for accepted readout.
- The model assumes valid IP header checksums and a calibrated full versus
  DPI-only visibility regime. TCP-invalid packets stay invalid to the endpoint;
  transformations by an inline device are outside this profile.
- No packet loss, PAWS, SACK/options, fragmentation, segmentation search, TCP fast
  open, SYN cookies/backlog pressure, server-initiated SYN, congestion control,
  application stream reconstruction, or calibrated censorship signal is modeled.

These choices support bounded reference feasibility within this profile. They are
not a claim of implementation equivalence to the current Linux kernel.

## Executable colored Petri net

A single `CState` token represents the complete endpoint marking, including both
flow records, knowledge, retired records, pending observation, and explicit wait
progress. Ten additional live projection places expose each flow's TCP phase,
attacker/server ISN, attacker knowledge, retained old identities, and pending
unobserved server identity. The ISN color classes are exactly `{red,blue}` and
`{pink,purple}`. Projection places are enforced by actual input/output arcs.

Each action is expanded into its ordered events. Packet transitions have prefix
`PACKET_SEND_ATTACKER_` or `PACKET_SEND_SERVER_`; each counts one packet. Intermediate
encoded tokens force mandatory genuine replies before another macro-action can
start. Wait and observation transitions are separate and have no packet cost.
The full weighted objective includes prefix-dependent decision coverage and is
applied by the offline search, rather than encoded as static Petri firing rates.

All generated plan and control traces can seed the exporter, after which bounded
breadth-first exploration extends their reachable endpoint subgraph. The CPN map
and export summary record its exact scope, states, edges, and whether a frontier
remains. This is a genuine executable finite colored net, not a drawing-only set
of per-path pages, but it is a bounded endpoint encoding rather than a compact
manual factorization of the entire Linux TCP stack. Large native nets are best
understood with the supplied structural overview and decoded JSON map. XML,
node uniqueness, arc endpoints, and ordered packet counts are verified locally;
opening/simulating it in native GreatSPN requires that unavailable runtime.
