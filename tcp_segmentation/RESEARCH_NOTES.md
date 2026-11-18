# TCP segmentation research notes

The delivered 1,000 packet programs and their IDs are preserved from the earlier bounded generation run. This revision updates the code, exported schema and presentation without changing packet payloads or schedules. The generation record in `search_summary.json` identifies the original run; the revised code uses structural coverage for future selections.

## Generation

Serialize a complete TLS 1.2 ClientHello first. Derive SNI offsets from the nested TLS structure. Every interval uses a slice of either the target or benign template; templates have equal hostname lengths and identical framing. The reserved example hostnames stand for a future calibrated target/control pair.

Construct ordered interval histories with reversible backtracking. Defaults permit six data packets and two simultaneous geometric holes. A hole has received data beyond it; the unbounded future suffix does not count. Count every framing packet, duplicate, gap fill and completion packet. Keep different packet histories distinct even when their final interval union agrees.

The generator's finite payload profile uses alternating and single-template-flip patterns, at most 2+2*k patterns for k packets before duplicate suppression. This is not exhaustive enumeration of all byte assignments. Candidate retention and new bundle construction use structural features and nominal execution cost.

Node, geometry and time caps are explicit. Exhaustive geometry claims apply only to completed budgets and the declared search endpoint set. Larger budgets in the delivered original run were capped. Nineteen descriptive local fixtures are represented; the exact Dharmapurikar-Paxson Figure 4 A-T correspondence remains unverified.

## Transport and measurement procedure

Start each trial with an ordinary genuine TCP handshake, learn actual ISNs and bind each sequence offset to CLIENT_ISN+1+start. Confirm the receive window, negotiated MSS and path payload bound. This profile requires the serialized record to fit the supplied packet payload bound; it does not hide extra packet splitting.

In the default family, every ClientHello data packet reaches the DPI observation point and expires before Linux. Separate families use full-TTL invalid TCP checksums, or combine server-expiring TTLs and invalid checksums. Verify intended checksum values on wire and exclude repair/normalization when relying on checksum rejection.

Send the data schedule without waiting for nonexistent server data ACKs. Cleanup uses Linux's actual receive frontier, which has not advanced over these application bytes. The absent TLS response, ICMP expiry, ordinary resets and local timeouts are not by themselves censorship evidence. A real readout requires an independently calibrated policy-action detector and a stated observation interval.

Run each mixed test with same-geometry all-target and all-benign companion trials on fresh connections. Preserve visibility and checksum classes. Use separate ordinary visibility baselines to establish the route and detector. Failed calibration is quality metadata; keep real observation fields empty until an evaluable measurement is performed.

## Cost

C = N_data + h*N_connections. Default h=4 represents three handshake packets and one genuine-state client RST. Three trial types and three repetitions yield nine planned connections per individual program. Nominal execution packets are 9*(N_data+4); bundle costs sum their programs. Actual calibration packets, injected traffic, retransmissions and waits remain unmeasured.

## Sources

The supplied specification is included in `source/segmentation_specification.pdf`.

- dMAP: https://diwenx.com/assets/files/dmap.pdf
- Dharmapurikar and Paxson, Figure 4: https://www.usenix.org/legacy/event/sec05/tech/full_papers/dharmapurikar/dharmapurikar.pdf
- Knuth, Basic backtrack: https://www.informit.com/articles/article.aspx?p=3150366&seqNum=5
- TLS SNI: https://www.rfc-editor.org/rfc/rfc6066.html
- TCP: https://www.rfc-editor.org/rfc/rfc9293.html
