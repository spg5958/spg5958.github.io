# Extracted requirements from the supplied handshake PDF

Source: `upload/dmap_tcp_handshake_algorithm (1)(1).pdf` (7 pages). Text extracted and pages 2–6 rendered and visually inspected. This document records the PDF's requirements, not measured network results.

## Measurement contract (page 2)

The sole empirical fingerprint variable is a binary censorship signal: `Y(p)=1` if a calibrated policy-dependent censorship action occurs; otherwise `Y(p)=0` in a valid, evaluable observation interval. It does not reveal DPI TCP state, reconstructed hostname, or server application output.

Each candidate must specify these four matched conditions:

| History | Request | Purpose |
|---|---|---|
| Ordinary reference history | Benign SNI | Negative baseline |
| Ordinary reference history | Blocked SNI | Positive calibration |
| Candidate history | Benign SNI | Rule out effects unrelated to the name |
| Candidate history | Blocked SNI | Candidate fingerprint bit |

Use one fixed, valid TLS ClientHello framing and fixed TCP segmentation. Hostnames should preferably have equal length so TLS lengths can remain equal. HTTP Host is optional and needs separate calibration. Match visibility, timing and request framing across relevant conditions. Repeat trials. Calibration failure, uncertain delivery and inconclusive trials are quality/exclusion metadata, **not a third bit value**. Offline outputs must leave `Y` unmeasured/null.

A TTL-limited readout reaches no Linux TLS endpoint, so a missing response alone is not an interpretable bit. It requires an independently attributable censorship side effect or separately validated follow-up effect. Ordinary TCP resets, ICMP Time Exceeded, checksum rejection and local timeouts do not themselves count as censorship.

## Visibility, validation and knowledge (page 3)

Attach delivery and TCP checksum attributes to every packet. Keep DPI arrival, Linux IP arrival, accepted Linux TCP effect and unknown DPI processing separate.

| Delivery | TCP checksum | Reference Linux behavior |
|---|---|---|
| Full | Valid | Run relevant modeled Linux TCP rules |
| Full | Invalid | No accepted TCP effect or TCP reply |
| DPI-only | Valid | No Linux arrival, TCP effect or reply |
| DPI-only | Invalid | No Linux arrival, TCP effect or reply |

All four visibility/checksum combinations are explicit PDF inputs. The IP header checksum remains valid. TTL numbers alone do not prove DPI visibility or Linux exclusion; these are calibrated delivery assumptions. Checksum rejection presumes the checksum remains invalid on arrival (offload artifacts and device repair invalidate that assumption).

Server ISN colors denote opaque identities, not a publicly guessable two-value space. Knowledge guards must prohibit server-relative packet values until the particular ISN is observed. In particular, a DPI-only SYN cannot teach a Linux ISN because Linux never emitted a response. Only genuine Linux events may generate server packets. Preserve causal wire/observation order and retain old identities while state/queued traffic can reference them.

## Goals and labels (page 4)

`f` = network four-tuple; `iota` = incarnation with client/server ISN identities.

1. `EST(f,iota)`.
2. Establish `EST(f,iota0)`, leave it, then establish `EST(f,iota1)` on the **same** four-tuple with a different incarnation.
3. Establish `EST(f0,iota0)`, leave it, then establish on a **different** four-tuple `f1`.

Leaving ESTABLISHED must preserve closing/TIME_WAIT state, outstanding packets and retained knowledge. Endpoint-invisible actions may change a candidate history while keeping the Linux marking unchanged.

Decision families:

- Allocation/validation: allocation after SYN, partial/full handshake or first data; detailed/simplified validation.
- Update/termination: use/ignore controls; forget on early close, completed close, reset or timeout.
- Incarnation/flow identity: replace/retain/combine old state; separate/shared flow state.
- Visibility/checksum: use traffic absent at Linux; validate/ignore checksum errors.

A decision label contains **phase, control meaning, sequence/ACK relationship, incarnation relationship, delivery class and checksum class**. A new raw flag pattern is not by itself a new semantic decision.

Prefix records retain Linux marking, pending wire events, attacker knowledge, lifecycle/reference automaton progress, exercised decisions, complete ordered history, packet count and elapsed explicit time.

## Cost (page 5)

`C(tau) = N(tau) + A(tau) + 2*W(tau) + kappa*T(tau)`, with `kappa>0`.

- `N`: every transmitted packet, including generated Linux replies, readout and cleanup.
- `A`: attacker actions departing from ordinary progress toward the chosen lifecycle goal.
- `W`: those departures adding no new designated decision within the current prefix.
- `T`: explicit waiting in fixed units.

One attacker packet with no response costs 1 when ordinary, 2 for a new-decision departure, and 4 for a repeated-decision departure. Linux replies add `N` only. Both DPI-only and checksum-invalid actions can test new decisions. Define ordinary behavior with a small frozen reference automaton allowing setup, teardown and reconnect variants.

Enumerate bounded **walks of complete prefixes**. Do not retain only a cheapest path per Linux marking and do not use `visited[Linux_marking]`. Different histories can matter to an unknown DPI despite reconverging at Linux. Bound packets, elapsed time, incarnations and expansions. Initially use two incarnations. Keep several candidates per goal and decision family. Any representative quota is an approximation, not a semantic-equivalence proof.

## Enumeration (page 6)

Use a min-priority queue of complete prefixes at accumulated weighted cost. For each popped prefix within bounds:

1. At a requested Linux checkpoint, append a costed SNI readout and cleanup **to a separate copy/replay**, then retain if the entire completed measurement fits bounds.
2. Continue expanding the original prefix, allowing close/reconnect after first establishment.
3. Enumerate knowledge-permitted attacker actions and causally ordered successors.
4. Set `new_labels = decisions(prefix, action, successor) - exercised`.
5. Set `a=0` for ordinary progress else 1; `w=1` only if `a=1` and `new_labels` is empty.
6. `delta = new_wire_packets + a + 2*w + kappa*explicit_wait_units`.
7. Carry the union of prior/new decisions and push the full successor prefix.

Readout must include/reserve genuine replies, cleanup and waits **before bounds are applied**. It must never be fed back into the continued search prefix. First/second-establishment measurements are separate replays and their execution costs must reflect that.

The reference history precedes censorship interference. Do not invent continued successful Linux exchanges after a possible observed censorship intervention.

## Suite selection (page 7)

Empirical pair separation is undefined until repeated valid reference-profile outcomes exist. With data, greedily choose `newly separated reference pairs / execution cost`; include candidate traffic, responses, controls, repetitions, checkpoint replays, cleanup and waits. Reserve exploration for decision families not covered by currently known reference profiles.

Offline bundles can be selected for semantic diversity and estimated cost, but must not claim measured information gain, pair separation or successful fingerprinting. Keep the segmentation companion separate.

## Missing numeric configuration and implementation choices

- **The PDF supplies no numeric pilot configuration** beyond initially using two incarnations and positive `kappa`.
- Numeric packet/time/expansion/memory/quota bounds, wait-unit duration, `kappa`, repetition count, observation interval, TTL calibration and cleanup policy must therefore come from the requested Markdown specification or be declared substitutions.
- The requested `TCP_lifecycle_measurement_prompt.md` is not among the visible three attached files at inspection time. Its alleged pilot cannot be recovered from this PDF. Do not claim a substituted pilot matches that absent specification.
- The PDF mentions invalid checksum inputs explicitly even though the attached prior model's filename is `tcp_no_checksum_1000`. Restoring them is justified by the new specification, with rejection as an explicit modeled no-effect case.
- The PDF does not prescribe simultaneous-open implementation, timer numeric values, actual Linux kernel version/configuration, exact server close policy, real SNI hostnames, observed DPI profiles or actual outcomes. State chosen abstractions and limitations.
- The PDF gives no permission or requirement to send packets. This project phase is offline candidate generation only.
