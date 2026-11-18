# Independent semantic review

## Scope and source status

The attached PDF defines generation and observation requirements, rather than a complete executable Linux specification. The offline endpoint must be described as a conservative, Linux-inspired symbolic profile. It is not a version-complete clone of the current Linux TCP implementation. Browser retrieval of the exact `v6.12` source paths failed. Official upstream `master` sources were inspectable/indexed, and RFC 9293 was readable. In particular, request-socket reset validation changed during 2026; claiming exact initial Linux 6.12 semantics would be misleading.

Primary sources inspected:

- Linux upstream TCP receive and synchronized validation: https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_input.c (`tcp_validate_incoming`, `tcp_ack`, `tcp_reset_check`).
- Linux upstream request sockets and TIME_WAIT: https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_minisocks.c (`tcp_check_req`, `tcp_timewait_state_process`).
- TCP specification: https://www.rfc-editor.org/rfc/rfc9293.html (checksum, reset processing, synchronized-state checks).

## Semantics to preserve

1. DPI-only delivery means no Linux IP-layer arrival. Invalid TCP checksum means IP arrival but no Linux TCP acceptance. Neither can generate a genuine Linux TCP response or reveal a newly selected server ISN.
2. In synchronized states, an exact `RCV.NXT` RST resets. A non-exact in-window RST generally challenges; an out-of-window RST is silently dropped. Challenge ACKs are rate-limited in Linux: generating every challenge reply assumes a permissive/rearmed rate-limit profile and must be documented.
3. Linux also accepts `RCV.NXT-1` RST after a FIN in CLOSE_WAIT, LAST_ACK, and CLOSING. A symbolic `previous` category can represent this exception. SACK's rightmost acknowledged block is another reset-acceptance exception; omit SACK only explicitly.
4. For a passive request socket, invalid ACK normally returns handling to the listener, which can send a reset. Current upstream request handling challenges non-exact in-window RST. This behavior must not be retroactively assumed for all kernel versions.
5. A SYN_RECV ACK with valid sequence/acknowledgment and FIN can move through establishment into CLOSE_WAIT in processing one incoming segment. A goal requiring a settled ESTABLISHED checkpoint cannot count the transient intermediate state as the final checkpoint.
6. Future ACKs cannot be treated as ordinary progress. Behind ACKs distinguish acceptable older acknowledgment from far-old validation failures; a single coarse `behind` category must define its range.
7. Same-four-tuple reconnection must preserve closing/TIME_WAIT records. TIME_WAIT does not universally forbid early reuse: Linux can pass an eligible new SYN to the listener if its sequence is newer (or accepted newer timestamp). A profile that only permits reconnect after explicit TIME_WAIT expiry is conservative and incomplete, and should say so.
8. TIME_WAIT RST assassination depends on `tcp_rfc1337`; an abstraction preserving TIME_WAIT on all RSTs must freeze and disclose that choice.
9. Readout and cleanup events must be projected through the endpoint and fully costed. Readout bytes must not leak back into continued search prefixes; separate establishment checkpoints require separate replays.
10. An ordinary server TCP ACK is not a TLS application response. A readout TTL profile cannot infer Y from absence of either. Every censorship bit remains null/unmeasured in this offline run.
11. Server ISN colors are opaque identities. Selection from two colors must not give an attacker knowledge. Saved references to prior incarnations must remain available and be distinguishable from a guessed current server color.
12. Retain pending reply observations across teardown/reconnection. Counting transmission and later observation as two packet sends would overcount N.

## Search/measurement requirements checked from PDF

- Cost is C=N+A+2W+kappa*T, including forced endpoint replies, readout, and cleanup. W applies only to departures with no new designated decision in that prefix.
- A complete history is a search object even if its Linux marking equals another prefix. No visited[Linux_marking] pruning is valid for unknown DPI behavior.
- Bounds, quotas, and family prioritization are explicit approximations; report incomplete exploration instead of optimality/exhaustiveness.
- Every plan has ordinary/benign, ordinary/blocked, candidate/benign, candidate/blocked conditions with matched request framing, visibility, and timing, and repeated-trial requirements.
- Calibration failure, uncertain delivery, and inconclusive trials are quality/exclusion metadata, not a third fingerprint bit.
- No empirical pair-separation score or achieved fingerprint accuracy is computable without real reference outcomes. Small bundles are unmeasured candidate sets, not validated fingerprint suites.

## Concrete initial implementation review

Reviewed the first written `tcp_lifecycle/endpoint.py` and communicated these actionable issues before generation:

- Reusing the same attacker color in two incarnations makes unconditional old/new sequence-space disjointness unsound. Restrict pilot allocations to fresh attacker colors, or implement explicit numeric/symbolic overlap cases.
- Do not emit a TIME_WAIT ACK in response to every exact bare ACK; upstream retains/refreshes silently for the exact zero-length case.
- Upstream SYN_RECV permits in-window nonexact final ACK establishment. Exact-only establishment is an omission unless fixed.
- Future ACK replies differ between ESTABLISHED and non-EST closing receive paths.
- The old supplied CPN enables TCP_DEFER_ACCEPT. Immediate bare-ACK establishment in the new profile changes that setting and must be disclosed.
- New finite flag/sequence alphabet is smaller than the baseline's sixteen flag combinations and detailed segment spans. Describe it as an executable pilot abstraction with added lifecycle/visibility composition, rather than a fidelity-preserving automatic transformation.

The model author was asked to make fixes directly. This review document is evidence of issues raised, not by itself a claim that final code has passed validation.

## Recheck after endpoint fixes

The endpoint author corrected and a subsequent source recheck confirmed:

- Real incarnation allocation consumes attacker colors without replacement.
- Future ACK has no forced ESTABLISHED reply; non-established receive states may challenge.
- A valid in-window nonexact final ACK can establish without consuming its ahead FIN.
- Exact bare TIME_WAIT ACK retains the record silently and refreshes its symbolic timer.
- SYN_RECV idle waits are outside the pilot, avoiding uncounted SYN-ACK retransmission/timeout behavior.
- Explicit waits have abstract units and no claim of calibrated physical seconds.

Remaining profile requirements communicated to the root:

- Freeze TIME_WAIT RST handling as RFC1337-protected, and disclose permissive/rearmed challenge-ACK rate limits.
- An ahead in-window FIN/data representative must remain beyond all subsequent accepted readout bytes in its incarnation, because arbitrary out-of-order queue/gap filling is outside this pilot.
- Clean up every remaining old/current flow on copied trial suffixes, or define an equally explicit isolated-trial resource policy; checkpoint-only cleanup undercounts leftover f0 state in different-four-tuple plans.
- Supply serialized fixed ClientHello fixtures/length checks if claiming the PDF's fixed valid TLS framing requirement.

An independent audit of the initial 228 generated plan records found all direct packet counts N and weighted identities C consistent, and every condition Y null. It also identified 344 condition instances with remaining old endpoint state after checkpoint-only cleanup. This was sent to the root before final generation.
