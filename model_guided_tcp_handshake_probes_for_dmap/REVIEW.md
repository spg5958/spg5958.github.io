# Independent verification of the CPN-first revision

The delivered sequence set was checked using an independent XML reader and literal-token firing implementation in `verify_revision.py`. This verifier does not import `cpn_runtime.py` or the earlier Python endpoint oracle. It reconstructs input/output multisets, evaluates the supported integer place guards, and fires every delivered plan and control sequence directly from the saved PNPRO.

## Verified result

- The source CPN contains 75 places, 671 uniquely named transitions, and 5,807 arcs. Its attacker/server ISN domains are `{red,blue}` and `{pink,purple}`.
- The CPN SHA-256 before and after search is `e4e546401ac27845eea374d68340b751c4e389f8989ac46e18405495e5c259b1`.
- All 1,000 plans have distinct physical packet words after ignoring handler-only differences and wait placement. Header symbols, sender, flow/incarnation, delivery, checksum, and readout payload are included in this identity. These complete experiments contain 601 distinct pre-readout packet histories; some complete plans share a history and differ by readout delivery or cleanup order.
- All 4,000 ordinary/candidate and benign/blocked conditions have replayable CPN transition sequences and null censorship outcomes.
- Independent replay fired 48,902 literal CPN transitions across plans and conditions. Input/output tokens, phase conservation, forced-response serialization, server-ISN knowledge, checkpoints, and complete cleanup matched the records.
- Independent accounting reproduced every `N`, `A`, `W`, `T`, and `C=N+A+2W+T` value. Recorded costs range from 5 to 13. All controls match their candidate's readout delivery and wait-unit totals. Condition histories display 21 distinct cost profiles.
- Goal coverage is 334 first-establishment plans, 333 same-four-tuple reconnection plans, and 333 different-four-tuple reconnection plans.

Machine-readable details are in `results/verification.json`.

## Search implementation review

The revised `greatspn_paths.py` retains the supplied `SequenceSearchSession` implementation and adds a contextual edge-cost callback plus corresponding checkpoint fields and consistency checks. It is actually invoked by `search_cpn.py`. Successor markings come from the already-written PNPRO's arcs and guards; the search does not call the previous endpoint simulator or export a reachability graph as its source model.

The priority uses a consistent remaining-cost potential computed by reverse Dijkstra on a relaxation of the same CPN. Relaxing history bounds and the `A/W` penalties yields a lower bound `h` using remaining packet/wait cost. The supplied prefix engine receives reweighted edges `delta_C+h(child)-h(parent)`. They are checked nonnegative, and completed plans have `h=0`, preserving complete-cost order within each fixed goal query. Cross-goal targets are chosen for lifecycle coverage; the union is not advertised as the globally cheapest 1,000 plans across all goals.

A separate synthetic fixture exercises the actual modified search class with the same probe transition repeated. Its first departure costs 2 and its repetition costs 4; complete solution costs are 1, 3, and 7. This checks that repeated-decision penalties are contextual rather than cached as a fixed transition-name weight.

The 1,000-path target is a count of unique packet sequences. CPN firing words that differ only by internal handling or wait placement do not manufacture extra results. Both full and DPI-only readouts can remain distinct experiments because their packet projections differ.

## Protocol fixtures

Fourteen independent token fixtures cover full/invalid and DPI-only SYN rejection, inability to acknowledge an unknown server ISN, learning only after genuine SYN-ACK observation, settled establishment, DPI-only readout without a Linux data effect or reply, mandatory full-readout ACK, valid in-window ACK progress in FIN_WAIT1/CLOSING/LAST_ACK, ordinary passive close without waiting, exact versus nonexact RST handling, retained prior-incarnation knowledge, and the global two-incarnation bound.

During review, model authors corrected an endpoint data-token change on a DPI-only readout, missing ACK-driven progress in closing states, a duplicate native transition name, a duplicate-SYN response inconsistency, and the displayed server FIN sequence offset. The final fixtures above run against the corrected saved CPN and hash.

## Practical limits

This is an offline feasibility and accounting check of the stated symbolic profile. Native GreatSPN parser/simulator execution was unavailable; the local reader supports the explicit literal-color, integer-guard PNPRO subset used by this model. XML token replay does not independently establish complete Linux implementation fidelity or exact native editor compatibility.

The model remains a conservative configured abstraction: passive server, fresh disjoint ISN windows, at most two incarnations, serialized genuine replies, protected TIME_WAIT reset handling, abstract waits, and no option/PAWS/SACK/backlog or arbitrary reassembly analysis. Model omissions are listed in `model/annotations.json`. The generated paths do not establish how any real DPI behaves, how informative a bundle is, or how an empirical censorship bit would evaluate.
