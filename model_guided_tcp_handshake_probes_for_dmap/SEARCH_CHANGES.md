# Search implementation and provenance

The implementation actually invokes `SequenceSearchSession` from the supplied
`greatspn_paths(1).py`. The complete original module is retained as the modified
`greatspn_paths.py`; `greatspn_paths_weighted.patch` records the exact changes.
`search_code_provenance.json` records original and modified SHA-256 hashes.

## CPN is the executable source

`model_builder.py` writes the compositional PNPRO before any search starts.
`cpn_runtime.py` reads its places, literal colored arc inscriptions, and guards.
Only enabled XML transitions produce successors. Annotation metadata attaches
packet observations and cost labels; it does not decide endpoint state changes.
The earlier `endpoint.py` is not imported or executed.

`search_cpn.py` augments actual CPN markings with the decision labels already
exercised, cost counters, replay stage, and finite-history budgets. Those fields
are part of the state key; there is no `visited[Linux_marking]` path collapse.
An accepted result contains the actual CPN readout, forced replies, and cleanup
firings before its terminal condition is checked.

## Weighted Dijkstra with a CPN potential

The generation cost is `C=N+A+2W+T`, with kappa fixed at 1 for this run. `N`
counts every attacker/server packet firing; `A` counts designated attacker
departures; `W` counts departures with an already-exercised semantic label; `T`
counts explicit modeled wait units. No heuristic reward or negative cost is used.

For performance, a finite relaxed graph of `(CPN marking, readout stage)` is
constructed separately for each lifecycle goal. It uses the same CPN firings,
while dropping history budgets and A/W penalties. Reverse Dijkstra computes
the exact minimum remaining `N+T` cost `h`. The supplied prefix engine receives
the reweighted edge `delta_C+h(child)-h(parent)`, which is nonnegative because
`h` is a consistent lower bound and `delta_C >= delta_N+delta_T`.

The total priority telescopes to `C+h(current)-h(initial)`. Every completed
goal has `h=0`, so the engine emits complete results in nondecreasing actual
weighted cost within each fixed goal. The callback records actual C, not the
shifted priority. Runtime assertions check edge nonnegativity and goal ordering.

This is equivalent to uniform-cost search with a consistent goal potential,
or A* using the CPN-derived lower bound. The original Dijkstra-style prefix
session, queue, witnesses, and distinct transition words remain the engine.

## Selection and distinctness

The run requests 334 first-establishment, 333 same-four-tuple reconnection, and
333 different-four-tuple reconnection paths. This balances lifecycle coverage;
it is not a claim that all 1,000 form the globally cheapest set across goals.
There are no quotas by predefined decision family or phase.

Accepted firing words are deduplicated by the complete ordered physical packet
sequence: direction, flags, flow/incarnation, symbolic sequence/ACK values,
delivery/checksum class, and readout payload. Purely internal firing or wait-only
differences do not create additional packet sequences. All 1,000 packet
signatures are distinct. Full-delivery and DPI-only readouts are physically
different packet histories and remain distinct; the metadata permits examining
their common pre-readout histories.

Ordinary control baselines are searched from the same CPN with departures
disabled and no waits, so matched controls can be padded using real `WAIT_IDLE`
firings. Censorship bits and empirical information gain remain unmeasured.

The graph, protocol abstraction, and explicit packet/action/wait/departure
bounds still limit coverage. Native GreatSPN parsing/simulation was not run;
the included PNPRO interpreter and independent token replay validate the
implemented PNPRO subset.
