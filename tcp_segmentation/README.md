# TCP segmentation measurement plans

Open `results/index.html`. The browser includes 1,000 packet programs, packet-exchange diagrams, interval tables, measurement bundles, costs and execution instructions. The light/dark toggle remembers your preference. The Back button uses browser history, with `../index.html` as its parent-page fallback.

This revision keeps the existing packet IDs, packet bytes, arrival order, visibility classes, checksum classes and bundle membership. No new search was run to replace the delivered 1,000 programs. The code and exported dataset contain packet plans and unmeasured observation fields.

## Rebuild the browser and tables

Use Python 3 and the standard library:

```bash
python3 validate.py results/results.json
python3 export.py results/results.json
python3 render_results.py results/results.json results/index.html
```

## Generate a new library

```bash
python3 search.py --output new_results --keep 1000 --max-segments 6 --max-holes 2 --overhead 4 --repeats 3
python3 validate.py new_results/results.json
python3 export.py new_results/results.json
python3 render_results.py new_results/results.json new_results/index.html
```

The revised generator uses ordered-interval backtracking and a bounded set of target/benign template assignments. It retains structural diversity across packet families, segment counts, hole counts and overlap geometries. Future generated selections can differ from the preserved library in this package. Selection does not establish a globally smallest suite.

## Data and execution

- `results.json`: complete packet programs, geometry, nominal costs and run requirements.
- `experiments.csv` and `packet_details.csv`: experiment and per-packet tables.
- `bundles.csv`: ordered multi-connection packet programs and their costs.
- `measurement_plan.jsonl`: test, all-target and all-benign trials with observation fields left empty.
- `probe_images/` and `combined.svg`: individual and grouped packet diagrams.
- `validation.json`: independent TLS, payload, geometry and cost checks.

Matched controls remain future measurement procedures. Preserve the same geometry, visibility and checksum schedule when changing the template assignment. All real DPI outcomes remain unmeasured. No network transmission code is included.

See `RESEARCH_NOTES.md` for bounds, cost assumptions and calibration requirements.
