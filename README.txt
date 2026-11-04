TCP PACKET EXCHANGES — 1,000 SHORTEST COMPLETED CONNECTION PATHS

START HERE
Extract the ZIP and open index.html in your browser. It works offline.
Select a path to see its attacker/server packet exchange. Use the second
image link for every correlated colored branch and its complete details.
No GreatSPN installation is needed to view the results.

IMAGES AND NAVIGATION
  per_path/path_000001.svg ... path_001000.svg
    One representative packet exchange for each ranked packet-family word.
    Large directional arrows run between the attacker and Linux server.
    The top summary gives packet cost, total firings, exact packet/transition
    sequences, complete-variant counts, and initial/final nonzero markings.
    Every exact bound transition and every intermediate nonzero marking is
    visible in the execution appendix below the exchange. Arrow rows order
    transmissions; send/receive firing references resolve any interleaving.

  colored_variants/path_000001.svg ... path_001000.svg
    Complete branch-detail atlases for those same packet words. Each starts
    with a packet-exchange family diagram, then the complete connectivity
    map, every full marking, and every firing with source/target, binding,
    packet cost and direction. Original full marking correlations are kept.
    These images preserve all 47,517 state occurrences and 87,267 firing
    edges represented in the earlier per-path PNPRO results. Long atlases
    are intended for scrolling and vector zooming, not a single paper page.

  all_paths.svg
    Full shared packet-prefix tree with 2,352 nodes and 1,000 ranked words.
    Every packet node contains a miniature attacker/server exchange.
    Green rank labels link to the corresponding detailed exchange image.
    Some accepted words are prefixes of longer words with different valid
    header bindings; such a rank can occur at an internal tree node.

  overview.svg
    Compact prefix-tree overview. It shows every first-packet group and the
    three largest alternative next-packet branches in each group. Additional
    next-packet branches are explicitly indicated rather than silently lost.

  prefix_trees/
    141 smaller exact trees, one per first-two-packet prefix. All selected
    words are included. Use these instead of the very tall full tree for
    smaller figures or convenient browsing on a limited-RAM machine.

  previews/
    PNG previews of the overview and the main exchange panels for paths
    1, 10 and 769. These are convenient publication/slide previews; the
    full SVGs retain the technical appendices and all exact details.

SVG is a scalable, editable vector-image format suitable for export and
publication. All drawing is deterministic from the computed data. No
generative imagery or invented packets are used.

IMPORTANT DISTINCTION BETWEEN THE TWO PER-PATH VIEWS
The simple exchange image selects one exact execution for readability.
Its complete branch atlas retains ALL represented correlated alternatives,
including other legal header bindings and internal processing orders.
The main exchange is not an assertion that every allowed value can be mixed
independently with every other value. Likewise, the combined tree groups
packet families; consult an individual atlas for its header correlations.

OTHER FILES
  packet_sequences.csv: ranks, packet words, symbolic examples and image links.
  packet_details.csv: all 5,444 packets in the representative executions.
  paths.jsonl.summary.json: source-model identity, assumptions and totals.
  search_policy.json: exact endpoint and server-role policy.
  recalculation.json: fresh search and independent replay verification.
  image_validation.json: source-to-image information-preservation checks.

Each SVG also embeds structured source data for reproducibility. The exact
details are visibly rendered as well; they are not available only as metadata.
This delivery contains image results instead of PNPRO visualization projects.
The executable checksum-free TCP model is unchanged from the previous bundle.

RECALCULATION AND SOURCE
A fresh search reproduced the exact ordered 1,000 packet-family words, using
the unchanged uploaded Dijkstra core over exact one-packet macroedges.
Independent enumeration and XML/Counter replay rechecked the same source.
The previously verified complete graphs could therefore be reused to render
all their colored information, without repeating the PNPRO export step.
Distribution: 1 sequence with 3 packets; 25 with 4; 503 with 5; 471 with 6.
The final cost layer has additional equal-cost ties beyond the 1,000 cutoff.

Source CPN: tcp_no_checksum_listening.PNPRO, page CPN.
SHA256: 476caaa8e5242445a2508a0d04bfe728c31c1b73975f362f282053eb3c58c2b5
49 places; 191 transitions; 1,380 arcs; 5 scalar color variables.
Every PACKET_SEND_ firing costs one. Other processing and receipt cost zero.
The complete graphs represent 2,532,656 finite colored firing histories,
grouped into the 1,000 ranked packet-family sequences.

The endpoint requires TCP_ESTABLISHED after packet processing and mandatory
server replies finish, both channels are empty, POST_EST_SERVER=0 and no
R_MAKE_* response request remains. Immediate teardown branches are excluded.
Delivery remains reliable, checksum is abstracted out under the valid-checksum
assumption, the server remains a passive listener, and the attacker learns
server ISS only through a revealing server response. The experiment-aligned
DEFER_CONFIG_SERVER=1 setting and all other finite-model exclusions remain.
These are model-derived results, not 1,000 demonstrated novel TCP mechanisms;
normal handshake variants and redundant valid-checksum probes remain possible.
Native GreatSPN execution was not used; independent XML replay was verified.

LAYOUT RELATION TO THE OTHER CHAT
The retrieved v11 description from "2) Dijkstra Algo For CPN" specifies large
packet arrows, summary above, exact bindings/markings below and a combined
packet-exchange tree. These images follow that description. The actual v11
source ZIP was not available in this conversation, so this is a local renderer
matching that layout rather than execution of the unseen v11 package.

EXTRACTION
This is a standard ZIP. Extract normally, then open index.html.
