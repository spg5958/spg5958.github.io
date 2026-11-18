# Supplied baseline audit

## Inputs and availability

Inspected the attached `greatspn_paths(1).py` (version `11.0-packet-figures`) and every ZIP member name. The ZIP was safely extracted after rejecting path traversal and symlinks into `baseline/tcp_no_checksum_1000/`. It has 2,018 entries and 448,313,711 uncompressed bytes.

`TCP_lifecycle_measurement_prompt.md` is absent from the available attachments and from this ZIP. No pilot configuration for the requested lifecycle extension is supplied by these files. The old `search_policy.json` and old search limits describe the establishment experiment only, and cannot be described as the new task's documented pilot.

## Executable source nets

| File | Page | Places | Transitions | Arcs | Packet-send transitions |
|---|---|---:|---:|---:|---:|
| `tcp_no_checksum.PNPRO` | `CPN` | 49 | 195 | 1,412 | 56 |
| `tcp_no_checksum_listening.PNPRO` | `CPN` | 49 | 191 | 1,380 | 53 |

Both XML files parse and have no dangling arc endpoints. The other PNPRO files represent result graphs or witness visualizations; the two files above are the source CPNs. Native GreatSPN GUI loading/firing was not validated by the previous experiment and has not been run during this audit.

Both initialize:

```
A_IRS_ATTACKER=<red>
R_ISS_SERVER=<blue>
A_READY_ATTACKER=1
TCP_DEFER_ACCEPT_SERVER=1
DEFER_CONFIG_SERVER=1
RL_EMPTY_NETWORK=1
sk_listener_SERVER=1
TCP_LISTEN_SERVER=1
```

Their exact scalar classes are:

```
L_ISN={red, orange, gold}
R_ISN={blue, teal, purple}
TCP_FLAGS={TCP_NONE,TCP_R,TCP_F,TCP_FR,TCP_A,TCP_AR,TCP_AF,TCP_AFR,
           TCP_S,TCP_SR,TCP_SF,TCP_SFR,TCP_SA,TCP_SAR,TCP_SAF,TCP_SAFR}
SEQ_LEN={OOW_MINUS_ANY,LEFT38_GET37,LEFT37_GET37,LEFT36_GET37,
         IRS_MINUS1_EMPTY,LEFT_OVERLAP_GET37,IRS_EMPTY,IRS_GET37,
         RCV_NXT_EMPTY,RCV_NXT_GET37,IN_WND_EMPTY,IN_WND_GET37,
         RIGHT_EDGE_EMPTY,RIGHT_EDGE_GET37,OOW_PLUS_ANY}
ACK_VALUE={ACK_ZERO,ACK_2000,ACK_ISS,ACK_ISS1,ACK_FUTURE,ACK_ISS2,ACK_OLD_FAR}
```

Product classes: `PAIR=L_ISN*R_ISN`, `RESET_VALUE=R_ISN*ACK_VALUE`, `RESET_END=L_ISN*SEQ_LEN`. Variables: `IRS:L_ISN`, `ISS:R_ISN`, `SEG_ACK:ACK_VALUE`, `SEG_CTL:TCP_FLAGS`, `SEG_SPAN:SEQ_LEN`.

These are old colors: changing attacker to `{red,blue}` and server to `{pink,purple}` requires disjoint consistent renaming in declarations, initial markings, arc inscriptions, guards, and metadata. Existing scalar TCP-state places and global attacker-knowledge place describe a single server connection record. Merely adding a second ISN token would permit incorrect cross-connection bindings. Two concurrent records require connection-indexed state/knowledge/channel resources or duplicated independent record subnets. Sequential reconnects need explicit epoch/record identity and knowledge reset or retained-history semantics.

## Current modeled scope

The full net includes SYN_SENT/SYN_RECV/NEW_SYN_RECV, ESTABLISHED, FIN_WAIT1/2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT, CLOSE; local shutdown, retransmission, timeout and listener restart rules exist. The listening scenario removes exactly `R_stop_listen_SERVER`, two `PACKET_SEND_R_active_open_*_SERVER` rules, and `PACKET_SEND_R_retransmit_active_SYN_SERVER`. Thus full model includes active/simultaneous open support; listening search deliberately excludes it.

All represented packets assume valid TCP checksums. Network loss is disabled; invalid SEQ/ACK/flags/state may still reject packets. One packet per direction is retained. Attacker ISS-derived ACK selection is gated by receipt of a revealing server reply. Payload abstraction is 0/37-byte before establishment and control-only continuation. No TTL-limited branch, DPI observer, multi-probe measurement composition, control/test domain substitution, or real DPI outcome is modeled in the supplied net.

Exclusions stated in the supplied MODEL_README: IPsec/xfrm; options/timestamps/PAWS; ECN/congestion; authentication; MPTCP/TFO/cookies; resource/backlog failures; sequence wraparound; calibrated timers; ACK rate limiting; arbitrary stream reassembly and future-FIN gap filling. Retain or explicitly report changes to these exclusions.

The latest result endpoint is stronger than `TCP_ESTABLISHED=1`: POST_EST_SERVER=0, P_LR_NETWORK=0, A_READY_ATTACKER=1, sk_socket_SERVER=1, sk_listener_SERVER=1, RL_EMPTY_NETWORK=1, all R_MAKE_* and all server-response banks empty. This excludes transient establishment followed by mandatory FIN processing to CLOSE_WAIT. The old result has 1,000 packet-family words of cost 3–6; 8,921 further equal-cost words at the cutoff were omitted. These establish old search behavior only.

## Search code reuse

The code contains a resumable Dijkstra prefix search, exact native GreatSPN binding adapters via JPype/Editor JARs, bounded native successor cache, model/query/engine fingerprints, a compressed frontier checkpoint, correlated colored variant reports, and SVG packet exchange/tree exporters. It does not produce an HTML results browser. HTML output is a new required deliverable.

`SequenceSearchSession._weight` enforces nonnegative integer transition costs; `PathCostPolicy` exposes packet/firing metrics and the packet prefix rule `PACKET_SEND_` => 1, other transitions => 0. The objective is `(packet cost, firing length)`; distinctness defaults to the complete ordered transition-name sequence, whereas the bundled old result used packet-family words with correlated variants. Decimal PDF weights can be represented exactly with scaled integers and a documented common denominator, but the new cost depends on reconnection/session/probe context and must not be silently substituted by packet count.

Default old limits: k=1000, max_expansions=500000, max_queue=1000000, seconds=60, cache_states=10000, Java heap 2g. These are not a lifecycle pilot. The CLI supports image export from grouped JSON without Java. Reusing its SVG styling is useful; using the native adapter requires GreatSPN Editor JARs and JPype. The baseline previous run explicitly reports `native_GreatSPN_executed=false` and independent XML replay instead.

## PNPRO XML schema useful for new export

```
<project name="..." version="121">
  <gspn name="CPN" zoom="75" view-rates="false" show-timed-cmd="false">
    <nodes>
      <place name="..." x="5" y="15" domain="L_ISN" marking="&lt;red&gt;"/>
      <transition name="..." x="30" y="16" type="IMM" guard="..."/>
      <color-class name="L_ISN" x="3" y="600" definition="{red,blue}"/>
      <color-var name="IRS" x="3" y="685" domain="L_ISN"/>
    </nodes>
    <edges>
      <arc kind="INPUT" tail="PLACE" head="TRANSITION" mult="&lt;IRS&gt;"/>
      <arc kind="OUTPUT" tail="TRANSITION" head="PLACE" mult="&lt;IRS&gt;"/>
    </edges>
  </gspn>
</project>
```

Ordinary arcs omit `mult` for multiplicity 1; ordinary empty places omit `marking`; ordinary places omit `domain`. Guards reference ordinary token counts as `#PLACE` and use `&&`, `||`, `==`, `!=`, comparisons, and parentheses, XML-escaped by an XML writer. Every arc endpoint references a unique declared node name.

## Recommended extension integrity checks

- Keep every plan's per-connection color pair and epoch explicit; never borrow server ISN knowledge across records accidentally.
- TTL-only delivery must leave the server record and server-observation knowledge unchanged; model a visibility event rather than an invented DPI response.
- Ensure final packets and required responses are processed before accepting a lifecycle milestone.
- Validate weighted costs by independent summation, including every mandatory server reply under the chosen PDF interpretation.
- Declare whether abstract local application close and TIME_WAIT expiration are controllable assumptions or calibrated network events.
- Preserve discovery path versus control/test/bundle composition as separate metadata, with all DPI outcomes null/unmeasured.
- Do not claim exhaustive Linux TCP coverage or globally optimal measurement plans after bounds, candidate grammar constraints, or diversity selection.
