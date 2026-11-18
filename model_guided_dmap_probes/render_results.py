"""Self-contained offline results browser and publication-style packet diagrams.

No HTTP client, server, packet transmission, or third-party dependency is used.
"""
from __future__ import annotations

import html
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

INK = '#142d3b'
MUTED = '#587080'
TEAL = '#117f7a'
ORANGE = '#bc681c'
RED = '#b54444'
ARROW_COLORS = ('#275f8a', TEAL, ORANGE, RED)


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def safe_id(value: Any) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value))


def event_data(event: dict) -> dict:
    packet = event.get('packet')
    return {**event, **packet} if isinstance(packet, dict) else event


def event_kind(event: dict) -> str:
    event = event_data(event)
    return str(event.get('kind', 'packet' if event.get('flags') or event.get('actor') else 'internal'))


def wrap(text: Any, length: int = 93, max_lines: int = 3) -> list[str]:
    text = str(text or '')
    words = text.split()
    lines: list[str] = []
    for word in words:
        if not lines or len(lines[-1]) + len(word) + 1 > length:
            lines.append(word)
        else:
            lines[-1] += ' ' + word
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][:max(0, length-3)] + '...'
    return lines or ['']


def text_line(x: int | float, y: int | float, value: Any, size: int = 13, fill: str = INK,
              weight: str = '400', anchor: str = 'start') -> str:
    return f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}">{esc(value)}</text>'


def svg_start(width: int, height: int, title: str) -> list[str]:
    # Explicit fills work in SVG viewers that do not support context-stroke.
    # The page's palette selectors theme these fills and arrow strokes together.
    markers = ''.join(
        f'<marker id="arrow-{color[1:]}" markerWidth="9" markerHeight="9" refX="8" refY="4" orient="auto">'
        f'<path d="M0,0 L8,4 L0,8 Z" fill="{color}" stroke="none"/></marker>'
        for color in ARROW_COLORS)
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{esc(title)}">',
            f'<title>{esc(title)}</title>',
            f'<defs>{markers}</defs>',
            '<style>text{font-family:Inter,Arial,Helvetica,sans-serif} .mono{font-family:ui-monospace,monospace}</style>',
            f'<rect width="{width}" height="{height}" fill="#ffffff"/>']


def packet_label(event: dict) -> str:
    flags = event.get('flags', event.get('name', event.get('action', 'packet')))
    if isinstance(flags, (list, tuple)):
        flags = '|'.join(flags)
    elif isinstance(flags, str) and flags and all(c in 'SAPFRUEC' for c in flags):
        names = {'S':'SYN','A':'ACK','P':'PSH','F':'FIN','R':'RST','U':'URG','E':'ECE','C':'CWR'}
        flags = '|'.join(names[c] for c in flags)
    payload = event.get('payload', '')
    if payload and payload != 'none':
        flags = str(flags) + ' + ' + str(payload)
    return str(flags)


def plan_svg(plan: dict) -> str:
    events = [event_data(e) for e in plan.get('history', [])]
    title = str(plan.get('title', plan.get('id', 'Measurement plan')))
    row_heights = [112 if event_kind(e) == 'packet' else 64 for e in events]
    header_height = 284
    footer_height = 78
    width, height = 1160, header_height + sum(row_heights) + footer_height
    out = svg_start(width, height, title)
    out += [f'<rect width="1160" height="145" fill="#eff7f6"/>',
            text_line(32, 33, str(plan.get('id', '')) + ' / OFFLINE MEASUREMENT PLAN', 12, TEAL, '700')]
    for i, line in enumerate(wrap(title, 95, 2)):
        out.append(text_line(32, 65+i*25, line, 21, INK, '700'))
    cost = plan.get('cost', {})
    total = cost.get('total', '?') if isinstance(cost, dict) else cost
    cost_text = f"C = {total}"
    if isinstance(cost, dict):
        cost_text += '  ·  N = {}  ·  A = {}  ·  W = {}  ·  T = {}'.format(*(cost.get(k, '?') for k in ['N','A','W','T']))
    out.append(text_line(32, 122, cost_text, 14, INK, '600'))
    out.append(text_line(32, 166, 'Goal: ' + str(plan.get('goal', '?')) + '   |   Decision family: ' + str(plan.get('family', '?')), 12, MUTED))
    checkpoint = plan.get('checkpoint', {})
    if isinstance(checkpoint, dict):
        checkpoint_text = 'Checkpoint: ' + ' / '.join(str(checkpoint[k]) for k in ['name', 'phase'] if checkpoint.get(k) is not None)
        checkpoint_text += ' / incarnation g' + str(checkpoint.get('generation', '?')) + ' / ISNs ' + str(checkpoint.get('client', '?')) + ', ' + str(checkpoint.get('server', '?'))
        out.append(text_line(32, 187, checkpoint_text[:160], 12, INK, '600'))
    labels = plan.get('labels', [])
    label_text = 'Decisions: ' + ('; '.join(str(x) for x in labels) if labels else 'ordinary reference progress')
    for j, line in enumerate(wrap(label_text, 145, 2)):
        out.append(text_line(32, 209+16*j, line, 10, MUTED))
    columns = [(148, 'MEASUREMENT MACHINE'), (557, 'DPI OBSERVATION'), (989, 'REFERENCE LINUX')]
    for x, name in columns:
        out.append(text_line(x, 261, name, 12, INK, '700', 'middle'))
        out.append(f'<line x1="{x}" y1="276" x2="{x}" y2="{height-footer_height+4}" stroke="#bacbd0" stroke-dasharray="3 5"/>')
    y = header_height
    for index, (event, row_height) in enumerate(zip(events, row_heights), 1):
        kind = event_kind(event)
        if index % 2:
            out.append(f'<rect x="25" y="{y}" width="1110" height="{row_height}" fill="#f8fafb"/>')
            for x, _ in columns:
                out.append(f'<line x1="{x}" y1="{y}" x2="{x}" y2="{y+row_height}" stroke="#bacbd0" stroke-dasharray="3 5"/>')
        out.append(text_line(42, y+25, f'{index:02}', 11, MUTED, '600'))
        if kind == 'packet':
            actor = str(event.get('actor', event.get('sender', 'attacker'))).lower()
            server = actor in {'server', 'linux', 's'}
            dpi_only = event.get('delivery') in {'dpi_only', 'dpi-only', 'ttl_limited', 'ttl'}
            bad = event.get('checksum') in {'invalid', 'bad', 'incorrect'}
            color = RED if bad else ORANGE if dpi_only else TEAL if server else '#275f8a'
            x1 = 989 if server else 148
            x2 = 148 if server else 557 if dpi_only else 989
            arrow_y = y + 43
            out.append(f'<line x1="{x1}" y1="{arrow_y}" x2="{x2}" y2="{arrow_y}" stroke="{color}" stroke-width="2.3" marker-end="url(#arrow-{color[1:]})"/>')
            if dpi_only:
                out.append(f'<line x1="570" y1="{arrow_y}" x2="969" y2="{arrow_y}" stroke="#b2bdc3" stroke-width="1.4" stroke-dasharray="6 6"/>')
                out.append(text_line(773, y+32, 'expires before Linux', 11, MUTED, anchor='middle'))
                out.append(f'<path d="M978 {arrow_y-6} l12 12 m-12 0 l12 -12" stroke="{ORANGE}" stroke-width="2"/>')
            if bad and not dpi_only:
                out.append(f'<path d="M981 {arrow_y-7} l14 14 m-14 0 l14 -14" stroke="{RED}" stroke-width="2.3"/>')
            flow = event.get('flow', '?')
            colors = '/'.join(str(event.get(k, event.get(fallback))) for k, fallback in [('client_color','client'), ('server_color','server')] if event.get(k, event.get(fallback)))
            details = [str(flow), 'g'+str(event.get('generation', '?'))] + (['ISNs '+colors] if colors else [])
            for key, relation_key, alias in [('seq','seq_relation','SEQ'), ('ack','ack_relation','ACK')]:
                value, relation = event.get(key), event.get(relation_key)
                if value is not None:
                    details.append(alias+'='+str(value)+((' ['+str(relation)+']') if relation and relation != 'none' else ''))
                elif relation is not None and relation != 'none':
                    details.append(alias+'='+str(relation))
            label = packet_label(event)
            if bad:
                label += ' · INVALID TCP CHECKSUM'
            if dpi_only:
                label += ' · DPI ONLY'
            mid = (x1+x2)/2
            out.append(text_line(mid, y+27, label[:112], 12, color, '700', 'middle'))
            out.append(text_line(148, y+64, '   |   '.join(details)[:137], 11, MUTED))
            effect = event.get('effect', event.get('linux_effect', event.get('note', '')))
            if not effect and dpi_only:
                effect = 'Reference Linux: no arrival, no effect, no reply. DPI behavior remains unknown.'
            if effect:
                out.append(text_line(148, y+81, str(effect)[:148], 11, MUTED))
            marking = event.get('state_after', {})
            if isinstance(marking, dict) and marking:
                state_text = 'Reference marking: ' + '   |   '.join(str(k)+' = '+str(v) for k,v in marking.items())
                out.append(text_line(148, y+100, state_text[:150], 10, MUTED))
            elif event.get('linux_tcp_accepted') is not None:
                status_text = 'Linux IP arrival: '+str(event.get('linux_ip_arrival'))+' / TCP effect accepted: '+str(event.get('linux_tcp_accepted'))+' / DPI processing: unmeasured'
                out.append(text_line(148, y+100, status_text, 10, MUTED))
        else:
            value = event.get('effect', event.get('description', event.get('note', event.get('action', event.get('name', kind)))))
            if kind == 'wait':
                value = f"WAIT {event.get('units', event.get('wait_units', 1))} unit(s) · {value}"
            out.append(f'<rect x="139" y="{y+8}" width="862" height="35" rx="7" fill="#edf1f4"/>')
            out.append(text_line(155, y+30, str(value)[:130], 12, MUTED))
        y += row_height
    out.append(f'<line x1="32" y1="{height-64}" x2="1127" y2="{height-64}" stroke="#d7e1e5"/>')
    out.append(text_line(32, height-41, 'Colored arrows = modeled wire events. Dashed endpoint leg = deliberate TTL expiry. Red = invalid TCP checksum.', 11, MUTED))
    out.append(text_line(32, height-21, 'No packets sent. Linux behavior is symbolic. All censorship bits and DPI implementation outcomes are unmeasured.', 11, MUTED))
    out.append('</svg>')
    return '\n'.join(out)


def overview_svg(plans: list[dict], metadata: dict) -> str:
    grouped: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for plan in plans:
        grouped[str(plan.get('goal', '?'))][str(plan.get('family', '?'))].append(plan)
    rows = []
    for goal, families in sorted(grouped.items()):
        for family, members in sorted(families.items()):
            rows.append((goal, family, members))
    height = 210 + len(rows)*138
    out = svg_start(1180, height, 'Lifecycle measurement coverage tree')
    out.append(text_line(35, 38, 'LIFECYCLE MEASUREMENT COVERAGE', 13, TEAL, '700'))
    out.append(text_line(35, 74, f'{len(plans):,} offline plans · grouped by goal and semantic decision', 24, INK, '700'))
    out.append(text_line(35, 104, 'Each branch shows all-group counts and a representative packet history; open an individual plan for the complete exchange.', 12, MUTED))
    out.append('<rect x="35" y="129" width="170" height="47" rx="8" fill="#142d3b"/>')
    out.append(text_line(120, 158, 'Initial LISTEN', 14, '#fff', '700', 'middle'))
    for i, (goal, family, members) in enumerate(rows):
        y = 195+i*138
        out.append(f'<path d="M120 176 V{y+42} H248" fill="none" stroke="#c2d0d6" stroke-width="1.6"/>')
        out.append(f'<rect x="248" y="{y}" width="890" height="118" rx="9" fill="#f5f8fa" stroke="#d9e3e7"/>')
        out.append(text_line(270, y+24, goal+' / '+family, 13, INK, '700'))
        costs = [p.get('cost', {}).get('total', 0) for p in members if isinstance(p.get('cost'), dict)]
        cost_range = f'cost {min(costs):g}–{max(costs):g}' if costs else 'cost not recorded'
        out.append(text_line(1116, y+24, f'{len(members)} plans · {cost_range}', 12, MUTED, anchor='end'))
        sample = min(members, key=lambda p: p.get('cost', {}).get('total', 0))
        packets = [event_data(e) for e in sample.get('history', []) if event_kind(e) == 'packet'][:7]
        for j, event in enumerate(packets):
            x = 277+j*119
            dpi_only = event.get('delivery') in {'dpi_only','dpi-only','ttl'}
            server = str(event.get('actor','attacker')).lower() in {'server','linux'}
            bad = event.get('checksum') == 'invalid'
            color = RED if bad else ORANGE if dpi_only else TEAL
            start,end=(x+86,x) if server else (x,x+42 if dpi_only else x+86)
            out.append(f'<line x1="{start}" y1="{y+65}" x2="{end}" y2="{y+65}" stroke="{color}" stroke-width="2" marker-end="url(#arrow-{color[1:]})"/>')
            out.append(text_line(x+43, y+51, packet_label(event)[:17], 9, color, '700', 'middle'))
            out.append(text_line(x+43, y+83, 'DPI only' if dpi_only else 'server' if server else 'full path', 9, MUTED, anchor='middle'))
        out.append(text_line(270, y+103, 'Representative: '+str(sample.get('id',''))+' · first '+str(len(packets))+' packet events', 10, MUTED))
    out.append('</svg>')
    return '\n'.join(out)


HTML_TEMPLATE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>TCP lifecycle · offline measurement atlas</title>
<script id="theme-init">
(function(){
  let saved=null,dark=false;
  try{saved=localStorage.getItem('tcp-lifecycle-theme')}catch(e){}
  try{dark=window.matchMedia('(prefers-color-scheme: dark)').matches}catch(e){}
  document.documentElement.dataset.theme=saved==='light'||saved==='dark'?saved:dark?'dark':'light';
})();
</script>
<style>
:root{--ink:#142d3b;--muted:#617583;--teal:#117f7a;--line:#dce5e8;--paper:#f4f7f8;--orange:#bc681c;--red:#b54444}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}a{color:var(--teal)}button,input,select{font:inherit}button,select{cursor:pointer}.top{background:var(--ink);color:white;padding:29px 36px 25px}.eyebrow{font-size:11px;letter-spacing:.14em;font-weight:750;text-transform:uppercase;color:#91d0c6}.top h1{font-size:30px;letter-spacing:-.04em;margin:6px 0 8px;line-height:1.15}.top p{margin:0;color:#c0d0d6;max-width:900px}.top a{color:#b3e0d8}.topnav{display:flex;gap:20px;flex-wrap:wrap;margin-top:15px;font-size:12px}.stats{display:flex;gap:0;flex-wrap:wrap;background:white;border-bottom:1px solid var(--line);padding:16px 36px}.stat{min-width:155px;margin:0 29px 0 0}.stat b{display:block;font-size:22px;line-height:1.2}.stat span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.status{margin-left:auto;max-width:380px;color:var(--muted);font-size:12px}.status strong{display:block;color:var(--ink)}.layout{display:grid;grid-template-columns:350px minmax(0,1fr);gap:22px;max-width:1800px;margin:auto;padding:24px 28px}.sidebar,.detail{background:white;border:1px solid var(--line);border-radius:11px;overflow:hidden;align-self:start}.sidebar{position:sticky;top:18px;max-height:calc(100vh - 36px);display:flex;flex-direction:column}.filterbox{padding:19px;border-bottom:1px solid var(--line)}.sectionlabel{font-size:11px;letter-spacing:.08em;text-transform:uppercase;font-weight:750;color:var(--muted)}.filterbox input,.filterbox select{width:100%;border:1px solid #cedbdf;border-radius:6px;background:white;padding:9px;color:var(--ink);min-width:0}.filterbox input{margin:10px 0}.filtergrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.filtergrid label{font-size:10px;color:var(--muted);text-transform:uppercase}.filtergrid select{margin-top:4px;font-size:11px;padding:7px}.resulthead{display:flex;justify-content:space-between;padding:11px 18px;background:#f7fafb;font-size:11px;color:var(--muted)}.resultlist{overflow:auto;min-height:100px}.result{border:0;border-bottom:1px solid #e9eef0;display:block;width:100%;background:white;padding:13px 17px;text-align:left;color:var(--ink)}.result:hover{background:#f3f9f8}.result.active{background:#eaf5f2;box-shadow:inset 3px 0 var(--teal)}.result small{display:flex;justify-content:space-between;color:var(--muted);font-size:10px}.result strong{font-size:12px;display:block;margin:5px 0 7px}.tag{display:inline-block;border-radius:4px;padding:2px 6px;background:#edf2f5;color:#516c7c;font-size:10px;margin:2px 4px 0 0}.tag.ttl{background:#fcf1e3;color:#94521b}.tag.bad{background:#faeded;color:#a44444}.cost{color:var(--teal);font-weight:700}.more{border:0;background:#edf5f2;padding:12px;color:var(--teal);width:100%}.detailtop{padding:25px 28px;border-bottom:1px solid var(--line)}.detailtop h2{font-size:24px;line-height:1.25;letter-spacing:-.025em;margin:8px 0 12px}.detailtop p{margin:10px 0;color:var(--muted)}.costrow{display:flex;flex-wrap:wrap;gap:16px;margin-top:19px;font-size:12px}.costrow b{font-size:19px;margin-right:4px}.formula{font-size:11px;color:var(--muted);margin-top:9px}.tabs{display:flex;gap:0;border-bottom:1px solid var(--line);padding:0 22px;background:#fbfcfd}.tabs button{border:0;border-bottom:3px solid transparent;background:none;padding:13px 15px;color:var(--muted);font-size:12px;font-weight:650}.tabs button.sel{border-color:var(--teal);color:var(--teal)}.pane{padding:22px 28px;display:none}.pane.sel{display:block}.diagram{width:100%;height:auto;display:block}.diagramwrap svg{width:100%;height:auto;display:block}.notice{background:#edf6f4;border-left:3px solid var(--teal);padding:12px 15px;margin-bottom:18px;font-size:12px;color:#375962}.notice.amber{background:#fff6e9;border-color:var(--orange);color:#805521}h3{font-size:14px;margin:22px 0 9px}h3:first-child{margin-top:0}table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.03em}th,td{border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:top}td:first-child,th:first-child{padding-left:0}code,pre{font:11px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace}pre{overflow:auto;background:#f5f8fa;padding:15px;border-radius:7px;max-height:700px;white-space:pre-wrap;word-break:break-word}.small{font-size:12px;color:var(--muted)}.key{display:flex;gap:15px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin:0 0 16px}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--teal);margin-right:4px}.dot.orange{background:var(--orange)}.dot.red{background:var(--red)}details{font-size:12px;margin:10px 0}summary{cursor:pointer;font-weight:650}.empty{padding:30px;color:var(--muted)}.download{font-size:12px;text-decoration:none;border:1px solid var(--line);border-radius:5px;padding:6px 10px;display:inline-block;margin:5px 5px 0 0}.footer{max-width:1800px;padding:0 30px 25px;margin:auto;font-size:11px;color:var(--muted)}@media(max-width:1000px){.layout{grid-template-columns:290px minmax(0,1fr);padding:16px;gap:14px}.detailtop,.pane{padding:20px}.top{padding:25px}.stat{min-width:110px;margin-right:16px}}@media(max-width:760px){.layout{display:block}.sidebar{position:relative;max-height:520px;margin-bottom:18px;top:0}.stats{padding:16px 22px}.stat b{font-size:18px}.status{margin-left:0;width:100%;margin-top:12px}.top h1{font-size:25px}.tabs{overflow:auto;padding:0 8px}.tabs button{padding:12px}.detailtop h2{font-size:21px}.pane{padding:16px}.resultlist{max-height:270px}}
:root{color-scheme:light;--surface:#fff;--surface-alt:#f7fafb;--field-line:#cedbdf;--hover:#f3f9f8;--selected:#eaf5f2;--tag:#edf2f5;--tag-ink:#516c7c;--ttl-bg:#fcf1e3;--ttl-ink:#94521b;--bad-bg:#faeded;--bad-ink:#a44444;--notice-bg:#edf6f4;--notice-ink:#375962;--amber-bg:#fff6e9;--amber-ink:#805521;--svg-heading:#eff7f6;--svg-row:#f8fafb;--svg-wait:#edf1f4;--svg-ink:#142d3b;--svg-muted:#587080;--svg-server:#117f7a;--svg-attacker:#275f8a;--svg-ttl:#bc681c;--svg-bad:#b54444;--svg-line:#bacbd0;--svg-expired:#b2bdc3;--svg-rule:#d7e1e5}
:root[data-theme="dark"]{color-scheme:dark;--ink:#e4edf3;--muted:#b1c0ca;--teal:#65d6c5;--line:#334655;--paper:#101820;--orange:#efb66b;--red:#ef9a9a;--surface:#192630;--surface-alt:#22323e;--field-line:#496170;--hover:#213a43;--selected:#21433e;--tag:#293b49;--tag-ink:#c4d2dc;--ttl-bg:#493722;--ttl-ink:#f3c58c;--bad-bg:#482e35;--bad-ink:#ffb0b0;--notice-bg:#203c3a;--notice-ink:#c2ded7;--amber-bg:#40331f;--amber-ink:#f0c996;--svg-heading:#173b3d;--svg-row:#1e303a;--svg-wait:#263844;--svg-ink:#e4edf3;--svg-muted:#b1c0ca;--svg-server:#65d6c5;--svg-attacker:#83baff;--svg-ttl:#efb66b;--svg-bad:#ef9a9a;--svg-line:#526875;--svg-expired:#6c808c;--svg-rule:#364b59}
.top{background:#142d3b}.topline{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}.theme-toggle{display:inline-flex;align-items:center;gap:8px;min-height:38px;border:1px solid #718d9c;border-radius:7px;background:transparent;color:#edf6fa;padding:7px 12px;font-size:12px;line-height:1.3;white-space:nowrap}.theme-toggle:hover{background:#254453}.theme-toggle[aria-pressed="true"]{background:#21433e;border-color:#65d6c5;color:#baf7ed}.theme-toggle svg{width:16px;height:16px;flex-shrink:0}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid var(--teal);outline-offset:3px}
.stats,.sidebar,.detail,.filterbox input,.filterbox select,.result{background:var(--surface)}.filterbox input,.filterbox select{border-color:var(--field-line)}.filterbox input::placeholder{color:var(--muted);opacity:1}.resulthead,.tabs,pre{background:var(--surface-alt)}.result{border-bottom-color:var(--line)}.result:hover{background:var(--hover)}.result.active,.more{background:var(--selected)}.tag{background:var(--tag);color:var(--tag-ink)}.tag.ttl{background:var(--ttl-bg);color:var(--ttl-ink)}.tag.bad{background:var(--bad-bg);color:var(--bad-ink)}.notice{background:var(--notice-bg);color:var(--notice-ink)}.notice.amber{background:var(--amber-bg);color:var(--amber-ink)}
.diagramwrap svg [fill="#ffffff"]{fill:var(--surface)}.diagramwrap svg [fill="#eff7f6"]{fill:var(--svg-heading)}.diagramwrap svg [fill="#f8fafb"]{fill:var(--svg-row)}.diagramwrap svg [fill="#edf1f4"]{fill:var(--svg-wait)}.diagramwrap svg [fill="#142d3b"]{fill:var(--svg-ink)}.diagramwrap svg [fill="#587080"]{fill:var(--svg-muted)}.diagramwrap svg [fill="#117f7a"]{fill:var(--svg-server)}.diagramwrap svg [stroke="#117f7a"]{stroke:var(--svg-server)}.diagramwrap svg [fill="#275f8a"]{fill:var(--svg-attacker)}.diagramwrap svg [stroke="#275f8a"]{stroke:var(--svg-attacker)}.diagramwrap svg [fill="#bc681c"]{fill:var(--svg-ttl)}.diagramwrap svg [stroke="#bc681c"]{stroke:var(--svg-ttl)}.diagramwrap svg [fill="#b54444"]{fill:var(--svg-bad)}.diagramwrap svg [stroke="#b54444"]{stroke:var(--svg-bad)}.diagramwrap svg [stroke="#bacbd0"]{stroke:var(--svg-line)}.diagramwrap svg [stroke="#b2bdc3"]{stroke:var(--svg-expired)}.diagramwrap svg [stroke="#d7e1e5"]{stroke:var(--svg-rule)}
</style></head><body>
<header class="top"><div class="topline"><div class="eyebrow">Petri Net Research / measurement generation</div><button type="button" id="theme-toggle" class="theme-toggle" aria-label="Dark mode" aria-pressed="false"><svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><circle cx="10" cy="10" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M10 3a7 7 0 0 0 0 14Z" fill="currentColor"/></svg>Dark mode</button></div><h1>TCP lifecycle measurement atlas</h1><p>Offline symbolic histories for connection start, establishment, termination, and reconnection. Reference TCP effects are modeled; DPI behavior and every censorship bit remain unmeasured.</p><nav class="topnav"><a href="overview.svg" id="export-overview" target="_blank">Coverage overview ↗</a><a href="plans.json" id="export-plans">Plans JSON</a><a href="plans.csv" id="export-csv">Plans CSV</a><a href="bundles.json" id="export-bundles">Multi-probe bundles</a><a href="run_metadata.json" id="export-metadata">Run metadata</a><a href="#method" id="methodlink">Method and reproduction</a></nav></header>
<div class="stats" id="stats"></div><div id="runnotes" style="max-width:1800px;margin:16px auto 0;padding:0 28px"></div>
<main class="layout"><aside class="sidebar"><div class="filterbox"><div class="sectionlabel">Browse measurement plans</div><input id="search" type="search" placeholder="Search flags, decisions, titles, IDs…" aria-label="Search plans"><div class="filtergrid"><label>Decision family<select id="family"></select></label><label>Lifecycle goal<select id="goal"></select></label><label>Packet visibility<select id="visibility"><option value="all">All visibility</option><option value="dpi_only">Contains DPI-only</option><option value="full">Full path only</option></select></label><label>Checksum<select id="checksum"><option value="all">All checksums</option><option value="invalid">Contains invalid</option><option value="valid">Valid only</option></select></label><label>Bundles<select id="bundle"><option value="all">All plans</option><option value="member">Bundle members</option></select></label><label>Order<select id="sort"><option value="cost">Cost, ascending</option><option value="id">Plan ID</option><option value="family">Decision family</option></select></label></div></div><div class="resulthead"><span id="resultcount"></span><span>C = N + A + 2W + κT</span></div><div class="resultlist" id="resultlist"></div></aside><article class="detail" id="detail"><div class="empty">Select a plan to inspect its complete exchange.</div></article></main>
<footer class="footer">Generated locally from the recorded pilot configuration. This browser is self-contained and works without a server or internet connection. Individual SVG diagrams preserve selectable text. No live probe or packet-sending code is included.</footer>
<script type="application/json" id="embedded-data">__PAYLOAD__</script><script id="atlas-app">
'use strict';
const DATA=JSON.parse(document.getElementById('embedded-data').textContent),PLANS=DATA.plans,META=DATA.metadata,DIAGRAMS=DATA.diagrams||{};
const $=id=>document.getElementById(id),h=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function syncThemeToggle(){const dark=document.documentElement.dataset.theme==='dark';$('theme-toggle').setAttribute('aria-pressed',String(dark));$('theme-toggle').title=dark?'Switch to light mode':'Switch to dark mode'}
syncThemeToggle();
$('theme-toggle').addEventListener('click',()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('tcp-lifecycle-theme',theme)}catch(e){}syncThemeToggle()});
const ev=e=>e.packet&&typeof e.packet==='object'?Object.assign({},e,e.packet):e;
const events=p=>(p.history||[]).map(ev);
const ttl=p=>events(p).some(e=>['dpi_only','dpi-only','ttl_limited','ttl'].includes(e.delivery));
const bad=p=>events(p).some(e=>['invalid','bad','incorrect'].includes(e.checksum));
const cost=p=>Number((p.cost||{}).total??0);
const planFamilies=p=>Array.isArray(p.families)&&p.families.length?p.families:[p.family||'?'];
const bundles=Array.isArray(META.bundles)?META.bundles:[];
const bmembers=new Set(bundles.flatMap(b=>b.probe_ids||b.plan_ids||b.members||[]).map(x=>typeof x==='object'?x.id:x));
const inBundle=p=>bmembers.has(p.id)||(p.bundle_ids||p.bundles||p.bundle||[]).length>0;
let selected=null,limit=150,filtered=[],activeTab='exchange';
const makeBlob=(body,type)=>URL.createObjectURL(new Blob([body],{type}));
for(const [id,body,type,name] of [['export-overview',DATA.overview||'','image/svg+xml','overview.svg'],['export-plans',JSON.stringify(PLANS,null,2),'application/json','plans.json'],['export-metadata',JSON.stringify(META,null,2),'application/json','run_metadata.json'],['export-bundles',JSON.stringify(bundles,null,2),'application/json','bundles.json'],['export-csv',['id,family,goal,cost,N,A,W,T',...PLANS.map(p=>[p.id,p.family,p.goal,cost(p),p.cost?.N,p.cost?.A,p.cost?.W,p.cost?.T].map(x=>JSON.stringify(x??'')).join(','))].join('\n'),'text/csv','plans.csv']]){if($(id)){$(id).href=makeBlob(body,type);$(id).download=name}}
for(const [id,key] of [['family','family'],['goal','goal']]){$(id).innerHTML='<option value="all">All '+(id==='family'?'families':'goals')+'</option>'+[...new Set(id==='family'?PLANS.flatMap(planFamilies):PLANS.map(p=>p[key]||'?'))].sort().map(v=>'<option value="'+h(v)+'">'+h(v)+'</option>').join('')}
const values=PLANS.map(cost),goals=new Set(PLANS.map(p=>p.goal)).size,families=new Set(PLANS.flatMap(planFamilies)).size;
const runStatus=META.status||META.search_status||META.stats?.status||'Bounded offline pilot';
$('stats').innerHTML=[['Plans',PLANS.length],['Decision families',families],['Lifecycle goals',goals],['DPI-only plans',PLANS.filter(ttl).length],['Cost range',values.length?Math.min(...values)+'–'+Math.max(...values):'—']].map(([k,v])=>'<div class="stat"><b>'+h(v)+'</b><span>'+h(k)+'</span></div>').join('')+'<div class="status"><strong>'+h(runStatus)+'</strong>Bounded candidate exploration; no claim of exhaustive TCP coverage or measured fingerprint separation.</div>';
const limitations=Array.isArray(META.limitations)?META.limitations:[META.limitations].filter(Boolean);$('runnotes').innerHTML='<details class="notice amber"><summary>Pilot bounds, approximations, and incomplete exploration</summary><ul>'+limitations.map(l=>'<li>'+h(typeof l==='string'?l:JSON.stringify(l))+'</li>').join('')+'</ul><pre>'+h(JSON.stringify(META.configuration||{},null,2))+'</pre></details>';
function tags(p){return '<span class="tag">'+h(p.goal)+'</span>'+(ttl(p)?'<span class="tag ttl">DPI-only TTL</span>':'')+(bad(p)?'<span class="tag bad">Invalid checksum</span>':'')+(inBundle(p)?'<span class="tag">Bundle member</span>':'')}
function apply(){const q=$('search').value.trim().toLowerCase();filtered=PLANS.filter(p=>($('family').value==='all'||planFamilies(p).includes($('family').value))&&($('goal').value==='all'||p.goal===$('goal').value)&&($('visibility').value==='all'||($('visibility').value==='dpi_only'?ttl(p):!ttl(p)))&&($('checksum').value==='all'||($('checksum').value==='invalid'?bad(p):!bad(p)))&&($('bundle').value==='all'||inBundle(p))&&(!q||JSON.stringify(p).toLowerCase().includes(q)));const order=$('sort').value;filtered.sort((a,b)=>order==='cost'?cost(a)-cost(b)||String(a.id).localeCompare(String(b.id)):String(a[order]||'').localeCompare(String(b[order]||''))||cost(a)-cost(b));$('resultcount').textContent=filtered.length+' matching / '+PLANS.length;renderList();if(!selected&&filtered.length)select(filtered[0].id);}
function renderList(){$('resultlist').innerHTML=filtered.slice(0,limit).map(p=>'<button class="result '+(selected?.id===p.id?'active':'')+'" data-id="'+h(p.id)+'"><small><span>'+h(p.id)+' · '+h(p.family)+'</span><span class="cost">C '+h(cost(p))+'</span></small><strong>'+h(p.title||p.id)+'</strong>'+tags(p)+'</button>').join('')+(filtered.length>limit?'<button class="more" id="more">Show next '+Math.min(150,filtered.length-limit)+' plans</button>':'')+(!filtered.length?'<div class="empty">No plans match these filters.</div>':'');document.querySelectorAll('.result').forEach(b=>b.onclick=()=>select(b.dataset.id));if($('more'))$('more').onclick=()=>{limit+=150;renderList()}}
function table(headers,rows){return '<table><thead><tr>'+headers.map(x=>'<th>'+h(x)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(x=>'<td>'+x+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}
function select(id){selected=PLANS.find(p=>p.id===id);if(!selected)return;const p=selected,c=p.cost||{},file='diagrams/'+String(p.id).replace(/[^A-Za-z0-9_.-]+/g,'_')+'.svg',conditions=p.conditions||[],labels=p.labels||[],check=p.checkpoint||{},pb=bundles.filter(b=>(b.probe_ids||b.plan_ids||b.members||[]).some(x=>(typeof x==='object'?x.id:x)===p.id));
let condRows=conditions.map((c,i)=>[h(c.id||i+1),h(c.history||c.history_type||'?'),h(c.hostname_class||c.sni_class||c.hostname||'?'),'<strong>Unmeasured</strong>',h(c.cost?.total??c.execution_cost??'See metadata')]);
if(!condRows.length)condRows=[['Ordinary / benign','Ordinary','Benign','<strong>Unmeasured</strong>','See metadata'],['Ordinary / blocked','Ordinary','Blocked','<strong>Unmeasured</strong>','See metadata'],['Candidate / benign','Candidate','Benign','<strong>Unmeasured</strong>','See metadata'],['Candidate / blocked','Candidate','Blocked','<strong>Unmeasured</strong>','See metadata']];
const hypothesis=p.hypothesis||p.decision_question||'Candidate opportunity for differing DPI tracking or parsing. Discrimination requires repeated calibrated measurements.';
$('detail').innerHTML='<div class="detailtop"><div class="sectionlabel">'+h(p.id)+' / '+h(p.family)+'</div><h2>'+h(p.title||p.id)+'</h2>'+tags(p)+'<p>'+h(hypothesis)+'</p><div class="costrow">'+[['C','total'],['Packets N','N'],['Departures A','A'],['Repeated decisions W','W'],['Wait units T','T']].map(([t,k])=>'<span><b>'+h(c[k]??'?')+'</b>'+h(t)+'</span>').join('')+'</div><div class="formula">Frozen generation objective: C = N + A + 2W + κT. Controls, repetitions, and checkpoint replays have separately recorded execution costs.</div><a class="download" id="downloadsvg" href="'+h(file)+'" target="_blank">Open / save full SVG ↗</a><a class="download" id="downloadplan" href="#">Download this plan JSON</a></div><nav class="tabs">'+[['exchange','Packet exchange'],['controls','Controls & readout'],['decisions','Decisions & bundles'],['raw','Metadata']].map(([k,t])=>'<button data-tab="'+k+'" class="'+(activeTab===k?'sel':'')+'">'+t+'</button>').join('')+'</nav><section class="pane '+(activeTab==='exchange'?'sel':'')+'" data-pane="exchange"><div class="key"><span><i class="dot"></i>Reference traffic</span><span><i class="dot orange"></i>DPI-only visibility</span><span><i class="dot red"></i>Invalid TCP checksum</span></div><div class="notice">One reference replay is shown, including its costed readout and cleanup. DPI processing is unknown. Any real censorship interference would require recording the observed outcome instead of assuming the reference exchange continued.</div><div class="diagramwrap">'+(DIAGRAMS[p.id]||'<img class="diagram" src="'+h(file)+'" alt="Packet exchange for '+h(p.id)+'">')+'</div></section><section class="pane '+(activeTab==='controls'?'sel':'')+'" data-pane="controls"><div class="notice">Y ∈ {0, 1} is an SNI-dependent, calibrated censorship bit. Every Y is currently null / unmeasured. Calibration failures and uncertain delivery are excluded trial metadata, not a third fingerprint value.</div><h3>Four matched conditions</h3>'+table(['Condition','History','Readout','Y / status','Replay cost'],condRows)+'<h3>Interpretation and observability</h3><p class="small">Use a fixed valid TLS ClientHello, a matched benign and blocked hostname, fixed segmentation, and matched timing and visibility. Baseline controls must establish a stable positive censorship signal and benign behavior. Repeat each condition. Ordinary TCP resets, deliberate TTL expiry, ICMP Time Exceeded, checksum rejection, and local timeouts do not establish censorship.</p><p class="small">A TTL-limited readout cannot use a missing Linux response as its signal. It requires an attributable injected reset or another independently calibrated, observable policy side effect. The delivery regime itself must be calibrated before any live execution.</p><details><summary>Readout and execution-cost metadata</summary><pre>'+h(JSON.stringify({readout:p.readout,execution_cost:p.execution_cost,conditions:p.conditions},null,2))+'</pre></details></section><section class="pane '+(activeTab==='decisions'?'sel':'')+'" data-pane="decisions"><h3>Designated decision labels</h3>'+(labels.length?labels.map(l=>'<div class="tag">'+h(typeof l==='object'?JSON.stringify(l):l)+'</div>').join(''):'<p class="small">See plan metadata.</p>')+'<h3>Proposal classifications</h3><p class="small">A single exact action history can cover several semantic families or phases. These aliases share one plan record.</p><pre>'+h(JSON.stringify({families:planFamilies(p),decision_phases:p.decision_phases||[p.decision_phase],proposal_classifications:p.proposal_classifications||[]},null,2))+'</pre><h3>Checkpoint</h3><pre>'+h(JSON.stringify(check,null,2))+'</pre><h3>Small multi-probe bundles</h3>'+(pb.length?pb.map(b=>'<details open><summary>'+h(b.id||b.title||'Bundle')+'</summary><pre>'+h(JSON.stringify(b,null,2))+'</pre></details>').join(''):'<p class="small">Consult <a href="bundles.json">bundles.json</a> for probe combinations and planned comparisons. Bundle value is unmeasured.</p>')+'<div class="notice amber">Semantic coverage labels are generation heuristics. They do not establish unknown DPI-state equivalence, information gain, or fingerprint separation.</div></section><section class="pane '+(activeTab==='raw'?'sel':'')+'" data-pane="raw"><h3>Complete plan record</h3><pre>'+h(JSON.stringify(p,null,2))+'</pre><details><summary>Pilot run metadata and limitations</summary><pre>'+h(JSON.stringify(META,null,2))+'</pre></details></section>';
if($('downloadsvg')&&DIAGRAMS[p.id]){$('downloadsvg').href=makeBlob(DIAGRAMS[p.id],'image/svg+xml');$('downloadsvg').download=p.id+'.svg'}
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{activeTab=b.dataset.tab;document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('sel',x.dataset.tab===activeTab));document.querySelectorAll('[data-pane]').forEach(x=>x.classList.toggle('sel',x.dataset.pane===activeTab))});$('downloadplan').onclick=e=>{e.preventDefault();const blob=new Blob([JSON.stringify(p,null,2)],{type:'application/json'}),u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=p.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)};renderList();if(location.hash!==('#'+encodeURIComponent(id)))history.replaceState(null,'','#'+encodeURIComponent(id));}
for(const id of ['search','family','goal','visibility','checksum','bundle','sort'])$(id).addEventListener(id==='search'?'input':'change',()=>{limit=150;apply()});
const initialHash=location.hash;apply();$('methodlink').onclick=e=>{e.preventDefault();activeTab='raw';select(selected?.id||PLANS[0]?.id)};if(initialHash){try{select(decodeURIComponent(initialHash.slice(1)))}catch(e){}}window.addEventListener('hashchange',()=>{if(location.hash)select(decodeURIComponent(location.hash.slice(1)))});
</script></body></html>'''


def render_all(output_dir: str | Path, plans: list[dict], metadata: dict) -> dict:
    """Write index.html, per-plan SVGs, and grouped overview.svg.

    `plans.json` and other tabular exports are owned by the search caller.
    The browser embeds all plan/metadata bytes and never needs a fetch().
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    diagrams = output_dir/'diagrams'
    diagrams.mkdir(exist_ok=True)
    expected = {safe_id(p['id'])+'.svg' for p in plans}
    for old in diagrams.glob('P[0-9][0-9][0-9][0-9].svg'):
        if old.name not in expected:
            old.unlink()
    diagram_svgs = {}
    for plan in plans:
        svg = plan_svg(plan)
        diagram_svgs[plan['id']] = svg
        (diagrams/(safe_id(plan['id'])+'.svg')).write_text(svg, encoding='utf-8')
    overview = overview_svg(plans, metadata)
    (output_dir/'overview.svg').write_text(overview, encoding='utf-8')
    payload = json.dumps({'plans': plans, 'metadata': metadata, 'diagrams': diagram_svgs, 'overview': overview}, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    (output_dir/'index.html').write_text(HTML_TEMPLATE.replace('__PAYLOAD__', payload), encoding='utf-8')
    return {'browser': 'index.html', 'diagrams': len(plans), 'overview': 'overview.svg'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results_dir', type=Path)
    args = parser.parse_args()
    plans = json.loads((args.results_dir/'plans.json').read_text())
    if isinstance(plans, dict):
        plans = plans.get('plans', [])
    metadata = json.loads((args.results_dir/'run_metadata.json').read_text())
    print(json.dumps(render_all(args.results_dir, plans, metadata), indent=2))
