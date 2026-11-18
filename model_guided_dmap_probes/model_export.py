"""Export an executable finite colored state-machine Petri net from endpoint.py.

Each CState token encodes one complete symbolic endpoint marking. Actions are
expanded into their actual ordered wire events; no response can be skipped or
interleaved. The JSON map supplies readable components of each encoded state.
This intentionally exports a bounded subgraph when limits are reached.
"""
from __future__ import annotations
import argparse
from collections import deque
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

try:
    from .endpoint import Action, initial_state, enabled_actions, step, state_summary, get_flow, knows
except ImportError:
    from endpoint import Action, initial_state, enabled_actions, step, state_summary, get_flow, knows


def export_model(output_dir, action_sequences=None, max_states=1200, max_edges=12000, max_wait_units=2):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    states = [initial_state()]
    ids = {states[0]: 0}
    queue = deque([0])
    edges = []
    edge_keys = set()
    rejected = 0
    limit_hits = set()

    def add(source, action, outcome, seed=False):
        target_state = outcome.state
        if target_state not in ids:
            if not seed and len(states) >= max_states:
                limit_hits.add('max_states')
                return False
            ids[target_state] = len(states)
            states.append(target_state)
            queue.append(ids[target_state])
        target = ids[target_state]
        ident = (source, action, target)
        if ident not in edge_keys:
            edge_keys.add(ident)
            edges.append((source, target, action, outcome))
        return True

    seed_sequences = 0
    for sequence in action_sequences or []:
        state = initial_state()
        for action in sequence:
            if isinstance(action, dict):
                action = Action(**action)
            outcomes = step(state, action)
            if not outcomes:
                raise ValueError('seed sequence includes action outside endpoint profile')
            outcome = outcomes[0]
            add(ids[state], action, outcome, seed=True)
            state = outcome.state
        seed_sequences += 1
    seed_states, seed_edges = len(states), len(edges)
    expanded = set()
    while queue and len(edges) < max_edges:
        source = queue.popleft()
        if source in expanded:
            continue
        expanded.add(source)
        state = states[source]
        actions = enabled_actions(state)
        # One fixed readout per incarnation; numerical payload geometry is separate.
        for flow in state.flows:
            if flow.phase == 'ESTABLISHED' and flow.rcv_offset == 1 and knows(state, flow):
                actions.append(Action(flow=flow.name, flags='PA', client=flow.client,
                                      server=flow.server, payload='readout'))
        for action in actions:
            if action.kind == 'wait' and state.elapsed_units >= max_wait_units:
                continue
            try:
                outcomes = step(state, action)
            except ValueError:
                rejected += 1
                continue
            for outcome in outcomes:
                if max((f.rcv_offset for f in outcome.state.flows), default=0) > 3:
                    continue
                add(source, action, outcome)
            if len(edges) >= max_edges:
                limit_hits.add('max_edges')
                break
    if queue:
        limit_hits.add('unexpanded_frontier')

    project = ET.Element('project', name='TCP_lifecycle_offline_symbolic', version='121')
    net = ET.SubElement(project, 'gspn', name='CPN', zoom='70', **{'view-rates': 'false', 'show-timed-cmd': 'false'})
    nodes = ET.SubElement(net, 'nodes')
    arcs = ET.SubElement(net, 'edges')
    # Intermediate encoded states force all actual replies before another action.
    intermediate_count = sum(max(0, len(o.events)-1) for _, _, _, o in edges)
    values = [f's{i}' for i in range(len(states))] + [f'q{i}' for i in range(intermediate_count)]
    ET.SubElement(nodes, 'color-class', name='CState', x='3', y='3', definition='{' + ', '.join(values) + '}')
    ET.SubElement(nodes, 'color-class', name='A_ISN', x='3', y='8', definition='{red, blue}')
    ET.SubElement(nodes, 'color-class', name='S_ISN', x='3', y='13', definition='{pink, purple}')
    ET.SubElement(nodes, 'place', name='COMPLETE_ENDPOINT_MARKING', x='125', y='28', domain='CState', marking='<s0>')
    phase_names = ('LISTEN','SYN_RECV','ESTABLISHED','CLOSE_WAIT','LAST_ACK','FIN_WAIT1','FIN_WAIT2','CLOSING','TIME_WAIT')
    ET.SubElement(nodes, 'color-class', name='TCP_PHASE', x='3', y='18', definition='{' + ', '.join('TCP_'+p for p in phase_names) + '}')

    def projections(state):
        result = {}
        for f in state.flows:
            prefix=f.name.upper()
            result[prefix+'_TCP_PHASE']='<TCP_'+f.phase+'>'
            if f.client is not None:
                result[prefix+'_ATTACKER_ISN']='<'+f.client+'>'
            if f.server is not None:
                result[prefix+'_SERVER_ISN_OPAQUE']='<'+f.server+'>'
        if state.knowledge:
            result['ATTACKER_KNOWN_SERVER_ISNS']=' + '.join('<'+v[2]+'>' for v in state.knowledge)
        old_clients=[f.client for f in state.retired if f.client is not None]
        old_servers=[f.server for f in state.retired if f.server is not None]
        if old_clients:
            result['RETAINED_OLD_ATTACKER_ISNS']=' + '.join('<'+v+'>' for v in old_clients)
        if old_servers:
            result['RETAINED_OLD_SERVER_ISNS']=' + '.join('<'+v+'>' for v in old_servers)
        pending=[p.server for p in state.pending if p.server is not None]
        if pending:
            result['PENDING_UNOBSERVED_SERVER_ISNS']=' + '.join('<'+v+'>' for v in pending)
        return result

    projection_domains={}
    for flow_index, flow_name in enumerate(('F0','F1')):
        for j,(suffix,domain) in enumerate((('TCP_PHASE','TCP_PHASE'),('ATTACKER_ISN','A_ISN'),('SERVER_ISN_OPAQUE','S_ISN'))):
            name=flow_name+'_'+suffix
            projection_domains[name]=(domain,25+flow_index*42,35+j*18)
    for j,(name,domain) in enumerate((('ATTACKER_KNOWN_SERVER_ISNS','S_ISN'),('RETAINED_OLD_ATTACKER_ISNS','A_ISN'),('RETAINED_OLD_SERVER_ISNS','S_ISN'),('PENDING_UNOBSERVED_SERVER_ISNS','S_ISN'))):
        projection_domains[name]=(domain,25+(j%2)*42,103+(j//2)*24)
    initial_projections=projections(states[0])
    for name,(domain,x,y) in projection_domains.items():
        attrs=dict(name=name,x=str(x),y=str(y),domain=domain)
        if name in initial_projections:
            attrs['marking']=initial_projections[name]
        ET.SubElement(nodes,'place',**attrs)

    intermediate = 0
    transition_records = []
    for edge_index, (source, target, action, outcome) in enumerate(edges):
        events = outcome.events or (dict(kind='internal', actor='environment', note=outcome.effect),)
        before = f's{source}'
        for j, event in enumerate(events):
            last = j == len(events)-1
            after = f's{target}' if last else f'q{intermediate}'
            if not last:
                intermediate += 1
            kind = event.get('kind', 'internal')
            actor = event.get('actor', 'environment').upper()
            prefix = f'PACKET_SEND_{actor}' if kind == 'packet' else kind.upper()
            transition = f'{prefix}_E{edge_index:05d}_{j:02d}'
            # Short columns retain practical editor coordinates even for large graph.
            idx = len(transition_records)
            x, y = 175 + 28*(idx//55), 25 + 7*(idx%55)
            ET.SubElement(nodes, 'transition', name=transition, x=str(x), y=str(y), type='IMM')
            ET.SubElement(arcs, 'arc', kind='INPUT', tail='COMPLETE_ENDPOINT_MARKING', head=transition, mult=f'<{before}>')
            ET.SubElement(arcs, 'arc', kind='OUTPUT', tail=transition, head='COMPLETE_ENDPOINT_MARKING', mult=f'<{after}>')
            if j == 0:
                for place,mult in projections(states[source]).items():
                    ET.SubElement(arcs,'arc',kind='INPUT',tail=place,head=transition,mult=mult)
            if last:
                for place,mult in projections(states[target]).items():
                    ET.SubElement(arcs,'arc',kind='OUTPUT',tail=transition,head=place,mult=mult)
            transition_records.append(dict(name=transition, source=before, target=after,
                                           action_edge=edge_index, event=event,
                                           packet_cost=int(kind == 'packet')))
            before = after
    path = output_dir/'tcp_lifecycle.PNPRO'
    ET.indent(project, space='  ')
    ET.ElementTree(project).write(path, encoding='utf-8', xml_declaration=True)
    summary = dict(format='finite_colored_endpoint_state_machine',
                   semantics='same endpoint.step oracle used by offline search; ordered wire-event expansion',
                   completeness='bounded_subgraph' if limit_hits else 'exhausted_finite_profile',
                   limits=dict(max_states=max_states,max_edges=max_edges,max_wait_units=max_wait_units),
                   hit_limits=sorted(limit_hits), states=len(states), intermediate_states=intermediate,
                   action_edges=len(edges), transitions=len(transition_records), projection_places=len(projection_domains),
                   visible_projection_semantics='Complete source projection is consumed on first wire event; complete target projection restored on last event. Intermediate states lock the macro-action.',
                   expanded_states=len(expanded), frontier_states=len(queue),
                   seeded_action_sequences=seed_sequences, seed_states=seed_states, seed_edges=seed_edges,
                   rejected_outside_profile=rejected,
                   native_GreatSPN_open_test=False,
                   cost_note='CPN counts each physical wire event. A,W depend on complete search prefix and are applied by search.py.',
                   exclusions=['full-prefix search labels are external to endpoint marking',
                               'TIME_WAIT early reuse', 'SYN_RECV idle timer exploration',
                               'application stream reconstruction', 'DPI semantics'],
                   sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    state_map = dict(summary=summary,
                     states={f's{i}': asdict(s) for i,s in enumerate(states)},
                     action_edges=[dict(id=i,source=f's{a}',target=f's{b}',action=asdict(c),effect=d.effect)
                                   for i,(a,b,c,d) in enumerate(edges)],
                     transitions=transition_records)
    (output_dir/'cpn_state_map.json').write_text(json.dumps(state_map,indent=2))
    (output_dir/'cpn_export_summary.json').write_text(json.dumps(summary,indent=2))
    validate_export(path, state_map)
    return summary


def validate_export(path, mapping):
    tree = ET.parse(path)
    nodes = tree.find('.//nodes')
    names = [node.attrib['name'] for node in nodes]
    if len(names) != len(set(names)):
        raise AssertionError('duplicate Petri node name')
    node_names = set(names)
    arcs = tree.findall('.//arc')
    for arc in arcs:
        assert arc.attrib['tail'] in node_names and arc.attrib['head'] in node_names
    transitions = mapping['transitions']
    assert len(arcs) >= 2*len(transitions)
    assert len(tree.findall(".//place[@domain='A_ISN']")) >= 3
    assert len(tree.findall(".//place[@domain='S_ISN']")) >= 5
    for item in transitions:
        assert item['name'].startswith('PACKET_SEND_') == bool(item['packet_cost'])
    return dict(xml_valid=True, node_names_unique=True, arc_endpoints_valid=True,
                ordered_packet_firings=True, native_GreatSPN_open_test=False)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',default='results/model')
    parser.add_argument('--max-states',type=int,default=1200)
    parser.add_argument('--max-edges',type=int,default=12000)
    args=parser.parse_args()
    print(json.dumps(export_model(args.out,max_states=args.max_states,max_edges=args.max_edges),indent=2))
