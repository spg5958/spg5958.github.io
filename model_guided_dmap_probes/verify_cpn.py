#!/usr/bin/env python3
"""Independent token-firing checks on the exported PNPRO XML; no network/native Java."""
from collections import Counter, defaultdict
import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def parse_tokens(place, expression):
    # Exporter uses sums of literal unit color tuples only, never variables.
    if not expression:
        return Counter()
    tokens = re.findall(r'<([^>]+)>', expression)
    remainder = re.sub(r'<[^>]+>', '', expression).replace('+','').strip()
    if remainder:
        raise AssertionError(f'Unsupported nonliteral multiset expression {expression}')
    return Counter((place, token.strip()) for token in tokens)


def stable_marking(state_id, state):
    marking=Counter({('COMPLETE_ENDPOINT_MARKING',state_id):1})
    for flow in state['flows']:
        prefix=flow['name'].upper()
        marking[(prefix+'_TCP_PHASE','TCP_'+flow['phase'])]+=1
        if flow['client'] is not None:
            marking[(prefix+'_ATTACKER_ISN',flow['client'])]+=1
        if flow['server'] is not None:
            marking[(prefix+'_SERVER_ISN_OPAQUE',flow['server'])]+=1
    for _,_,server in state['knowledge']:
        marking[('ATTACKER_KNOWN_SERVER_ISNS',server)]+=1
    for flow in state['retired']:
        if flow['client'] is not None:
            marking[('RETAINED_OLD_ATTACKER_ISNS',flow['client'])]+=1
        if flow['server'] is not None:
            marking[('RETAINED_OLD_SERVER_ISNS',flow['server'])]+=1
    for pending in state['pending']:
        if pending['server'] is not None:
            marking[('PENDING_UNOBSERVED_SERVER_ISNS',pending['server'])]+=1
    return marking


def verify(model_dir, plans_path=None):
    model_dir=Path(model_dir)
    mapping=json.loads((model_dir/'cpn_state_map.json').read_text())
    root=ET.parse(model_dir/'tcp_lifecycle.PNPRO').getroot()
    inputs=defaultdict(Counter)
    outputs=defaultdict(Counter)
    for arc in root.findall('.//arc'):
        attrs=arc.attrib
        if attrs['kind']=='INPUT':
            inputs[attrs['head']].update(parse_tokens(attrs['tail'],attrs.get('mult')))
        elif attrs['kind']=='OUTPUT':
            outputs[attrs['tail']].update(parse_tokens(attrs['head'],attrs.get('mult')))
        else:
            raise AssertionError('Unexpected arc type')
    initial=Counter()
    for place in root.findall('.//place'):
        initial.update(parse_tokens(place.attrib['name'],place.attrib.get('marking')))
    assert initial==stable_marking('s0',mapping['states']['s0'])
    by_edge=defaultdict(list)
    for transition in mapping['transitions']:
        by_edge[transition['action_edge']].append(transition)

    def fire(marking, transition):
        name=transition['name']
        if inputs[name]-marking:
            raise AssertionError(f'Nonenabled transition {name}: {inputs[name]-marking}')
        marking.subtract(inputs[name])
        marking.update(outputs[name])
        marking=+marking
        assert sum(n for (place,_),n in marking.items() if place=='COMPLETE_ENDPOINT_MARKING')==1
        assert all(n>0 for n in marking.values())
        return marking

    knowledge_checks=0
    for edge in mapping['action_edges']:
        source=mapping['states'][edge['source']]
        target=mapping['states'][edge['target']]
        marking=stable_marking(edge['source'],source)
        chain=by_edge[edge['id']]
        assert chain
        for transition in chain:
            marking=fire(marking,transition)
        assert marking==stable_marking(edge['target'],target),edge['id']
        before={tuple(x) for x in source['knowledge']}
        after={tuple(x) for x in target['knowledge']}
        assert before<=after,'knowledge was forgotten'
        explained=set()
        if edge['action']['kind']=='deliver_pending':
            assert source['pending']
            pending=source['pending'][0]
            if pending['server'] is not None:
                explained.add((pending['flow'],pending['generation'],pending['server']))
        for transition in chain:
            event=transition['event']
            if (event.get('kind')=='packet' and event.get('actor')=='server'
                and event.get('observed_by_attacker') and 'R' not in event.get('flags','')
                and event.get('server') is not None):
                explained.add((event['flow'],event['generation'],event['server']))
        assert after-before <= explained,('uncaused server-ISN knowledge',edge['id'])
        if edge['action']['delivery']=='dpi_only' or edge['action']['checksum']=='invalid':
            if edge['action']['kind']=='packet':
                assert before==after,'invisible/rejected packet invented knowledge'
                assert not any(t['event'].get('actor')=='server' and t['event'].get('kind')=='packet' for t in chain)
        knowledge_checks+=1

    seed_sequences=seed_firings=0
    if plans_path is not None:
        plans=json.loads(Path(plans_path).read_text())
        if isinstance(plans,dict):
            plans=plans['plans']
        lookup={}
        for edge in mapping['action_edges']:
            key=(edge['source'],json.dumps(edge['action'],sort_keys=True))
            if key in lookup:
                assert lookup[key]['target']==edge['target'],'unexpected nondeterminism'
            lookup[key]=edge
        sequences=[]
        for plan in plans:
            sequences.append(plan['actions'])
            for condition in plan.get('conditions',[]):
                sequences.append(condition['actions'])
        for sequence in sequences:
            source='s0'
            marking=initial.copy()
            for action in sequence:
                edge=lookup.get((source,json.dumps(action,sort_keys=True)))
                assert edge is not None,('missing exported action',source,action)
                for transition in by_edge[edge['id']]:
                    marking=fire(marking,transition)
                    seed_firings+=1
                source=edge['target']
            assert marking==stable_marking(source,mapping['states'][source])
            seed_sequences+=1
    summary=dict(status='passed',xml_state_token_firings=True,
                 all_action_edges_replayed=len(mapping['action_edges']),
                 all_packet_and_internal_transitions_fired=len(mapping['transitions']),
                 live_colored_projections_verified=True,
                 knowledge_causality_edges_checked=knowledge_checks,
                 generated_plan_and_condition_sequences_replayed=seed_sequences,
                 generated_sequence_total_transition_firings=seed_firings,
                 native_GreatSPN_parser_or_simulator=False,
                 scope='independent literal-colored-token replay of exported XML; not native GreatSPN syntax/runtime validation')
    (model_dir/'cpn_verification.json').write_text(json.dumps(summary,indent=2))
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',default=str(Path(__file__).parent/'model'))
    parser.add_argument('--plans',default=str(Path(__file__).parent/'results/plans.json'))
    args=parser.parse_args()
    print(json.dumps(verify(args.model,args.plans),indent=2))
