#!/usr/bin/env python3
"""Independent literal-token PNPRO replay and results accounting checks.

This verifier does not import cpn_runtime or the previous endpoint oracle.
It supports only the documented fixed-color, integer-guard PNPRO profile.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def multiset(expression, place):
    expression=(expression or '0').strip()
    if expression in ('', '0'):
        return Counter()
    result=Counter()
    # Literal ordinary multiplicities or sums of literal colored tuples.
    for term in expression.split('+'):
        term=term.strip()
        if re.fullmatch(r'\d+',term):
            count=int(term);color=()
        else:
            m=re.fullmatch(r'(?:(\d+)\s*\*?\s*)?<\s*([\w,\s]+)\s*>',term)
            if not m:
                raise ValueError('Unsupported arc/marking expression: '+expression)
            count=int(m.group(1) or 1)
            color=tuple(s.strip() for s in m.group(2).split(','))
        result[place,color]+=count
    return result


class LiteralCPN:
    def __init__(self, path):
        self.path=Path(path)
        tree=ET.parse(path)
        node_names=[n.attrib['name'] for n in tree.findall('.//nodes/*')]
        assert len(node_names)==len(set(node_names)),'Duplicate native PNPRO node names'
        classes={n.attrib['name']:tuple(x.strip() for x in n.attrib['definition'].strip('{} ').split(','))
                 for n in tree.findall('.//nodes/color-class')}
        self.places={n.attrib['name']:n.attrib for n in tree.findall('.//nodes/place')}
        self.transitions={n.attrib['name']:n.attrib for n in tree.findall('.//nodes/transition')}
        self.initial=Counter()
        self.atoms=[]
        for name,attrs in self.places.items():
            self.initial.update(multiset(attrs.get('marking','0'),name))
            self.atoms.extend((name,(c,)) for c in classes[attrs['domain']]) if attrs.get('domain') else self.atoms.append((name,()))
        self.inputs={name:Counter() for name in self.transitions}
        self.outputs={name:Counter() for name in self.transitions}
        self.inhibitors={name:Counter() for name in self.transitions}
        for arc in tree.findall('.//edges/arc'):
            a=arc.attrib
            tail,head,kind=a['tail'],a['head'],a['kind']
            if kind in ('INPUT','INHIBITOR'):
                assert tail in self.places and head in self.transitions
                dest=self.inputs if kind=='INPUT' else self.inhibitors
                dest[head].update(multiset(a.get('mult','1'),tail))
            elif kind=='OUTPUT':
                assert tail in self.transitions and head in self.places
                self.outputs[tail].update(multiset(a.get('mult','1'),head))
            else:
                raise ValueError('Unsupported arc kind '+kind)
        valid_atoms=set(self.atoms)
        for marking in [self.initial,*self.inputs.values(),*self.outputs.values(),*self.inhibitors.values()]:
            assert all(atom in valid_atoms and count>=0 for atom,count in marking.items()),'Arc/marking color outside declared place domain'

    def count(self, marking, place):
        return sum(v for (p,c),v in marking.items() if p==place)

    def guard(self, marking, expression):
        if not expression or expression.lower() in ('true','1'):
            return True
        values={}
        def count_name(match):
            name=match.group(1)
            assert name in self.places, name
            key='p'+str(len(values))
            values[key]=self.count(marking,name)
            return key
        src=re.sub(r'#([A-Za-z_]\w*)',count_name,expression)
        src=src.replace('&&',' and ').replace('||',' or ')
        src=re.sub(r'!(?!=)',' not ',src).strip()
        tree=ast.parse(src,mode='eval')
        allowed=(ast.Expression,ast.BoolOp,ast.And,ast.Or,ast.UnaryOp,ast.Not,
                 ast.Compare,ast.Eq,ast.NotEq,ast.Lt,ast.LtE,ast.Gt,ast.GtE,
                 ast.Name,ast.Load,ast.Constant,ast.BinOp,ast.Add,ast.Sub)
        assert all(isinstance(n,allowed) for n in ast.walk(tree)),src
        assert all(n.id in values for n in ast.walk(tree) if isinstance(n,ast.Name)),src
        return bool(eval(compile(tree,'<literal-cpn-guard>','eval'),{'__builtins__':{}},values))

    def enabled(self, marking, name):
        assert name in self.transitions,name
        if any(marking[k]<v for k,v in self.inputs[name].items()):
            return False
        if any(marking[k]>=v for k,v in self.inhibitors[name].items()):
            return False
        return self.guard(marking,self.transitions[name].get('guard',''))

    def fire(self, marking, name):
        if not self.enabled(marking,name):
            raise AssertionError('Transition not enabled in independent XML replay: '+name)
        after=marking.copy()
        after.subtract(self.inputs[name]);after.update(self.outputs[name])
        assert min(after.values(),default=0)>=0
        return +after

    def replay(self, names):
        marking=self.initial.copy()
        for name in names:
            marking=self.fire(marking,name.split()[0])
        return marking

    def vector(self,marking):
        return [marking[k] for k in self.atoms]


def search_cost_fixture(search_file):
    spec=importlib.util.spec_from_file_location('independent_modified_search',search_file)
    module=importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name]=module;spec.loader.exec_module(module)
    def successor(state):
        n,seen,done=state
        if done:return
        yield 'PACKET_SEND_FINISH',(n,seen,True),1
        if n<2:
            yield 'PACKET_SEND_PROBE',(n+1,True,False),1
    def weight(name,before,after):
        return 1 if name=='PACKET_SEND_FINISH' else 4 if before[1] else 2
    answers=[]
    session=module.SequenceSearchSession((0,False,False),successor,lambda s:s,
        lambda s:s[2],contextual_edge_cost=weight)
    stats=session.run(module.Limits(k=3,max_expansions=100,max_queue=100,seconds=10),
        on_sequence=lambda rank,cost,names:answers.append((cost,names)))
    assert stats.status=='found_k',stats
    assert [c for c,n in answers]==[1,3,7],answers
    assert answers[-1][1]==['PACKET_SEND_PROBE','PACKET_SEND_PROBE','PACKET_SEND_FINISH']
    return {'contextual_repeat_costs':[c for c,n in answers],
            'same_transition_name_distinct_history_cost':True}


def protocol_fixtures(net):
    slot='F0_G0'
    setup=['PACKET_SEND_ATTACKER_F0_G0_SYN','PACKET_SEND_SERVER_F0_G0_SYNACK_LEARN',
           'PACKET_SEND_ATTACKER_F0_G0_ACK_ESTABLISH']
    def has(marking,place,color=()):
        return marking[place,color if isinstance(color,tuple) else (color,)]
    def run(names):return net.replay(names)
    def fire(marking,name):return net.fire(marking,name)
    tested=[]
    for stem in ('VISIBILITY_S_LISTEN','CHECKSUM_S_LISTEN','VISIBILITY_CHECKSUM_S_LISTEN'):
        m=run(['PACKET_SEND_ATTACKER_F0_G0_'+stem])
        assert m==net.initial,stem+' changes endpoint or knowledge'
        assert not any('PACKET_SEND_SERVER_' in t and net.enabled(m,t) for t in net.transitions)
        tested.append(stem)
    pre_synack=run(setup[:1]);artificial=pre_synack.copy();artificial['ATTACKER_READY',()]=1
    assert not net.enabled(artificial,setup[2]),'Missing server-ISN knowledge guard'
    tested.append('unknown_server_ISN_ack_forbidden')
    known=run(setup[:2]);assert has(known,slot+'_KNOWS_SERVER','pink')==1
    tested.append('knowledge_only_after_genuine_SYNACK')
    established=run(setup);assert has(established,slot+'_ESTABLISHED')==1
    tested.append('settled_establishment')
    ttl=fire(established,'PACKET_SEND_ATTACKER_F0_G0_READOUT_DPI_ONLY')
    assert has(ttl,slot+'_DATA_EMPTY')==1 and has(ttl,slot+'_DATA_SEEN')==0,'TTL readout modified Linux data state'
    assert has(ttl,slot+'_REPLY_A')==0 and has(ttl,'ATTACKER_READY')==1
    tested.append('DPI_only_readout_no_TCP_effect_or_reply')
    full=fire(established,'PACKET_SEND_ATTACKER_F0_G0_READOUT_FULL')
    assert has(full,slot+'_DATA_EMPTY')==0 and has(full,slot+'_DATA_SEEN')==1
    assert has(full,slot+'_REPLY_A')==1 and has(full,'ATTACKER_READY')==0
    tested.append('full_readout_ack_is_mandatory')
    base=setup+['SERVER_APPLICATION_CLOSE_F0_G0_ESTABLISHED','PACKET_SEND_SERVER_F0_G0_FA']
    fw=run(base+['PACKET_SEND_ATTACKER_F0_G0_ACK_SEQ_IN_WINDOW_FIN_WAIT1'])
    assert has(fw,slot+'_FIN_WAIT2')==1,'In-window ACK fails to acknowledge server FIN'
    tested.append('inwindow_ack_advances_FIN_WAIT1')
    simultaneous=base+['PACKET_SEND_ATTACKER_F0_G0_FIN_SIMULTANEOUS_UNACKED','PACKET_SEND_SERVER_F0_G0_A']
    closing=run(simultaneous+['PACKET_SEND_ATTACKER_F0_G0_ACK_SEQ_IN_WINDOW_CLOSING'])
    assert has(closing,slot+'_TIME_WAIT')==1,'In-window ACK fails to complete CLOSING'
    tested.append('inwindow_ack_advances_CLOSING')
    passive=setup+['PACKET_SEND_ATTACKER_F0_G0_FIN_PASSIVE','PACKET_SEND_SERVER_F0_G0_A',
                   'SERVER_APPLICATION_CLOSE_F0_G0_CLOSE_WAIT','PACKET_SEND_SERVER_F0_G0_FA']
    ordinary_last=run(passive+['PACKET_SEND_ATTACKER_F0_G0_ACK_PASSIVE_CLOSE_COMPLETE'])
    assert has(ordinary_last,slot+'_CLOSED')==1 and has(ordinary_last,'ATTACKER_READY')==1
    tested.append('ordinary_passive_close_without_wait')
    last=run(passive+['PACKET_SEND_ATTACKER_F0_G0_ACK_SEQ_IN_WINDOW_LAST_ACK'])
    assert has(last,slot+'_CLOSED')==1,'In-window ACK fails to complete LAST_ACK'
    tested.append('inwindow_ack_advances_LAST_ACK')
    challenge=fire(established,'PACKET_SEND_ATTACKER_F0_G0_RST_IN_WINDOW_ESTABLISHED')
    assert has(challenge,slot+'_ESTABLISHED')==1 and has(challenge,slot+'_REPLY_A')==1
    reset=fire(established,'PACKET_SEND_ATTACKER_F0_G0_RST_EXACT_ESTABLISHED')
    assert has(reset,slot+'_CLOSED')==1
    tested.append('exact_vs_inwindow_reset')
    same=setup+['PACKET_SEND_ATTACKER_F0_G0_CLEANUP_RST_ESTABLISHED',
                'PACKET_SEND_ATTACKER_F0_G1_SYN','PACKET_SEND_SERVER_F0_G1_SYNACK_LEARN',
                'PACKET_SEND_ATTACKER_F0_G1_ACK_ESTABLISH']
    reincarnated=run(same)
    assert has(reincarnated,'F0_G0_KNOWS_SERVER','pink')==1 and has(reincarnated,'F0_G1_KNOWS_SERVER','purple')==1
    assert not net.enabled(reincarnated,'PACKET_SEND_ATTACKER_F1_G1_SYN'),'More than two real incarnations enabled'
    tested.append('retained_knowledge_and_global_incarnation_bound')
    return {'count':len(tested),'checks':tested}


def independent_path(net,annotations,profile,path,*,goal=None):
    transitions=path['transitions']
    marking=net.initial.copy();N=A=W=T=0;labels=set();expected_events=[]
    checkpoint=None;readout_count=0;slots=profile['slots'];phase_names=profile['phases']
    def has(m,p,c=()):return m[p,c if isinstance(c,tuple) else (c,)]
    for i,name in enumerate(transitions):
        name=name.split()[0];meta=annotations[name];before=marking
        if meta.get('purpose')=='readout':
            assert checkpoint is None,'Multiple readouts'
            checkpoint=before.copy();readout_count+=1
            slot=meta['slot'];info=slots[slot]
            assert has(before,slot+'_ESTABLISHED')==1 and has(before,'ATTACKER_READY')==1
            assert has(before,'G0_EVER_EST')>=1
            if goal=='establish':assert info['generation']==0 and has(before,'G0_LEFT_EST')==0
            elif goal=='reconnect_same':assert info['generation']==1 and info['flow']=='f0' and has(before,'G0_LEFT_EST')>=1
            elif goal=='reconnect_different':assert info['generation']==1 and info['flow']=='f1' and has(before,'G0_LEFT_EST')>=1
            if 'prefix_transitions' in path:
                assert path['prefix_transitions']==transitions[:i]
            if 'checkpoint_marking' in path:
                assert path['checkpoint_marking']==net.vector(before),'Checkpoint marking differs'
        if meta.get('actor')=='attacker' and meta.get('kind')=='packet' and meta.get('server'):
            scope='F0_G0' if meta.get('old_reference') else meta['slot']
            assert has(before,scope+'_KNOWS_SERVER',meta['server'])==1,('unknown server ISN',name)
        marking=net.fire(marking,name)
        assert has(marking,'ATTACKER_READY')+sum(v for (p,c),v in marking.items() if '_REPLY_' in p)==1,'Wire-event serialization broken'
        for slot in slots:
            assert sum(has(marking,slot+'_'+ph) for ph in phase_names)==1,'Endpoint has multiple/no phases'
            assert net.count(marking,slot+'_KNOWS_SERVER')<=1,'Knowledge duplicates'
        if meta.get('kind')=='packet':
            N+=1
            if meta.get('actor')=='attacker' and not meta.get('ordinary_progress'):
                A+=1;label=meta.get('decision_label')
                assert label,'Unusual packet missing designated decision'
                W+=int(label in labels);labels.add(label)
            if meta.get('actor')=='attacker' and (meta.get('delivery')=='dpi_only' or meta.get('checksum')=='invalid'):
                assert {k:v for k,v in marking.items() if k[0]!='READOUT_USED'}=={k:v for k,v in before.items() if k[0]!='READOUT_USED'},'Invisible/rejected packet changes endpoint marking'
        elif meta.get('kind')=='wait':T+=int(meta.get('wait_units',1))
        if meta.get('kind') in ('packet','wait','observation'):expected_events.append(name)
    assert readout_count==1 and checkpoint is not None,'Completed measurement lacks one readout'
    assert has(marking,'READOUT_USED')==1 and has(marking,'ATTACKER_READY')==1
    for slot in slots:
        assert sum(has(marking,slot+'_'+p) for p in ('DORMANT','LISTEN','CLOSED'))==1,'Endpoint state left after cleanup'
    if 'final_marking' in path:assert path['final_marking']==net.vector(marking),'Final marking differs'
    costs={'N':N,'A':A,'W':W,'T':T,'kappa':1,'total':N+A+2*W+T}
    if 'cost' in path:assert path['cost']==costs,('Cost differs',path['cost'],costs)
    event_list=path.get('history',path.get('events'))
    if event_list is not None:
        assert [e['transition'] for e in event_list]==expected_events,'Event transcript differs from CPN firing word'
        assert sum(e.get('kind')=='packet' for e in event_list)==N
        assert all(e.get('dpi_processing','unmeasured')=='unmeasured' for e in event_list)
    return costs


def verify_outputs(net,model_path,results,expected_count=None):
    ann=json.loads(model_path.with_name('annotations.json').read_text());annotations=ann['transitions'];profile=ann['profile']
    file=results/'plans.json'
    paths=json.loads(file.read_text()) if file.exists() else [json.loads(x) for x in (results/'raw_paths.jsonl').read_text().splitlines() if x.strip()]
    if expected_count is not None:assert len(paths)==expected_count,(len(paths),expected_count)
    signatures=set();goals=Counter();costs=Counter();firings=conditions=0;control_costs=set()
    fields=('actor','flags','flow','generation','client','server','seq','ack','delivery','checksum','payload')
    for path in paths:
        cost=independent_path(net,annotations,profile,path,goal=path['goal'])
        signature=tuple(tuple(str(e.get(k,'')) for k in fields) for e in path['history'] if e.get('kind')=='packet')
        assert signature not in signatures,'Duplicate physical packet sequence';signatures.add(signature)
        if path.get('packet_signature'):
            assert path['packet_signature']==hashlib.sha256(json.dumps(signature,separators=(',',':')).encode()).hexdigest()
        goals[path['goal']]+=1;costs[cost['total']]+=1;firings+=len(path['transitions'])
        assert path.get('Y') is None
        if 'conditions' in path:
            rows=path['conditions'];assert len(rows)==4
            assert {(c['history'],c['hostname_class']) for c in rows}=={(h,s) for h in ('ordinary','candidate') for s in ('benign','blocked')}
            history_refs=path.get('condition_histories',{})
            for c in rows:
                assert c['Y'] is None and c['status']=='unmeasured'
                ref=c.get('history_ref',c['history']);trace=history_refs.get(ref,{})
                trace={'transitions':path['transitions'],'events':path['history'],'cost':path['cost']} if ref=='candidate' else trace
                if c.get('transitions'):trace=c
                assert trace.get('transitions'),'Control condition has no replayable CPN transition sequence'
                cc=independent_path(net,annotations,profile,trace,goal=path['goal'])
                assert c['cost']==cc
                readout=next(annotations[n] for n in trace['transitions'] if annotations[n].get('purpose')=='readout')
                assert c['readout_delivery']==readout['delivery']==path['readout_delivery']
                assert cc['T']==cost['T'],'Wait units not matched across controls'
                conditions+=1;firings+=len(trace['transitions'])
                control_costs.add((cc['N'],cc['T'],cc['total']))
            repeats=path.get('trial_repetitions',3)
            assert path['execution_resource_proxy']==repeats*sum(c['cost']['N']+c['cost']['T'] for c in rows)
    metadata_path=results/'search_metadata.json'
    if metadata_path.exists():
        metadata=json.loads(metadata_path.read_text());digest=hashlib.sha256(model_path.read_bytes()).hexdigest()
        assert metadata['model_sha256_before_search']==metadata['model_sha256_after_search']==digest,'Model changed after/between search'
        assert metadata['model_created_before_search'] and metadata['successor_source']=='PNPRO XML arcs and guards'
        assert not metadata['native_GreatSPN_executed'] and metadata['packets_transmitted']==0
    return {'paths':len(paths),'unique_physical_packet_sequences':len(signatures),'conditions':conditions,
            'goal_counts':dict(goals),'cost_range':[min(costs),max(costs)],'literal_transition_firings':firings,
            'distinct_control_cost_profiles':len(control_costs)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',type=Path)
    parser.add_argument('--results',type=Path,default=Path(__file__).with_name('results'))
    parser.add_argument('--expected-count',type=int)
    args=parser.parse_args()
    report={'status':'PASS','native_GreatSPN_validation':False,
            'scope':'Independent literal-color token arithmetic over supplied PNPRO, not full GreatSPN syntax validation.'}
    report['search_fixture']=search_cost_fixture(Path(__file__).with_name('greatspn_paths.py'))
    if args.model:
        net=LiteralCPN(args.model)
        report['model_sha256']=hashlib.sha256(args.model.read_bytes()).hexdigest()
        report['places']=len(net.places);report['transitions']=len(net.transitions)
        report['protocol_fixtures']=protocol_fixtures(net)
        if (args.results/'plans.json').exists() or (args.results/'raw_paths.jsonl').exists():
            report['results']=verify_outputs(net,args.model,args.results,args.expected_count)
            (args.results/'verification.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
