#!/usr/bin/env python3
"""Weighted complete-prefix search using the user's SequenceSearchSession.

Every successor marking is fired from the supplied, already-created PNPRO XML.
Search state adds history-sensitive accounting and bounds, never TCP effects.
"""
from __future__ import annotations
import argparse
from collections import Counter
from dataclasses import dataclass, asdict
import gc
import hashlib
import heapq
import json
from pathlib import Path
from time import perf_counter

from cpn_runtime import CPNModel
from greatspn_paths import SequenceSearchSession, Limits


@dataclass(frozen=True, slots=True)
class SearchState:
    marking: tuple
    labels: frozenset = frozenset()
    N: int = 0
    A: int = 0
    W: int = 0
    T: int = 0
    firings: int = 0
    stage: str = 'history'
    checkpoint_slot: str = ''
    checkpoint_marking: tuple = ()
    checkpoint_firings: int = 0
    readout_delivery: str = ''

    @property
    def cost(self):
        return self.N+self.A+2*self.W+self.T


class FoundPacketQuota(Exception):
    pass


class Query:
    def __init__(self, model, goal, *, ordinary_only=False, readout_delivery=None,
                 max_packets=32, max_actions=48, max_waits=2, max_departures=2):
        self.model=model
        self.goal=goal
        self.ordinary_only=ordinary_only
        self.readout_delivery=readout_delivery
        self.max_packets=max_packets
        self.max_actions=max_actions
        self.max_waits=max_waits
        self.max_departures=max_departures
        self.pruned=Counter()
        self.potential=None

    def checkpoint(self, marking):
        for item in self.model.checkpoint(marking):
            generation=item.get('generation',item.get('incarnation',0))
            if isinstance(generation,str):
                generation=int(generation.removeprefix('g'))
            flow=item.get('flow',item.get('name'))
            if self.goal=='establish' and generation==0:
                return item
            if self.goal=='reconnect_same' and generation==1 and flow=='f0' and self.model.tokens(marking,'G0_LEFT_EST'):
                return item
            if self.goal=='reconnect_different' and generation==1 and flow=='f1' and self.model.tokens(marking,'G0_LEFT_EST'):
                return item
        return None

    @staticmethod
    def ordinary(meta):
        return bool(meta.get('ordinary_progress',meta.get('actor')=='server' or meta.get('kind')!='packet'))

    @staticmethod
    def decision(meta):
        if Query.ordinary(meta):
            return None
        return meta.get('decision_label') or '|'.join(str(meta.get(k,'')) for k in
            ('family','phase','flags','seq_relation','ack_relation','generation','delivery','checksum'))

    def allowed(self,before,after,stage,meta,relax_ordinary=False):
            purpose=meta.get('purpose','normal')
            checkpoint=self.checkpoint(before)
            if self.ordinary_only and not relax_ordinary and not self.ordinary(meta):
                return False
            if stage=='history':
                if purpose=='cleanup':
                    return False
                if purpose=='readout':
                    if checkpoint is None or meta.get('slot')!=checkpoint['slot']:
                        return False
                    if self.readout_delivery and meta.get('delivery')!=self.readout_delivery:
                        return False
                # Once first EST has been left, its original incarnation cannot
                # satisfy the first-establishment checkpoint again.
                if self.goal=='establish' and self.model.tokens(after,'G0_LEFT_EST'):
                    return False
                # Select the requested four-tuple for the second incarnation.
                if meta.get('generation')==1 and meta.get('actor')=='attacker':
                    target='f0' if self.goal=='reconnect_same' else 'f1'
                    if self.goal=='establish' or meta.get('flow')!=target:
                        return False
            else:
                # Real forced replies and internal processing remain enabled.
                # New experiment traffic is forbidden after its readout.
                if meta.get('actor')=='attacker' and meta.get('kind')=='packet' and purpose!='cleanup':
                    return False
                if purpose=='readout':
                    return False
            return True

    def successors(self, state):
        for name,marking,_ in self.model.successors(state.marking):
            meta=self.model.annotations[name]
            purpose=meta.get('purpose','normal')
            if not self.allowed(state.marking,marking,state.stage,meta):
                continue
            checkpoint=self.checkpoint(state.marking)
            ordinary=self.ordinary(meta)
            label=self.decision(meta)
            a=int(meta.get('kind')=='packet' and meta.get('actor')=='attacker' and not ordinary)
            w=int(a and label in state.labels)
            n=int(meta.get('kind')=='packet')
            t=int(meta.get('wait_units',1)) if meta.get('kind')=='wait' else 0
            N,A,W,T=state.N+n,state.A+a,state.W+w,state.T+t
            if N>self.max_packets or A>self.max_departures or T>self.max_waits or state.firings+1>self.max_actions:
                self.pruned['path_bounds']+=1
                continue
            stage=state.stage;slot=state.checkpoint_slot;cp=state.checkpoint_marking;cf=state.checkpoint_firings
            delivery=state.readout_delivery
            if purpose=='readout':
                stage='cleanup';slot=checkpoint['slot'];cp=state.marking;cf=state.firings;delivery=meta['delivery']
            labels=state.labels|({label} if label else set())
            child=SearchState(marking,frozenset(labels),N,A,W,T,state.firings+1,stage,slot,cp,cf,delivery)
            if self.potential is not None and (child.marking,child.stage) not in self.potential:
                self.pruned['no_abstract_completion']+=1
                continue
            yield name,child,1

    def goal_reached(self,state):
        return state.stage=='cleanup' and self.model.idle(state.marking)

    def replay(self,names):
        state=SearchState(self.model.initial())
        states=[state]
        for name in names:
            state=next((s for n,s,c in self.successors(state) if n==name),None)
            if state is None:
                raise ValueError('Path is not enabled under CPN query: '+name)
            states.append(state)
        return states


def cost_dict(state):
    return {'N':state.N,'A':state.A,'W':state.W,'T':state.T,'kappa':1,'total':state.cost}


def packet_signature(history):
    # Wait placement and internal handler firings do not manufacture distinct
    # packet sequences. Header symbols, incarnation and delivery are retained.
    fields=('actor','flags','flow','generation','client','server','seq','ack','delivery','checksum','payload')
    return tuple(tuple(str(event.get(k,'')) for k in fields) for event in history if event.get('kind')=='packet')


def cpn_potential(query):
    """Exact remaining N+T distance in a relaxation of the same CPN query.

    Discarding A/W, seen labels and history budgets can only lower remaining
    cost. For every original edge ΔC >= N_edge+T_edge and h(u)<=N_edge+T_edge+h(v),
    so ΔC+h(v)-h(u)>=0. Complete goals have h=0: Dijkstra on the reweighted
    edges emits complete paths in the same order as the actual weighted C.
    """
    initial=(query.model.initial(),'history')
    states=[initial];ids={initial:0};reverse=[[]];goals=[];edge_count=0
    for before,stage in states:
        source=ids[before,stage]
        if stage=='cleanup' and query.model.idle(before):
            goals.append(source)
        for name,after,_ in query.model.successors(before):
            meta=query.model.annotations[name]
            if not query.allowed(before,after,stage,meta,relax_ordinary=True):
                continue
            target_stage='cleanup' if meta.get('purpose')=='readout' else stage
            key=(after,target_stage)
            if key not in ids:
                ids[key]=len(states);states.append(key);reverse.append([])
                if len(states)>50000:
                    raise RuntimeError('CPN lower-bound graph exceeds explicit state budget')
            weight=int(meta.get('kind')=='packet')+(int(meta.get('wait_units',1)) if meta.get('kind')=='wait' else 0)
            reverse[ids[key]].append((source,weight));edge_count+=1
    distances={g:0 for g in goals};queue=[(0,g) for g in goals];heapq.heapify(queue)
    while queue:
        cost,current=heapq.heappop(queue)
        if cost!=distances[current]:continue
        for source,weight in reverse[current]:
            candidate=cost+weight
            if candidate<distances.get(source,float('inf')):
                distances[source]=candidate;heapq.heappush(queue,(candidate,source))
    h={states[i]:d for i,d in distances.items()}
    if initial not in h:
        raise RuntimeError('CPN query has no relaxed completion')
    return h,{'states':len(states),'edges':edge_count,'goals':len(goals),'initial_lower_bound':h[initial],
              'method':'reverse Dijkstra on CPN marking/readout-stage graph with N+T edge costs'}


def record(model,query,names,states,rank):
    last=states[-1];events=[];prefix=[]
    for i,name in enumerate(names):
        items=model.events(states[i].marking,name,states[i+1].marking)
        for event in items:
            e=dict(event);e['action_index']=i;e['ordinary_progress']=Query.ordinary(model.annotations[name])
            if e.get('kind') in ('packet','wait','observation'):
                events.append(e)
                if i<last.checkpoint_firings:
                    prefix.append(e)
    info=dict(model.profile['slots'][last.checkpoint_slot])
    info.update(slot=last.checkpoint_slot,name=info.get('flow'),phase='ESTABLISHED')
    labels=sorted(last.labels)
    families=list(dict.fromkeys(model.annotations[n].get('family','control_validation') for n in names if Query.decision(model.annotations[n]))) or ['ordinary']
    family=families[0]
    sig=packet_signature(events)
    return {'goal':query.goal,'search_rank':rank,'title':query.goal.replace('_',' ')+' / '+', '.join(families),
        'family':family,'families':families,'decision_phase':'CPN-defined','labels':labels,
        'cost':cost_dict(last),'history':events,'prefix_history':prefix,
        'transitions':list(names),'prefix_transitions':list(names[:last.checkpoint_firings]),
        'checkpoint':info,'checkpoint_marking':list(last.checkpoint_marking),
        'checkpoint_summary':model.summary(last.checkpoint_marking),
        'final_marking':list(last.marking),'final_summary':model.summary(last.marking),
        'readout_delivery':last.readout_delivery,'native_GreatSPN_executed':False,
        'packet_signature':hashlib.sha256(json.dumps(sig,separators=(',',':')).encode()).hexdigest()}


def enumerate_query(model,goal,k,*,seconds=120,max_expansions=500000,max_queue=160000,
                    ordinary_only=False,readout_delivery=None,on_result=None,max_waits=2):
    query=Query(model,goal,ordinary_only=ordinary_only,readout_delivery=readout_delivery,max_waits=max_waits)
    query.potential,potential_stats=cpn_potential(query)
    seen=set();results=[]
    def weighted_edge(name,before,after):
        value=(after.cost-before.cost)+query.potential[after.marking,after.stage]-query.potential[before.marking,before.stage]
        assert value>=0,'Negative reweighted edge violates lower-bound consistency'
        return value
    session=SequenceSearchSession(SearchState(model.initial()),query.successors,lambda s:s,
        query.goal_reached,contextual_edge_cost=weighted_edge)
    def variant(rank,variant,names,states):
        p=record(model,query,names,states,rank)
        sig=p['packet_signature']
        if sig not in seen:
            if results:assert p['cost']['total']>=results[-1]['cost']['total']
            seen.add(sig);results.append(p)
            if on_result:on_result(p)
        if len(results)>=k:
            raise FoundPacketQuota()
    def progress(stats,pending):
        print(f'{goal}: unique={len(results)}/{k} firing_words={stats.found} expanded={stats.expanded} queue={pending}',flush=True)
    try:
        stats=session.run(Limits(k=max(2000,k*30),max_expansions=max_expansions,
            max_queue=max_queue,seconds=seconds,cache_states=10000),on_variant=variant,on_progress=progress)
    except FoundPacketQuota:
        stats=session.stats;stats.status='found_unique_packet_k'
        # This model has fixed literal bindings, so each firing word has one variant.
        stats.variants_complete=True
    result_stats=asdict(stats)
    result_stats.update(goal=goal,unique_packet_paths=len(results),requested_packet_paths=k,
        duplicate_firing_words_skipped=stats.found-len(results),frontier_remaining=len(session.queue),
        bound_pruning=dict(query.pruned),search='supplied SequenceSearchSession with contextual edge weights and CPN remaining-cost potential',potential=potential_stats)
    del session
    gc.collect()
    return results,result_stats


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--model',type=Path,default=Path(__file__).with_name('model')/'model_guided_tcp_handshake.PNPRO')
    ap.add_argument('--output',type=Path,default=Path(__file__).with_name('results'))
    ap.add_argument('--k',type=int,default=1000)
    ap.add_argument('--seconds',type=float,default=150)
    ap.add_argument('--max-expansions',type=int,default=500000)
    ap.add_argument('--max-queue',type=int,default=160000)
    args=ap.parse_args()
    model=CPNModel(args.model);args.output.mkdir(parents=True,exist_ok=True)
    start=perf_counter();baselines={}
    for goal in ('establish','reconnect_same','reconnect_different'):
        for delivery in ('full','dpi_only'):
            rows,stats=enumerate_query(model,goal,1,seconds=30,ordinary_only=True,readout_delivery=delivery,max_waits=0)
            if not rows:
                raise RuntimeError(f'No CPN ordinary baseline for {goal}/{delivery}: {stats}')
            b=rows[0];baselines[goal+'|'+delivery]={'transitions':b['transitions'],'events':b['history'],'cost':b['cost']}
    (args.output/'baselines.json').write_text(json.dumps(baselines,indent=2))
    paths=[];stats=[];targets=[args.k//3+(i<args.k%3) for i in range(3)]
    raw=args.output/'raw_paths.jsonl'
    with raw.open('w') as stream:
        for goal,target in zip(('establish','reconnect_same','reconnect_different'),targets):
            def save(p):
                p['id']=f'P{len(paths)+1:04d}';paths.append(p)
                stream.write(json.dumps(p)+'\n');stream.flush()
            _,st=enumerate_query(model,goal,target,seconds=args.seconds,
                max_expansions=args.max_expansions,max_queue=args.max_queue,on_result=save)
            stats.append(st)
    signatures={p['packet_signature'] for p in paths}
    assert len(signatures)==len(paths),'Packet signatures duplicated between lifecycle goals'
    metadata={'title':'Model-guided TCP handshake probes for dMAP','path_count':len(paths),
        'requested_paths':args.k,'search_stats':stats,'elapsed_seconds':round(perf_counter()-start,3),
        'model_file':str(args.model),'model_sha256_before_search':model.sha256,
        'model_sha256_after_search':hashlib.sha256(args.model.read_bytes()).hexdigest(),
        'model_created_before_search':True,'successor_source':'PNPRO XML arcs and guards',
        'engine_source':'user-supplied greatspn_paths(1).py SequenceSearchSession, modified for context edge weights',
        'native_GreatSPN_executed':False,'kappa':1,'cost_formula':'N+A+2W+kappa*T',
        'packets_transmitted':0,'dpi_outcomes_measured':False,'complete':False,
        'configuration':{'target_per_goal':dict(zip(('establish','reconnect_same','reconnect_different'),targets)),
            'seconds_per_goal':args.seconds,'max_expansions_per_goal':args.max_expansions,
            'max_queue_per_goal':args.max_queue,'max_packets':32,'max_firings':48,'max_wait_units':2,'max_departures':2},
        'ordering_claim':'Nondecreasing complete weighted cost within each fixed goal and restricted PNPRO profile; per-goal targets ensure lifecycle coverage.',
        'priority_potential':'h is reverse-Dijkstra minimum remaining N+T on the same CPN with history budgets and A/W relaxed; priority edge is actual deltaC+h(child)-h(parent)>=0',
        'unique_packet_sequences':len(signatures)}
    (args.output/'search_metadata.json').write_text(json.dumps(metadata,indent=2))
    print(json.dumps({'paths':len(paths),'goals':dict(Counter(p['goal'] for p in paths)),'stats':stats,'seconds':metadata['elapsed_seconds']},indent=2))
    if len(paths)<args.k:
        raise SystemExit('Requested path quota not reached; inspect saved exploration metadata')


if __name__=='__main__':
    main()
