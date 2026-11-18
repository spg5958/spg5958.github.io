#!/usr/bin/env python3
"""Compose four matched offline conditions and render CPN search results."""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path

TITLE = 'Model-guided TCP handshake probes for dMAP'


def counts(events):
    return sum(e.get('kind')=='packet' for e in events), sum(e.get('units',1) for e in events if e.get('kind')=='wait')


def matched_baseline(plan, baselines, model, cache):
    """Pad actual ordinary CPN firings to the candidate's two wait intervals."""
    from search_cpn import Query, record
    before=sum(e.get('units',1) for e in plan.get('prefix_history',[]) if e.get('kind')=='wait')
    after=plan['cost']['T']-before
    key=(plan['goal'],plan.get('readout_delivery','full'),before,after)
    if key in cache:return cache[key]
    original=baselines[key[0]+'|'+key[1]]
    names=list(original['transitions'])
    query=Query(model,key[0],ordinary_only=True,readout_delivery=key[1])
    assert original['cost']['T']==0,'Reference baselines must start without waits'
    readout=next(i for i,n in enumerate(names) if model.annotations[n].get('purpose')=='readout')
    def wait_at(index):
        states=query.replay(names[:index]);state=states[-1]
        wait=next(n for n,s,c in query.successors(state) if n=='WAIT_IDLE')
        names.insert(index,wait)
    for i in range(before):wait_at(readout+i)
    for i in range(after):wait_at(len(names))
    states=query.replay(names)
    result=record(model,query,names,states,0)
    cache[key]={'events':result['history'],'transitions':names,'cost':result['cost'],
                'wait_matching':{'before_readout_units':before,'after_readout_units':after}}
    return cache[key]


def decorate(plan, index, baselines, model, baseline_cache, repetitions=3):
    p=deepcopy(plan)
    p['id']=f'P{index:04d}'
    p['title']=p.get('title') or p.get('goal','').replace('_',' ')+' / '+', '.join(p.get('families',[]) or ['ordinary'])
    p['families']=p.get('families') or ['ordinary']
    p['family']=p.get('family') or p['families'][0]
    p['decision_phase']=p.get('decision_phase','CPN-defined')
    p['goal']=p.get('goal','establish')
    p['labels']=p.get('labels',[])
    p['Y']=None
    p['outcome_status']='unmeasured'
    p['hypothesis']='CPN-feasible candidate concerning '+', '.join(p['families'])+'. DPI effects require calibrated measurement.'
    p['bundle_ids']=[]
    p['readout']=dict(fixture='fixtures/clienthello.json',length_symbol='L_readout',length_bytes=100,
                     segmentation='one fixed ClientHello segment',hostname_placeholders=True)
    if 'baseline_history' in p:
        base={'events':p.pop('baseline_history'),'transitions':p.pop('baseline_transitions',[]),
              'cost':p.pop('baseline_cost',None)}
    else:
        base=matched_baseline(p,baselines,model,baseline_cache)
    if not base.get('cost'):
        n,t=counts(base.get('events',base.get('history',[])))
        base['cost']={'N':n,'A':0,'W':0,'T':t,'kappa':1,'total':n+t}
    base.setdefault('events',base.get('history',[]))
    p['condition_histories']={'ordinary':base,'candidate':{'transitions':p['transitions'],'cost':p['cost']}}
    p['conditions']=[]
    for ref,trace in [('ordinary',base),('candidate',p)]:
        for host in ['benign','blocked']:
            p['conditions'].append({'id':ref+'_'+host,'history':ref,'history_ref':ref,
                'hostname_class':host,'hostname':'allowed.example' if host=='benign' else 'blocked.example',
                'fixture':'fixtures/clienthello_'+host+'.bin','Y':None,'status':'unmeasured',
                'readout_delivery':p.get('readout_delivery','full'),'cost':trace['cost'],
                'quality_metadata':{'calibration_passed':None,'delivery_confirmed':None,'repeat_stability':None}})
    p['trial_repetitions']=repetitions
    p['execution_resource_proxy']=repetitions*sum(c['cost']['N']+c['cost']['T'] for c in p['conditions'])
    p['empirical_separated_pairs']=None
    p['empirical_information_gain']=None
    return p


def bundles_for(plans, limit=24):
    result=[]
    for goal in dict.fromkeys(p['goal'] for p in plans):
        rows=[p for p in plans if p['goal']==goal]
        families=list(dict.fromkeys(f for p in rows for f in p['families'] if f!='ordinary'))
        for start in range(0,len(families),3):
            selected=[]
            for family in families[start:start+3]:
                choices=[p for p in rows if family in p['families'] and p not in selected]
                if choices:selected.append(min(choices,key=lambda p:p['cost']['total']))
            if len(selected)<2:continue
            bid=f'B{len(result)+1:03d}'
            for p in selected:p['bundle_ids'].append(bid)
            result.append(dict(id=bid,goal=goal,probe_ids=[p['id'] for p in selected],size=len(selected),
                families=list(dict.fromkeys(f for p in selected for f in p['families'])),
                selection='offline semantic coverage; empirical separation unmeasured',
                execution_resource_proxy=sum(p['execution_resource_proxy'] for p in selected),
                outcome_vector=[None]*len(selected),separated_reference_pairs=None))
            if len(result)>=limit:return result
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--results',type=Path,default=Path(__file__).with_name('results'))
    args=ap.parse_args();out=args.results
    raw=[json.loads(s) for s in (out/'raw_paths.jsonl').read_text().splitlines() if s.strip()]
    baselines=json.loads((out/'baselines.json').read_text()) if (out/'baselines.json').exists() else {}
    from cpn_runtime import CPNModel
    model=CPNModel(Path(__file__).with_name('model')/'model_guided_tcp_handshake.PNPRO')
    baseline_cache={}
    plans=[decorate(p,i+1,baselines,model,baseline_cache) for i,p in enumerate(raw)]
    bundles=bundles_for(plans)
    meta_path=out/'run_metadata.json'
    source_meta=out/'search_metadata.json'
    meta=json.loads(source_meta.read_text()) if source_meta.exists() else {}
    meta['status']=f'{len(plans):,} CPN-derived packet sequences; bounded weighted search'
    profile=model.profile
    meta['limitations']=profile.get('limitations',[])
    verification_path=out/'verification.json'
    if verification_path.exists():meta['verification']=json.loads(verification_path.read_text())
    meta.update(title=TITLE,plan_count=len(plans),bundle_count=len(bundles),bundles=bundles,
        parent_index='../../index.html',packets_transmitted=0,dpi_outcomes_measured=False,
        cost_formula='N + A + 2W + kappa*T',coverage=dict(Counter(f for p in plans for f in p['families'])),
        goal_counts=dict(Counter(p['goal'] for p in plans)))
    (out/'plans.json').write_text(json.dumps(plans,indent=2))
    (out/'plans.jsonl').write_text(''.join(json.dumps(p)+'\n' for p in plans))
    (out/'bundles.json').write_text(json.dumps(bundles,indent=2))
    meta_path.write_text(json.dumps(meta,indent=2))
    with (out/'plans.csv').open('w',newline='') as f:
        w=csv.writer(f);w.writerow(['id','goal','family','readout_delivery','N','A','W','T','cost','Y'])
        for p in plans:w.writerow([p['id'],p['goal'],p['family'],p.get('readout_delivery'),*[p['cost'][k] for k in ['N','A','W','T','total']],None])
    from render_results import render_all
    render_all(out,plans,meta)
    # A standalone entry point for a results folder linked from the main website.
    entry=(out/'index.html').read_text().replace('"parent_index":"../../index.html"',
        '"parent_index":"../index.html"',1)
    (Path(__file__).parent/'index.html').write_text(entry)
    print(json.dumps({'title':TITLE,'plans':len(plans),'bundles':len(bundles)}))


if __name__=='__main__':main()
