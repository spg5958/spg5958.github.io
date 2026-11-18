#!/usr/bin/env python3
"""Offline TCP segmentation experiment synthesis. No packet transmission code."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import itertools
import json
from pathlib import Path
import struct
import time

def u16(n): return struct.pack('!H', n)

def parse_hello(record):
    assert record[:1] == b'\x16'
    assert int.from_bytes(record[3:5], 'big') == len(record)-5
    assert record[5] == 1
    assert int.from_bytes(record[6:9], 'big') == len(record)-9
    pos = 9+2+32
    pos += 1+record[pos]
    size = int.from_bytes(record[pos:pos+2], 'big')
    assert size > 0 and size % 2 == 0
    pos += 2+size
    pos += 1+record[pos]
    end = pos+2+int.from_bytes(record[pos:pos+2], 'big')
    assert end == len(record)
    pos += 2
    found = None
    while pos < end:
        typ = int.from_bytes(record[pos:pos+2], 'big')
        size = int.from_bytes(record[pos+2:pos+4], 'big')
        pos += 4
        assert pos+size <= end
        if typ == 0:
            assert int.from_bytes(record[pos:pos+2], 'big') == size-2
            assert record[pos+2] == 0
            length = int.from_bytes(record[pos+3:pos+5], 'big')
            assert length == size-5
            found = (pos+5, length, record[pos+5:pos+5+length].decode('ascii'))
        pos += size
    assert pos == end and found is not None
    return found

def serialize_hello(hostname):
    """TLS 1.2 ClientHello with deterministic random; derive SNI offset by parsing."""
    host = hostname.encode('ascii')
    assert all(0<len(x)<=63 and x[0].isalnum() and x[-1].isalnum()
               and all(c.isalnum() or c=='-' for c in x) for x in hostname.split('.'))
    name = b'\x00'+u16(len(host))+host
    sni = u16(len(name))+name
    extensions = (u16(0)+u16(len(sni))+sni
                  + b'\x00\x0a\x00\x04\x00\x02\x00\x17'
                  + b'\x00\x0b\x00\x02\x01\x00'
                  + b'\x00\x0d\x00\x06\x00\x04\x04\x01\x04\x03')
    body = (b'\x03\x03'+bytes(range(32))+b'\x00'+u16(4)+b'\xc0\x2f\x00\x9c'
            + b'\x01\x00'+u16(len(extensions))+extensions)
    handshake = b'\x01'+len(body).to_bytes(3,'big')+body
    record = b'\x16\x03\x01'+u16(len(handshake))+handshake
    start, length, actual = parse_hello(record)
    assert actual == hostname
    return record,start,length





def merge_intervals(intervals):
    merged=[]
    for lo,hi in sorted(intervals):
        if merged and lo<=merged[-1][1]: merged[-1]=(merged[-1][0],max(hi,merged[-1][1]))
        else: merged.append((lo,hi))
    return merged

def geometry_state(intervals,length):
    merged=merge_intervals(intervals)
    cursor,holes=0,[]
    for lo,hi in merged:
        if lo>cursor: holes.append([cursor,lo])
        cursor=hi
    return {'coverage':[list(x) for x in merged],'holes':holes,'hole_count':len(holes),
            'frontier':merged[0][1] if merged and merged[0][0]==0 else 0,
            'complete':merged==[(0,length)]}

def pair_relation(old,new):
    a,b=old; c,d=new
    if c==a and d==b: return 'equal'
    if d<a: return 'before'
    if d==a: return 'meets_left'
    if c>b: return 'after'
    if c==b: return 'meets_right'
    if c==a: return 'same_start_shorter' if d<b else 'same_start_longer'
    if d==b: return 'same_end_shorter' if c>a else 'same_end_longer'
    if c<a and d>b: return 'contains'
    if c>a and d<b: return 'inside'
    return 'overlap_left' if c<a else 'overlap_right'





def witness_assignments(geometry,target,benign,u,n):
    """Bounded template patterns; packet bytes are generated without a DPI oracle."""
    k=len(geometry)
    patterns={tuple('T' if i%2==0 else 'B' for i in range(k)),
              tuple('B' if i%2==0 else 'T' for i in range(k))}
    for chosen in range(k):
        patterns.add(tuple('B' if i==chosen else 'T' for i in range(k)))
        patterns.add(tuple('T' if i==chosen else 'B' for i in range(k)))
    return sorted(patterns)

def geometry_tags(geometry,length,u,n):
    tags=set(); history=[]; max_holes=0
    for lo,hi in geometry:
        before=geometry_state(history,length)
        if lo<before['frontier'] and any(max(lo,a)<min(hi,b) for a,b in history):
            tags.add('after_contiguous_prefix' if hi<=before['frontier'] else 'cross_contiguous_prefix')
        for old in history: tags.add(pair_relation(old,(lo,hi)))
        if sum(max(lo,a)<min(hi,b) for a,b in before['coverage'])>=2: tags.add('spans_multiple_regions')
        history.append((lo,hi))
        max_holes=max(max_holes,geometry_state(history,length)['hole_count'])
    if max_holes==2: tags.add('two_holes')
    if geometry[0][0]>0: tags.add('leading_gap')
    if any(lo<=u+4<hi and not lo<=u+5<hi for lo,hi in geometry) and any(lo<=u+5<hi and not lo<=u+4<hi for lo,hi in geometry):
        tags.add('independent_sni_regions')
    return sorted(tags),max_holes

def enumerate_histories(endpoints,length,max_segments,holes_bound,node_cap,emit_cap,stats,deadline=None):
    """Increasing budgets and reversible prefixes. Resource caps are disclosed."""
    choices=[(a,b) for i,a in enumerate(endpoints) for b in endpoints[i+1:]]
    fullmask=(1<<length)-1
    masks={(a,b):((1<<(b-a))-1)<<a for a,b in choices}
    for budget in range(1,max_segments+1):
        nodes=emitted=0; cutoff=None; history=[]; counts=[0]*length
        ordering=sorted(choices,key=lambda p:((p[0]==0,(p[0]+p[1]+budget)%7 if budget>3 else 0),p))
        def backtrack(mask):
            nonlocal nodes,emitted,cutoff
            if cutoff: return
            nodes+=1
            if deadline is not None and time.perf_counter()>deadline: cutoff='time_limit'; return
            if nodes>node_cap: cutoff='node_limit'; return
            remaining=budget-len(history)
            lower_bound=0 if mask==fullmask else 1
            if lower_bound>remaining:
                stats['completion_lower_bound_prunes']+=1; return
            if remaining==0:
                if mask==fullmask:
                    emitted+=1
                    yield tuple(history)
                    if emitted>=emit_cap and budget>3: cutoff='geometry_limit'
                return
            for interval in ordering:
                history.append(interval)
                if geometry_state(history,length)['hole_count']<=holes_bound:
                    for x in range(*interval): counts[x]+=1
                    yield from backtrack(mask|masks[interval])
                    for x in range(*interval): counts[x]-=1
                else: stats['hole_bound_prunes']+=1
                history.pop()
                if cutoff: break
        yield from backtrack(0)
        stats['budgets'].append({'data_packet_budget':budget,'nodes':nodes,'complete_geometries':emitted,
                                 'cutoff':cutoff,'exhaustive':cutoff is None})
        assert not any(counts)
        print(f'budget={budget}: nodes={nodes:,} geometries={emitted:,} cutoff={cutoff}',flush=True)

def execution_contract(segments,length,mss,receive_window):
    assert 0<length<=receive_window
    assert all(0<=s['start']<s['end']<=length and s['end']-s['start']<=mss for s in segments)
    assert all(s['visibility']=='ttl' or s['checksum']=='invalid' for s in segments)
    return {'genuine_handshake_required':True,'server_isn_must_be_learned':True,
            'seq_binding':'(genuine_client_isn + 1 + start) modulo 2^32',
            'ack_binding':'(genuine_server_isn + 1) modulo 2^32',
            'server_data_frontier':0,'observed_server_data_acks':0,'server_tls_reply_expected':False,
            'server_state_during_trial':'TCP_ESTABLISHED',
            'cleanup':'full-TTL valid-checksum RST|ACK at genuine client_isn+1, ACK genuine server_isn+1; verify actual state',
            'not_run':True}

def make_probe(geometry,assignment,family,target,benign,u,n,args,source='backtracking',cases=(),title=None):
    segments=[]
    for idx,((lo,hi),variant) in enumerate(zip(geometry,assignment)):
        invalid=family=='full_bad_checksum' or family=='ttl_bad_checksum' and variant=='B'
        data=(target if variant=='T' else benign)[lo:hi]
        a,b=max(u,lo),min(u+n,hi)
        segments.append({'start':lo,'end':hi,'variant':variant,
                         'visibility':'full' if family=='full_bad_checksum' else 'ttl',
                         'checksum':'invalid' if invalid else 'valid','payload_hex':data.hex(),
                         'hostname_slice':(target if variant=='T' else benign)[a:b].decode('ascii') if a<b else '',
                         'seq_offset':lo,'payload_bytes':hi-lo})
    if family=='ttl_bad_checksum' and not any(s['checksum']=='invalid' for s in segments): segments[0]['checksum']='invalid'
    tags,max_holes=geometry_tags(geometry,len(target),u,n)
    conflicts=set()
    for j,s in enumerate(segments):
        payload=bytes.fromhex(s['payload_hex'])
        for old in segments[:j]:
            old_payload=bytes.fromhex(old['payload_hex'])
            for x in range(max(s['start'],old['start']),min(s['end'],old['end'])):
                if payload[x-s['start']]!=old_payload[x-old['start']]: conflicts.add(x)
    if conflicts: tags.append('conflicting_bytes')
    if any(b-a>1 for a,b in zip(sorted(conflicts),sorted(conflicts)[1:])): tags.append('separated_conflict_regions')
    cost=len(geometry)+args.overhead
    return {'id':'','title':title or f'{len(geometry)} segments · '+('buffered conflict' if 'leading_gap' in tags else 'interval history'),
            'family':family,'source':source,'tags':tags,'dp_cases':list(cases),'max_holes':max_holes,
            'data_packets':len(geometry),'cost':cost,'execution_packets':3*args.repeats*cost,
            'control_connections_per_repetition':3,'repetitions':args.repeats,
            'segments':segments,'observations':None,'measurement_status':'not_run',
            'target_hostname':target[u:u+n].decode('ascii'),'benign_hostname':benign[u:u+n].decode('ascii'),
            'individual_packet_contains_full_target':any(target[u:u+n] in bytes.fromhex(s['payload_hex']) for s in segments),
            'conflicting_byte_offsets':sorted(conflicts),
            'transport':execution_contract(segments,len(target),args.mss,args.receive_window),
            'identity_sha256':hashlib.sha256(json.dumps(segments,sort_keys=True).encode()).hexdigest()}

def summarize_bundle(programs,title,ident):
    return {'id':ident,'title':title,'probe_ids':[p['id'] for p in programs],
            'data_packets':sum(p['data_packets'] for p in programs),'connections':len(programs),
            'cost':sum(p['cost'] for p in programs),
            'execution_packets':sum(p['execution_packets'] for p in programs)}

def structural_features(probe):
    return set(probe['tags']) | {f"family:{probe['family']}",
            f"data_packets:{probe['data_packets']}",f"holes:{probe['max_holes']}"}

def coverage_bundle(probes,title,ident,permitted=None,max_connections=6):
    candidates=[p for p in probes if permitted is None or permitted(p)]
    chosen=[]; covered=set()
    while candidates and len(chosen)<max_connections:
        best=max(candidates,key=lambda p:(len(structural_features(p)-covered)/p['execution_packets'],
                                         -p['cost'],p['id']))
        new=structural_features(best)-covered
        if not new: break
        chosen.append(best); covered.update(new); candidates.remove(best)
    result=summarize_bundle(chosen,title,ident)
    result['selection']='Greedy new structural features per nominal execution cost; no optimality claim.'
    return result

def select_diverse(pool,keep):
    selected=[]; used=set()
    def take(probe):
        if probe['identity_sha256'] not in used and len(selected)<keep:
            used.add(probe['identity_sha256']); selected.append(probe)
    for probe in pool:
        if probe['source']!='backtracking': take(probe)
    strata=defaultdict(list)
    for probe in pool:
        strata[(probe['family'],probe['data_packets'],probe['max_holes'])].append(probe)
    for key in sorted(strata):
        for probe in sorted(strata[key],key=lambda p:p['identity_sha256'])[:20]: take(probe)
    groups=defaultdict(list)
    for probe in pool:
        for tag in probe['tags'] or ['plain']:
            groups[(probe['family'],probe['data_packets'],tag)].append(probe)
    for group in groups.values(): group.sort(key=lambda p:(p['cost'],p['identity_sha256']))
    round_no=0
    while len(selected)<min(keep,len(pool)):
        possible=False
        for key in sorted(groups):
            if round_no<len(groups[key]):
                possible=True; take(groups[key][round_no])
        if not possible: break
        round_no+=1
    return selected

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,default=Path('results'))
    ap.add_argument('--keep',type=int,default=1000)
    ap.add_argument('--max-segments',type=int,default=6)
    ap.add_argument('--max-holes',type=int,default=2)
    ap.add_argument('--node-cap',type=int,default=80000)
    ap.add_argument('--geometry-cap',type=int,default=350)
    ap.add_argument('--seconds',type=float,default=120)
    ap.add_argument('--overhead',type=int,default=4)
    ap.add_argument('--repeats',type=int,default=3)
    ap.add_argument('--mss',type=int,default=1200)
    ap.add_argument('--receive-window',type=int,default=65535)
    ap.add_argument('--target',default='abcdefgh.example')
    ap.add_argument('--benign',default='abcdxygh.example')
    ap.add_argument('--all-hostname-cuts',action='store_true')
    ap.add_argument('--geometry-cases',type=Path,default=Path(__file__).with_name('geometry_cases.json'))
    args=ap.parse_args()
    assert args.overhead>0 and args.repeats>0 and 1<=args.max_segments<=8 and args.keep>0 and args.seconds>0
    start=time.perf_counter()
    target,u,n=serialize_hello(args.target); benign,ub,nb=serialize_hello(args.benign)
    assert len(target)==len(benign) and (u,n)==(ub,nb)
    assert all((a==46)==(b==46) for a,b in zip(target[u:u+n],benign[u:u+n]))
    assert target[:u]==benign[:u] and target[u+n:]==benign[u+n:]
    assert n>=10, 'This geometry profile requires at least ten hostname bytes'
    endpoints=sorted({0,u,u+2,u+4,u+5,u+6,u+8,u+n,len(target)} |
                     ({u+i for i in range(n+1)} if args.all_hostname_cuts else set()))
    assert len(target)<=args.mss, 'This framing profile requires MSS >= complete ClientHello; no uncounted packet splitting is allowed'
    stats={'budgets':[],'completion_lower_bound_prunes':0,'hole_bound_prunes':0,
           'histories_seen':0,'assignments_synthesized':0,'duplicate_candidates_suppressed':0}
    pool=[]; seen=set()
    def retain(p):
        if p['identity_sha256'] in seen:
            stats['duplicate_candidates_suppressed']+=1
            # Preserve local-coverage labels when identical packet programs coincide.
            existing=next(x for x in pool if x['identity_sha256']==p['identity_sha256'])
            existing['dp_cases']=sorted(set(existing['dp_cases']+p['dp_cases']))
            return
        seen.add(p['identity_sha256']); pool.append(p)
    demo_a=[(u+2,u+6),(u+4,len(target)),(0,u+2)]
    demo_b=[demo_a[1],demo_a[0],demo_a[2]]
    for family in ['ttl_valid','full_bad_checksum','ttl_bad_checksum']:
        for geom,bits,label in [(demo_a,('T','B','T'),'A: X → Y → G'),(demo_b,('B','T','T'),'B: Y → X → G')]:
            if len(geom)<=args.max_segments:
                retain(make_probe(geom,bits,family,target,benign,u,n,args,'pdf_page4',title=label))
    exploration=[
        ([(u+4,u+5),(u+6,len(target)),(u+5,u+8),(0,u+4)],('T','T','B','T'),'Two holes with separate hostname letters'),
        ([(u+4,u+5),(u+6,u+8),(u+4,len(target)),(0,u+4)],('T','T','B','T'),'Incoming segment spans two buffered regions'),
        ([(0,u+5),(u+4,u+6),(u+5,len(target))],('B','T','T'),'Overlap crosses a contiguous prefix'),
        ([(0,u+6),(u+4,u+6),(u+6,len(target))],('B','T','T'),'Overlap lies within a contiguous prefix'),
        ([(0,len(target)),(u+4,u+6)],('T','B'),'Target record followed by conflicting bytes'),
        ([(0,len(target)),(u+4,u+6)],('B','T'),'Benign record followed by conflicting target bytes'),
        ([(0,len(target))],('T',),'Unsplit target control geometry'),
        ([(0,u+4),(u+5,len(target)),(u+4,u+5),(u+4,u+6)],('T','B','T','T'),'Complete before final conflicting segment')]
    for geom,bits,title in exploration:
        if len(geom)<=args.max_segments and all(geometry_state(geom[:i+1],len(target))['hole_count']<=args.max_holes for i in range(len(geom))):
            for family in ['ttl_valid','full_bad_checksum','ttl_bad_checksum']:
                retain(make_probe(geom,bits,family,target,benign,u,n,args,'coverage_seed',title=title))
    broad_name='ijklmnop.example' if args.target=='abcdefgh.example' else ''.join(
        chr((ord(c.lower())-97+11)%26+97) if c.isalpha() else c for c in args.target)
    broad,bu,bn=serialize_hello(broad_name)
    assert (bu,bn,len(broad))==(u,n,len(target))
    broad_seeds=[
        ([(u+2,u+4),(u+6,u+8),(u+3,u+7),(0,u+2),(u+8,len(target))],('T','T','B','T','T'),'Two separated conflicting buffered regions'),
        ([(u+2,u+4),(u+6,u+8),(u+1,u+9),(0,u+1),(u+9,len(target))],('T','T','B','T','T'),'Incoming spans two independently conflicting islands')]
    for geom,bits,title in broad_seeds:
        if len(geom)<=args.max_segments and all(geometry_state(geom[:i+1],len(target))['hole_count']<=args.max_holes for i in range(len(geom))):
            for family in ['ttl_valid','full_bad_checksum','ttl_bad_checksum']:
                retain(make_probe(geom,bits,family,target,broad,u,n,args,'coverage_seed',title=title))
    case_info={}
    if args.geometry_cases.exists():
        case_info=json.loads(args.geometry_cases.read_text())
        for label,case in case_info.get('cases',{}).items():
            geom=[tuple(x) for x in case['geometry']]
            if case.get('relative_to_sni',True):
                geom=[(0 if i==0 and a==0 and case.get('map_initial_forwarded_zero_to_stream_start') else u+a,u+b)
                      for i,(a,b) in enumerate(geom)]
            # Add every missing framing/gap packet explicitly to the budget.
            missing=geometry_state(geom,len(target))['holes']
            geom.extend(tuple(x) for x in missing)
            right=max(b for a,b in geom)
            if right<len(target): geom.append((right,len(target)))
            if len(geom)>args.max_segments or any(geometry_state(geom[:i+1],len(target))['hole_count']>args.max_holes for i in range(len(geom))): continue
            for bits in witness_assignments(geom,target,benign,u,n)[:4]:
                retain(make_probe(geom,bits,'ttl_valid',target,benign,u,n,args,'dp_coverage',[label],f'Geometry: {label.replace("_"," ")}'))
    for geom in enumerate_histories(endpoints,len(target),args.max_segments,args.max_holes,args.node_cap,args.geometry_cap,stats,start+args.seconds):
        stats['histories_seen']+=1
        for assignment in witness_assignments(geom,target,benign,u,n):
            stats['assignments_synthesized']+=1
            retain(make_probe(geom,assignment,'ttl_valid',target,benign,u,n,args))
    base=select_diverse(pool,max(args.keep*2,2000))
    for p in base[:min(450,len(base))]:
        if p['family']!='ttl_valid': continue
        geom=[(s['start'],s['end']) for s in p['segments']]
        bits=tuple(s['variant'] for s in p['segments'])
        for family in ['full_bad_checksum','ttl_bad_checksum']:
            retain(make_probe(geom,bits,family,target,benign,u,n,args))
    probes=select_diverse(pool,args.keep)
    for idx,p in enumerate(probes,1): p['id']=f'S{idx:04d}'
    demo=[p for p in probes if p['source']=='pdf_page4' and p['family']=='ttl_valid']
    bundles=[summarize_bundle(demo,'Two-connection example from the specification','pdf_page4'),
             coverage_bundle(probes,'Coverage bundle across packet families','coverage_suite'),
             coverage_bundle(probes,'TTL-only measurement bundle','default_family',lambda p:p['family']=='ttl_valid'),
             coverage_bundle(probes,'Bundle with split target SNI','segmented_sni',
                             lambda p:p['family']=='ttl_valid' and not p['individual_packet_contains_full_target'],max_connections=2)]
    coverage={'cases':{label:dict(case,probe_ids=[p['id'] for p in probes if label in p['dp_cases']]) for label,case in case_info.get('cases',{}).items()},
              'tags':dict(Counter(tag for p in probes for tag in p['tags'])),
              'letter_mapping_status':case_info.get('letter_mapping_status','not_provided'),
              'verified_categories':case_info.get('verified_categories',{}),
              'provenance':'Descriptive fixtures cover local interval geometry. Exact Figure 4 A-T letter mapping unverified; no claim of audited 20/20 coverage.'}
    elapsed=time.perf_counter()-start
    stats.update({'elapsed_seconds':round(elapsed,3),'candidate_pool':len(pool),'retained':len(probes),
                  'globally_exhaustive':all(x['exhaustive'] for x in stats['budgets']),
                  'selection':'coverage-first over families, budgets and interval tags; not k globally shortest probes',
                  'payload_synthesis':'alternating and single-template-flip patterns; at most 2+2*k assignments for k packets; not exhaustive payload enumeration',
                  'geometry_deduplication':'ordered history only; never coverage-map equivalence'})
    used_endpoints=sorted(set(endpoints)|{x for p in probes for s in p['segments'] for x in [s['start'],s['end']]})
    data={'meta':{'config':dict(vars(args),output=str(args.output),geometry_cases=str(args.geometry_cases)),
                  'template':{'target':args.target,'benign':args.benign,'length':len(target),'sni_start':u,'sni_length':n,
                              'endpoints':used_endpoints,'search_endpoints':endpoints,'target_hex':target.hex(),'benign_hex':benign.hex(),
                              'payload_pairs':[{'target':args.target,'benign':args.benign,'purpose':'PDF page4 and main bounded search'},
                                               {'target':args.target,'benign':broad_name,'purpose':'Separated multi-region byte conflicts'}],
                              'tls_version':'TLS 1.2 ClientHello, one TLS record; no TLS-record fragmentation'},
                  'search':stats,
                  'source_notes':['Attachment 2 defines the task; engine independent of prior CPN/Dijkstra.',
                                  'Reserved .example hostnames implement a hypothetical exact-SNI rule; not known censored Internet targets.',
                                  'No connection, TTL calibration, censorship measurement, Linux replay or live DPI validation performed.']},
          'summary':{'probes':len(probes),'families':dict(Counter(p['family'] for p in probes)),
                     'data_packet_distribution':dict(sorted(Counter(p['data_packets'] for p in probes).items())),
                     'max_holes':max(p['max_holes'] for p in probes),
                     'geometry_cases_covered':sum(bool(v['probe_ids']) for v in coverage['cases'].values()),
                     'measured_trials':0},
          'probes':probes,'bundles':bundles,'coverage':coverage,'validation':{},
          'cost_contract':{'formula':'C(p) = N_data(p) + h * N_connections(p)','h':args.overhead,
                           'ordinary_overhead':'3 handshake packets + 1 genuine-state RST cleanup; assumed not observed',
                           'test_types':['conflicting test','same geometry all-target control','same geometry all-benign control'],
                           'planned_execution_packets_per_probe':'repetitions * 3 * (N_data + h)',
                           'repetitions':args.repeats,'wire_count_status':'nominal planned count; retransmissions, injected packets, calibration and waits unmeasured',
                           'calibration_packets':None,'wait_seconds':None,'actual_packets':None},
          'run_quality_contract':{'prerequisites':['controlled policy or calibrated equal-length target/benign hostnames','DPI-visible/server-expiring TTL class','independent policy-action detector',
                                                  'on-wire TCP checksum confirmation; exclude repair/normalization for checksum families','MSS, payload and window check','fresh connection and residual-state isolation'],
                                  'binary_observation':'Y=1 calibrated policy action; Y=0 no signal in an evaluable interval',
                                  'not_a_policy_signal':['missing TLS response','ordinary TCP reset','ICMP Time Exceeded','local timeout'],
                                  'quality_failure':'exclude through metadata; not a third fingerprint symbol',
                                  'control_expectations':'Run each control with the same geometry and packet classes; establish route visibility and detector operation with separate ordinary target/benign baselines.',
                                  'send_schedule':'send ordered segments without waiting for server data ACKs; interval and final detector observation wait must be calibrated before execution',
                                  'measured_send_times':None},
          'connection_template':[
              {'direction':'client_to_server','flags':'SYN','seq':'CLIENT_ISN','ack':None,'ttl':'ordinary','checksum':'valid'},
              {'direction':'server_to_client','flags':'SYN|ACK','seq':'SERVER_ISN','ack':'CLIENT_ISN+1','knowledge':'learn real SERVER_ISN; verify actual window/MSS'},
              {'direction':'client_to_server','flags':'ACK','seq':'CLIENT_ISN+1','ack':'SERVER_ISN+1','ttl':'ordinary','checksum':'valid'},
              {'direction':'client_to_dpi','flags':'ACK','seq':'CLIENT_ISN+1+segment.start','ack':'SERVER_ISN+1','repeat':'each ordered data segment'},
              {'direction':'client_to_server','flags':'RST|ACK','seq':'CLIENT_ISN+1','ack':'SERVER_ISN+1','ttl':'ordinary','checksum':'valid'}]}
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'results.json').write_text(json.dumps(data,separators=(',',':')))
    (args.output/'search_summary.json').write_text(json.dumps({'summary':data['summary'],'search':stats,'bundles':bundles},indent=2))
    (args.output/'target_clienthello.bin').write_bytes(target)
    (args.output/'benign_clienthello.bin').write_bytes(benign)
    print(json.dumps(data['summary'],indent=2),flush=True)
    print(f'Elapsed {elapsed:.2f} seconds',flush=True)

if __name__=='__main__': main()
