#!/usr/bin/env python3
"""Independent offline contracts and regressions for generated probe plans."""
from __future__ import annotations

import argparse
from collections import Counter
import contextlib
import io
import itertools
import json
from pathlib import Path
import struct

import search


class Cursor:
    def __init__(self, data): self.data, self.p = data, 0
    def take(self, count):
        assert count >= 0 and self.p + count <= len(self.data)
        out = self.data[self.p:self.p+count]
        self.p += count
        return out
    def integer(self, count): return int.from_bytes(self.take(count), 'big')
    def vector(self, width): return self.take(self.integer(width))
    def exhausted(self): assert self.p == len(self.data)


def inspect_tls(raw):
    """Parse every nested TLS length independently of the synthesizer."""
    r = Cursor(raw)
    assert r.integer(1) == 22
    version = r.take(2)
    assert version in [b'\x03\x01', b'\x03\x03']
    record = r.vector(2)
    r.exhausted()
    hs = Cursor(record)
    assert hs.integer(1) == 1
    body = hs.vector(3)
    hs.exhausted()
    hello = Cursor(body)
    assert hello.take(2) == b'\x03\x03'
    assert len(hello.take(32)) == 32
    assert len(hello.vector(1)) <= 32
    ciphers = hello.vector(2)
    assert ciphers and len(ciphers) % 2 == 0
    assert hello.vector(1) == b'\x00'
    extension_data = hello.vector(2)
    hello.exhausted()
    ext = Cursor(extension_data)
    host = None
    extension_types = []
    while ext.p < len(extension_data):
        typ = ext.integer(2)
        extension_types.append(typ)
        payload = ext.vector(2)
        if typ == 0:
            payload_cursor = Cursor(payload)
            names = Cursor(payload_cursor.vector(2))
            payload_cursor.exhausted()
            assert names.integer(1) == 0
            hostname = names.vector(2)
            names.exhausted()
            assert host is None
            host = hostname.decode('ascii')
            for label in host.split('.'):
                assert 0 < len(label) <= 63
                assert label[0].isalnum() and label[-1].isalnum()
                assert all(ch.isalnum() or ch == '-' for ch in label)
    ext.exhausted()
    assert len(extension_types) == len(set(extension_types))
    assert host is not None
    # Structural offset: SNI is the first extension in this emitted template.
    prefix = (5 + 4 + 2 + 32 + 1 + 2 + len(ciphers) + 1 + 1
              + 2 + 4 + 2 + 1 + 2)
    assert raw[prefix:prefix+len(host)] == host.encode('ascii')
    return prefix, len(host), host


def independent_geometry(intervals, length):
    seen = {i for lo, hi in intervals for i in range(lo, hi)}
    missing = []
    right = max(seen) + 1 if seen else 0
    i = 0
    while i < right:
        if i in seen:
            i += 1
            continue
        left = i
        while i < right and i not in seen: i += 1
        missing.append([left, i])
    frontier = 0
    while frontier in seen: frontier += 1
    return missing, frontier, len(seen) == length


def independent_prediction(segments, model, target, u, n):
    """Dictionary-based streaming reference, using exported literal packet bytes."""
    if model['policy'] in ('ack', 'ttl'): return 0, None
    cells = {}
    frozen = set()
    latched = None
    for step, seg in enumerate(segments, 1):
        if model['validate_checksum'] and seg['checksum'] == 'invalid': continue
        raw = bytes.fromhex(seg['payload_hex'])
        lo = seg['start']
        if model['policy'] == 'packet':
            if lo == 0 and len(raw) == len(target) and raw[u:u+n] == target[u:u+n] and latched is None:
                latched = step
            continue
        new = {lo+j: value for j, value in enumerate(raw)}
        if model['policy'] == 'reject' and any(x in cells and cells[x][0] != value for x, value in new.items()):
            break
        for x, value in new.items():
            if x in frozen: continue
            previous = cells.get(x)
            option = (value, lo, step)
            if previous is None:
                cells[x] = option
            elif model['policy'] == 'last':
                cells[x] = option
            elif model['policy'] == 'lower' and lo < previous[1]:
                cells[x] = option
            elif model['policy'] == 'higher' and lo > previous[1]:
                cells[x] = option
        frontier = 0
        while frontier in cells: frontier += 1
        if model['inspection'] == 'contiguous' or frontier == len(target):
            frozen.update(range(frontier))
        if frontier == len(target):
            assembled = bytes(cells[x][0] for x in range(len(target)))
            # Any mixture can differ only in hostname letters, never TLS framing.
            assert assembled[:u] == target[:u] and assembled[u+n:] == target[u+n:]
            inspect_tls(assembled)
            if assembled[u:u+n] == target[u:u+n] and latched is None:
                latched = step
    return int(latched is not None), latched


def regression_checks():
    target, u, n = search.serialize_hello('abcdefgh.example')
    benign, _, _ = search.serialize_hello('abcdxygh.example')
    models = {m.id:m for m in search.reference_models()}
    def seg(lo, hi, variant):
        return {'start':lo, 'end':hi, 'variant':variant, 'checksum':'valid', 'visibility':'ttl',
                'payload_hex':(target if variant == 'T' else benign)[lo:hi].hex()}
    a = [seg(u+2,u+6,'T'),seg(u+4,len(target),'B'),seg(0,u+2,'T')]
    b = [a[1],a[0],a[2]]
    expected = {'first':(1,0),'last':(0,1),'lower':(1,1),'higher':(0,0)}
    for policy, bits in expected.items():
        model = models[f'{policy}_contiguous_check']
        assert tuple(search.predict(p,model,target,benign,u,n)['prediction'] for p in [a,b]) == bits
        assert tuple(independent_prediction(p,vars(model),target,u,n)[0] for p in [a,b]) == bits
    late = [seg(0,len(target),'T'), seg(u+4,u+6,'B')]
    for model in models.values():
        result = search.predict(late,model,target,benign,u,n)
        if model.policy not in ('ack','ttl'):
            assert result['prediction'] == 1 and result['trigger_step'] == 1
    frontier_case = [seg(0,u+6,'B'),seg(u+4,u+6,'T'),seg(u+6,len(target),'T')]
    assert search.predict(frontier_case,models['last_contiguous_check'],target,benign,u,n)['prediction'] == 0
    assert search.predict(frontier_case,models['last_record_check'],target,benign,u,n)['prediction'] == 1
    assert search.geometry_state([(0,2)],10)['holes'] == []
    assert search.geometry_state([(3,5),(7,9)],10)['holes'] == [[0,3],[5,7]]
    # Exhaustively verify bounded generator with a separate Cartesian enumeration.
    endpoints = [0,1,2,3]
    choices = list(itertools.combinations(endpoints,2))
    expected_geometries = set()
    for budget in range(1,4):
        for history in itertools.product(choices,repeat=budget):
            if all(len(independent_geometry(history[:i+1],3)[0]) <= 1 for i in range(budget)) and independent_geometry(history,3)[2]:
                expected_geometries.add(history)
    stats = {'completion_lower_bound_prunes':0,'hole_bound_prunes':0,'budgets':[]}
    with contextlib.redirect_stdout(io.StringIO()):
        found = list(search.enumerate_histories(endpoints,3,3,1,100000,100000,stats))
    assert len(found) == len(set(found))
    assert set(found) == expected_geometries
    assert all(row['exhaustive'] for row in stats['budgets'])
    return {'pdf_page4_table':True,'irreversible_trigger':True,'frozen_vs_record_boundary':True,
            'future_suffix_not_a_hole':True,'small_domain_bruteforce_match':True,
            'small_domain_complete_geometries':len(found)}


def validate(data):
    cfg = data['meta']['config']; template = data['meta']['template']
    target = bytes.fromhex(template['target_hex'])
    benign = bytes.fromhex(template['benign_hex'])
    u,n,host = inspect_tls(target)
    ub,nb,benign_host = inspect_tls(benign)
    assert (u,n) == (ub,nb) == (template['sni_start'],template['sni_length'])
    assert host == template['target'] and benign_host == template['benign']
    assert len(target) == len(benign) == template['length']
    assert target[:u] == benign[:u] and target[u+n:] == benign[u+n:]
    assert [i for i,v in enumerate(target) if v == 46] == [i for i,v in enumerate(benign) if v == 46]
    assert len(target) <= cfg['receive_window']
    assert len(data['probes']) == data['summary']['probes']
    models = {m['id']:m for m in data['meta']['models']}
    ids = set(); identities = set(); prediction_checks = 0
    by_id = {}
    for p in data['probes']:
        assert p['id'] not in ids and p['identity_sha256'] not in identities
        ids.add(p['id']); identities.add(p['identity_sha256']); by_id[p['id']] = p
        probe_target = target[:u]+p.get('target_hostname',host).encode('ascii')+target[u+n:]
        probe_benign = benign[:u]+p.get('benign_hostname',benign_host).encode('ascii')+benign[u+n:]
        assert len(probe_target)==len(probe_benign)==len(target)
        inspect_tls(probe_target); inspect_tls(probe_benign)
        segments = p['segments']; geometry = []
        assert len(segments) == p['data_packets'] <= cfg['max_segments']
        max_holes = 0
        for step,s in enumerate(segments):
            assert 0 <= s['start'] < s['end'] <= len(target)
            assert s['seq_offset'] == s['start']
            assert s['payload_bytes'] == s['end']-s['start'] <= cfg['mss']
            assert bytes.fromhex(s['payload_hex']) == (probe_target if s['variant']=='T' else probe_benign)[s['start']:s['end']]
            assert s['visibility']=='ttl' or s['checksum']=='invalid'
            if p['family']=='ttl_valid': assert s['visibility']=='ttl' and s['checksum']=='valid'
            if p['family']=='full_bad_checksum': assert s['visibility']=='full' and s['checksum']=='invalid'
            geometry.append((s['start'],s['end']))
            holes,frontier,complete=independent_geometry(geometry,len(target))
            max_holes=max(max_holes,len(holes))
            trace=p['trace'][step]
            assert trace['holes']==holes and trace['frontier']==frontier and trace['complete']==complete
            assert trace['server_frontier']==0
        assert independent_geometry(geometry,len(target))[2]
        assert max_holes == p['max_holes'] <= cfg['max_holes']
        assert p['cost']==len(segments)+cfg['overhead']
        assert p['execution_packets']==3*cfg['repeats']*p['cost']
        assert p['observations'] is None and p['measurement_status']=='not_run'
        assert p['transport']['observed_server_data_acks']==0
        assert p['transport']['server_data_frontier']==0
        assert p['transport']['server_tls_reply_expected'] is False
        assert set(p['predictions'])==set(models)
        for ident,model in models.items():
            bit,trigger=independent_prediction(segments,model,probe_target,u,n)
            assert p['predictions'][ident]==bit, (p['id'],ident,bit)
            assert p['explanations'][ident]['trigger_step']==trigger
            prediction_checks+=1
        if 'control_predictions' in p:
            for control, template_bytes in [('all_target',probe_target),('all_benign',probe_benign)]:
                control_segments=[dict(s,payload_hex=template_bytes[s['start']:s['end']].hex()) for s in segments]
                for ident,model in models.items():
                    bit,_=independent_prediction(control_segments,model,probe_target,u,n)
                    assert p['control_predictions'][control][ident]==bit, (p['id'],control,ident)
                    prediction_checks+=1
    for suite in data['bundles']:
        programs=[by_id[p] for p in suite['probe_ids']]
        vectors={m:''.join(str(p['predictions'][m]) for p in programs) for m in suite['models']}
        assert vectors==suite['fingerprints']
        pairs=list(itertools.combinations(suite['models'],2))
        unresolved=[list(pair) for pair in pairs if vectors[pair[0]]==vectors[pair[1]]]
        assert len(pairs)==suite['total_pairs']
        assert len(pairs)-len(unresolved)==suite['separated_pairs']
        assert {tuple(x) for x in unresolved}=={tuple(x) for x in suite['unresolved_pairs']}
        assert len(set(vectors.values()))==suite['distinct_fingerprints']
        assert len(programs)==suite['connections']
        assert sum(p['data_packets'] for p in programs)==suite['data_packets']
        assert sum(p['cost'] for p in programs)==suite['cost']
        assert sum(p['execution_packets'] for p in programs)==suite['execution_packets']
    return {'status':'PASS','probes_checked':len(ids),'prediction_checks':prediction_checks,
            'independent_tls_parser':True,'literal_payloads_and_offsets':True,
            'independent_geometry_and_holes':True,'independent_prediction_replay':True,
            'bundle_costs_and_fingerprints':True,'all_observations_unmeasured':True,
            'regressions':regression_checks(),
            'limits':['Offline checks validate the declared reference models only.',
                      'No live Linux TCP, real DPI, route TTL or on-wire checksum validation was performed.']}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('results',type=Path,nargs='?',default=Path(__file__).with_name('results')/'results.json')
    args=ap.parse_args()
    data=json.loads(args.results.read_text())
    report=validate(data)
    data['validation']=report
    args.results.write_text(json.dumps(data,separators=(',',':')))
    (args.results.parent/'validation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


if __name__=='__main__': main()
