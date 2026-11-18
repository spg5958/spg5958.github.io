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





def regression_checks():
    target, u, n = search.serialize_hello('abcdefgh.example')
    benign, _, _ = search.serialize_hello('abcdxygh.example')
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
    return {'future_suffix_not_a_hole':True,'small_domain_bruteforce_match':True,
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
    ids = set(); identities = set()
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
        assert independent_geometry(geometry,len(target))[2]
        assert max_holes == p['max_holes'] <= cfg['max_holes']
        assert p['cost']==len(segments)+cfg['overhead']
        assert p['execution_packets']==3*cfg['repeats']*p['cost']
        assert p['observations'] is None and p['measurement_status']=='not_run'
        assert p['transport']['observed_server_data_acks']==0
        assert p['transport']['server_data_frontier']==0
        assert p['transport']['server_tls_reply_expected'] is False
    for suite in data['bundles']:
        programs=[by_id[p] for p in suite['probe_ids']]
        assert len(programs)==suite['connections']
        assert sum(p['data_packets'] for p in programs)==suite['data_packets']
        assert sum(p['cost'] for p in programs)==suite['cost']
        assert sum(p['execution_packets'] for p in programs)==suite['execution_packets']
    return {'status':'PASS','probes_checked':len(ids),'independent_tls_parser':True,'literal_payloads_and_offsets':True,
            'independent_geometry_and_holes':True,
            'bundle_costs':True,'all_observations_unmeasured':True,
            'regressions':regression_checks(),
            'limits':['Offline checks validate packet serialization, geometry, transport bounds and nominal costs only.',
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
