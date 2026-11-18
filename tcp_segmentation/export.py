#!/usr/bin/env python3
"""Write CSV tables, null-observation trial plans and concise result notes."""
import argparse
import csv
import json
from pathlib import Path

def write_csv(path,rows):
    rows=list(rows)
    if not rows: return
    with path.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)

def export(result_path):
    data=json.loads(result_path.read_text())
    root=result_path.parent
    probes=data['probes']; config=data['meta']['config']
    rows=[]; packet_rows=[]
    for p in probes:
        rows.append({'id':p['id'],'title':p['title'],'family':p['family'],
                     'target':p['target_hostname'],'benign':p['benign_hostname'],
                     'data_packets':p['data_packets'],'max_holes':p['max_holes'],
                     'cost':p['cost'],'planned_packets_with_controls_repeats':p['execution_packets'],
                     'tags':'|'.join(p['tags']),'geometry_fixtures':'|'.join(p['dp_cases']),
                     'actual_outcome':'UNMEASURED',
                     'figure':f'probe_images/{p["id"]}.svg'})
        for i,s in enumerate(p['segments'],1):
            packet_rows.append({'probe_id':p['id'],'packet_index':i,'start':s['start'],'end':s['end'],
                                'seq':f'CLIENT_ISN+1+{s["start"]}','ack':'SERVER_ISN+1',
                                'payload_bytes':s['payload_bytes'],'source':s['variant'],
                                'hostname_slice':s['hostname_slice'],'payload_hex':s['payload_hex'],
                                'visibility':s['visibility'],'tcp_checksum':s['checksum'],
                                'server_application_frontier':0,'server_data_ack_expected':False})
    write_csv(root/'experiments.csv',rows)
    write_csv(root/'packet_details.csv',packet_rows)
    write_csv(root/'bundles.csv',[
        {'bundle_id':b['id'],'title':b['title'],'probe_order':'|'.join(b['probe_ids']),
         'connections':b['connections'],'data_packets':b['data_packets'],'cost':b['cost'],
         'planned_packets_with_controls_repeats':b['execution_packets']} for b in data['bundles']])
    trial_count=0
    with (root/'measurement_plan.jsonl').open('w') as f:
        for p in probes:
            for repeat in range(1,config['repeats']+1):
                for typ,override in [('test',None),('all_target','T'),('all_benign','B')]:
                    trial={'trial_id':f'{p["id"]}_{typ}_R{repeat}','probe_id':p['id'],
                           'type':typ,'repetition':repeat,'fresh_connection':True,
                           'segment_variant_override':override,
                           'packet_program_reference':{'file':'results.json','probe_id':p['id'],'lookup':'probes array by id'},
                           'keep_visibility_checksum_and_interval_geometry':True,
                           'planned_wire_packets':p['cost'],'status':'not_run',
                           'evaluable':None,'observed_censored':None,'quality_failure':None,
                           'calibration_id':None,'observation_interval_seconds':None,
                           'actual_wire_packets':None,'observed_server_data_acks':None}
                    f.write(json.dumps(trial,separators=(',',':'))+'\n')
                    trial_count+=1
    summary=data['summary']; stats=data['meta']['search']
    lines=['# TCP segmentation search: computed results','',
           f'{len(probes):,} distinct offline packet programs retained from {stats["candidate_pool"]:,} synthesized candidates.',
           f'{trial_count:,} planned fresh-connection trials including controls and repetitions. No real DPI observations.',
           '', '## Bounds and computation','',
           f'- Serialized TLS ClientHello: {data["meta"]["template"]["length"]} bytes; hostname interval [{data["meta"]["template"]["sni_start"]}, {data["meta"]["template"]["sni_start"]+data["meta"]["template"]["sni_length"]}).',
           f'- At most {config["max_segments"]} data packets and {config["max_holes"]} simultaneous holes; every framing/gap packet counted.',
           f'- Search time: {stats["elapsed_seconds"]} seconds on this host; this is not an Apple M2 benchmark.',
           '- Ordered geometry enumeration is exhaustive at completed budgets marked exhaustive in search_summary.json. Payload assignments use a declared finite profile.',
           '- Higher budgets use declared resource cutoffs. The selected library and greedy bundles are not globally optimal or globally shortest.',
           '', '| Data packets | Retained programs |','|---:|---:|']
    for k,v in summary['data_packet_distribution'].items(): lines.append(f'| {k} | {v} |')
    lines+=['','## Measurement bundles','','| Bundle | Connections | Data packets | Nominal repeated-control packets |',
            '|---|---:|---:|---:|']
    for b in data['bundles']:
        lines.append(f'| {b["title"]} | {b["connections"]} | {b["data_packets"]} | {b["execution_packets"]} |')
    lines+=['','## Interpretation','',
            '- All actual observations remain null. The tables describe packet programs, costs and future measurement procedures.',
            '- 19 descriptive geometry fixtures are represented. Exact Dharmapurikar–Paxson Figure 4 A–T mapping remains unverified; no audited 20/20 coverage claim.',
            '- h=4 assumes a three-packet ordinary handshake plus a genuine-state client RST. Nominal cost includes three trial types and three repetitions.',
            '- Actual execution totals additionally require measured calibration, retransmissions/injected traffic and waits. Those fields remain null.',
            '- Server silence, ordinary resets, ICMP expiry and local timeouts do not by themselves establish censorship.',
            '', '## Files','',
            'Open index.html. It contains all result data and works without a local web server or external assets. Figures and machine tables are included alongside it.']
    (root/'RESULTS.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'exported_probes':len(probes),'packet_rows':len(packet_rows),'unmeasured_trial_rows':trial_count}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results',type=Path)
    export(parser.parse_args().results)
