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
    probes=data['probes']; config=data['meta']['config']; models=data['meta']['models']
    rows=[]; packet_rows=[]; prediction_rows=[]
    for p in probes:
        rows.append({'id':p['id'],'title':p['title'],'family':p['family'],
                     'target':p['target_hostname'],'benign':p['benign_hostname'],
                     'data_packets':p['data_packets'],'max_holes':p['max_holes'],
                     'cost':p['cost'],'planned_packets_with_controls_repeats':p['execution_packets'],
                     'tags':'|'.join(p['tags']),'geometry_fixtures':'|'.join(p['dp_cases']),
                     'reference_pairs_split':p['separated_reference_pairs'],'actual_outcome':'UNMEASURED',
                     'figure':f'probe_images/{p["id"]}.svg'})
        for i,s in enumerate(p['segments'],1):
            packet_rows.append({'probe_id':p['id'],'packet_index':i,'start':s['start'],'end':s['end'],
                                'seq':f'CLIENT_ISN+1+{s["start"]}','ack':'SERVER_ISN+1',
                                'payload_bytes':s['payload_bytes'],'source':s['variant'],
                                'hostname_slice':s['hostname_slice'],'payload_hex':s['payload_hex'],
                                'visibility':s['visibility'],'tcp_checksum':s['checksum'],
                                'server_application_frontier':0,'server_data_ack_expected':False})
        for model in models:
            m=model['id']
            prediction_rows.append({'probe_id':p['id'],'model_id':m,'predicted_test_bit':p['predictions'][m],
                                    'predicted_all_target_bit':p['control_predictions']['all_target'][m],
                                    'predicted_all_benign_bit':p['control_predictions']['all_benign'][m],
                                    'hypothetical_hostname':p['explanations'][m]['hostname'],
                                    'trigger_data_packet':p['explanations'][m]['trigger_step'],
                                    'actual_censor_bit':''})
    write_csv(root/'experiments.csv',rows)
    write_csv(root/'packet_details.csv',packet_rows)
    write_csv(root/'predictions.csv',prediction_rows)
    bundle_rows=[]
    for b in data['bundles']:
        for m,bits in b['fingerprints'].items():
            bundle_rows.append({'bundle_id':b['id'],'model_id':m,'probe_order':'|'.join(b['probe_ids']),
                                'predicted_vector':bits,'data_packets':b['data_packets'],'test_connections':b['connections'],
                                'cost':b['cost'],'planned_packets_with_controls_repeats':b['execution_packets']})
    write_csv(root/'bundle_fingerprints.csv',bundle_rows)
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
           f'{len(models)} illustrative hypotheses; {trial_count:,} planned fresh-connection trials including matched controls and repetitions. No real DPI observations.',
           '', '## Bounds and computation','',
           f'- Serialized TLS ClientHello: {data["meta"]["template"]["length"]} bytes; hostname interval [{data["meta"]["template"]["sni_start"]}, {data["meta"]["template"]["sni_start"]+data["meta"]["template"]["sni_length"]}).',
           f'- At most {config["max_segments"]} data packets and {config["max_holes"]} simultaneous holes; every framing/gap packet counted.',
           f'- Search time: {stats["elapsed_seconds"]} seconds on this host; this is not an Apple M2 benchmark.',
           '- Ordered geometry enumeration is exhaustive at completed budgets marked exhaustive in search_summary.json. Payload synthesis is model guided.',
           '- Higher budgets use declared resource cutoffs. The selected library and greedy bundles are not globally optimal or globally shortest.',
           '', '| Data packets | Retained programs |','|---:|---:|']
    for k,v in summary['data_packet_distribution'].items(): lines.append(f'| {k} | {v} |')
    lines+=['','## Binary fingerprint bundles','','| Bundle | Connections | Data packets | Predicted vectors | Separated pairs | Nominal repeated-control packets |',
            '|---|---:|---:|---:|---:|---:|']
    for b in data['bundles']:
        lines.append(f'| {b["title"]} | {b["connections"]} | {b["data_packets"]} | {b["distinct_fingerprints"]} | {b["separated_pairs"]}/{b["total_pairs"]} | {b["execution_packets"]} |')
    lines+=['','## Interpretation','',
            '- The four-policy page-4 pair reproduces first=10, last=01, lower-start=11, higher-start=00 when read in A,B order.',
            '- Real observations are null. A predicted bit is not a measured DPI result or a proven implementation identity.',
            '- 19 descriptive geometry fixtures are represented. Exact Dharmapurikar–Paxson Figure 4 A–T mapping remains unverified; no audited 20/20 coverage claim.',
            '- h=4 assumes a three-packet ordinary handshake plus a genuine-state client RST. Nominal cost includes three trial types and three repetitions.',
            '- Actual execution totals additionally require measured calibration, retransmissions/injected traffic and waits. Those fields remain null.',
            '- Server silence, ordinary resets, ICMP expiry and local timeouts do not by themselves establish censorship.',
            '', '## Files','',
            'Open index.html. It contains all result data and works without a local web server or external assets. Figures and machine tables are included alongside it.']
    (root/'RESULTS.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'exported_probes':len(probes),'packet_rows':len(packet_rows),'prediction_rows':len(prediction_rows),'unmeasured_trial_rows':trial_count}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results',type=Path)
    export(parser.parse_args().results)
