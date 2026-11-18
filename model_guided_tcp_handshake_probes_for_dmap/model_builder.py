#!/usr/bin/env python3
"""Build a compositional CPN before exploration. No endpoint simulation/oracle.

Every TCP effect is an explicit Petri transition with fixed colored input/output
arc inscriptions and integer place guards. The result is not a state-graph export.
"""
from pathlib import Path
import hashlib,json
import xml.etree.ElementTree as ET

PHASES=('DORMANT','LISTEN','SYN_RECV','ESTABLISHED','CLOSE_WAIT','LAST_ACK','FIN_WAIT1','FIN_WAIT2','CLOSING','TIME_WAIT','CLOSED')
SLOTS={'F0_G0':dict(flow='f0',generation=0,client='red',server='pink'),
       'F0_G1':dict(flow='f0',generation=1,client='blue',server='purple'),
       'F1_G1':dict(flow='f1',generation=1,client='blue',server='purple')}


def build(output=None):
    out=Path(output) if output else Path(__file__).with_name('model');out.mkdir(exist_ok=True,parents=True)
    project=ET.Element('project',name='Model-guided TCP handshake probes for dMAP',version='121')
    net=ET.SubElement(project,'gspn',name='CPN',zoom='75',**{'view-rates':'false','show-timed-cmd':'false'})
    nodes=ET.SubElement(net,'nodes');edges=ET.SubElement(net,'edges')
    ET.SubElement(nodes,'color-class',name='A_ISN',x='2',y='3',definition='{red,blue}')
    ET.SubElement(nodes,'color-class',name='S_ISN',x='2',y='8',definition='{pink,purple}')
    places={};annotations={};transition_counter=0
    def place(name,marking=0,domain=None,xy=None):
        if name in places:return
        attrs=dict(name=name,x=str((xy or (5,20+len(places)*4))[0]),y=str((xy or (5,20+len(places)*4))[1]))
        if marking:attrs['marking']=str(marking)
        if domain:attrs['domain']=domain
        places[name]=attrs;ET.SubElement(nodes,'place',**attrs)
    def mult(item):return '<'+item+'>' if isinstance(item,str) else str(item)
    def trans(name,ins=None,outs=None,reads=None,guard=None,meta=None):
        nonlocal transition_counter
        if name in annotations:raise ValueError('Duplicate native transition name: '+name)
        ins=dict(ins or {});outs=dict(outs or {})
        for p,v in (reads or {}).items():
            if p in ins or p in outs:raise ValueError('overlapping read '+p)
            ins[p]=v;outs[p]=v
        idx=transition_counter;transition_counter+=1
        attrs=dict(name=name,x=str(82+32*(idx//50)),y=str(24+7*(idx%50)),type='IMM')
        if guard:attrs['guard']=guard
        ET.SubElement(nodes,'transition',**attrs)
        for p,v in ins.items():ET.SubElement(edges,'arc',kind='INPUT',tail=p,head=name,mult=mult(v))
        for p,v in outs.items():ET.SubElement(edges,'arc',kind='OUTPUT',tail=name,head=p,mult=mult(v))
        annotations[name]=dict(meta or {})
    for name,mark in [('ATTACKER_READY',1),('G0_EVER_EST',0),('G0_LEFT_EST',0),('G1_EVER_EST',0),('G1_FREE',1),('READOUT_USED',0)]:place(name,mark)
    for j,(slot,info) in enumerate(SLOTS.items()):
        for k,ph in enumerate(PHASES):place(slot+'_'+ph,int(ph==('LISTEN' if info['generation']==0 else 'DORMANT')),xy=(12+26*j,22+k*6))
        place(slot+'_ATTACKER_ISN',domain='A_ISN',xy=(12+26*j,94))
        place(slot+'_SERVER_ISN',domain='S_ISN',xy=(12+26*j,100))
        place(slot+'_KNOWS_SERVER',domain='S_ISN',xy=(12+26*j,106))
        place(slot+'_SERVER_UNKNOWN',1,xy=(12+26*j,110))
        for k,label in enumerate(('A_FIN_SEEN','S_FIN_SENT','DATA_EMPTY','DATA_SEEN','REPLY_SA','REPLY_A','REPLY_FA','REPLY_R')):
            place(slot+'_'+label,int(label=='DATA_EMPTY'),xy=(12+26*j,114+6*k))
    def metadata(slot,phase,**extra):
        m=dict(SLOTS[slot],slot=slot,phase=phase,kind='packet',actor='attacker',flags='A',seq_relation='exact',ack_relation='exact',delivery='full',checksum='valid',payload='none',purpose='normal',ordinary_progress=False,accepted=False,family='validation')
        m.update(extra)
        if m['actor']=='attacker' and ('A' not in m['flags'] or m['ack_relation'] in ('none','blind')):m['server']=None
        if not m.get('ordinary_progress') and m['actor']=='attacker' and m['purpose']=='normal':
            m['decision_label']='|'.join(str(m.get(k,'')) for k in ('family','phase','flags','seq_relation','ack_relation','generation','delivery','checksum'))
        else:m['decision_label']=None
        return m
    def packet(slot,phase,label,after=None,reply=None,known=False,ordinary=False,guard=None,extra_ins=None,extra_outs=None,reads=None,**extra):
        info=SLOTS[slot];ins={'ATTACKER_READY':1,slot+'_'+phase:1};outs={slot+'_'+(after or phase):1};r=dict(reads or {})
        if reply:outs[slot+'_REPLY_'+reply]=1
        else:outs['ATTACKER_READY']=1
        if known:r[slot+'_KNOWS_SERVER']=info['server']
        ins.update(extra_ins or {});outs.update(extra_outs or {})
        # Existing incarnation color records remain retained after closure.
        if phase not in ('LISTEN','DORMANT'):
            r[slot+'_ATTACKER_ISN']=info['client'];r[slot+'_SERVER_ISN']=info['server']
        g=[]
        if guard:g.append(guard)
        if info['generation']==1:g.append('#G0_LEFT_EST >= 1')
        name='PACKET_SEND_ATTACKER_'+slot+'_'+label
        trans(name,ins,outs,r,' && '.join('('+x+')' for x in g) or None,
              metadata(slot,phase,ordinary_progress=ordinary,**extra))
    trans('WAIT_IDLE',reads={'ATTACKER_READY':1},
          guard=' && '.join('#'+slot+'_SYN_RECV == 0' for slot in SLOTS),
          meta=dict(kind='wait',actor='environment',ordinary_progress=True,purpose='normal',
                    wait_units=1,family='timing',decision_label=None,effect='explicit_abstract_idle_interval'))
    # Real allocation and knowledge are distinct transitions: only observed
    # genuine server SYNACK emits the incarnation-scoped knowledge token.
    for slot,info in SLOTS.items():
        initial='LISTEN' if info['generation']==0 else 'DORMANT'
        extra_ins={'G1_FREE':1} if info['generation'] else {}
        guard='#F0_G0_CLOSED == 1' if slot=='F0_G1' else None
        packet(slot,initial,'SYN',after='SYN_RECV',reply='SA',ordinary=True,flags='S',seq_relation='isn',ack_relation='none',accepted=True,family='setup',effect='allocate_request',extra_ins=extra_ins,
               extra_outs={slot+'_ATTACKER_ISN':info['client'],slot+'_SERVER_ISN':info['server']},guard=guard)
        for learn in (True,False):
            r={};outs={'ATTACKER_READY':1};ins={slot+'_REPLY_SA':1}
            if learn:
                ins[slot+'_SERVER_UNKNOWN']=1
                outs[slot+'_KNOWS_SERVER']=info['server']
            else:r[slot+'_KNOWS_SERVER']=info['server']
            trans('PACKET_SEND_SERVER_'+slot+'_SYNACK_'+('LEARN' if learn else 'KNOWN'),ins,outs,r,
                  meta=metadata(slot,'SYN_RECV',kind='packet',actor='server',flags='SA',seq_relation='isn',ack_relation='exact',ordinary_progress=True,accepted=True,family='setup',effect='genuine_SYN_ACK_observed'))
        for flag in ('A','FA','R'):
            trans('PACKET_SEND_SERVER_'+slot+'_'+flag,{slot+'_REPLY_'+flag:1},{'ATTACKER_READY':1},
                  meta=metadata(slot,'reply',actor='server',flags=flag,seq_relation='exact' if flag!='R' else 'blind',ack_relation='exact' if flag!='R' else 'none',ordinary_progress=True,accepted=True,family='forced_response',effect='genuine_TCP_response'))
        packet(slot,'SYN_RECV','ACK_ESTABLISH',after='ESTABLISHED',known=True,ordinary=True,flags='A',accepted=True,family='setup',effect='settled_ESTABLISHED',extra_outs={'G0_EVER_EST' if info['generation']==0 else 'G1_EVER_EST':1})
        # Existing request retransmission responds causally, without adding color.
        packet(slot,'SYN_RECV','DUPLICATE_SYN',reply='SA',flags='S',seq_relation='isn',ack_relation='none',family='allocation',effect='duplicate_SYN_request')
        # Reference teardown alternatives (passive, active, simultaneous close).
        left={'G0_LEFT_EST':1} if info['generation']==0 else {}
        packet(slot,'ESTABLISHED','FIN_PASSIVE',after='CLOSE_WAIT',reply='A',known=True,ordinary=True,flags='FA',accepted=True,family='termination',effect='peer_FIN_enters_CLOSE_WAIT',extra_outs={slot+'_A_FIN_SEEN':1,**left})
        for ph,after in [('ESTABLISHED','FIN_WAIT1'),('CLOSE_WAIT','LAST_ACK')]:
            ins={'ATTACKER_READY':1,slot+'_'+ph:1};outs={slot+'_'+after:1,slot+'_REPLY_FA':1,slot+'_S_FIN_SENT':1}
            if ph=='ESTABLISHED':outs.update(left)
            trans('SERVER_APPLICATION_CLOSE_'+slot+'_'+ph,ins,outs,{slot+'_SERVER_ISN':info['server']},meta=metadata(slot,ph,kind='internal',actor='environment',flags='',ordinary_progress=True,accepted=True,family='termination',effect='application_close_requests_FIN'))
        packet(slot,'LAST_ACK','ACK_PASSIVE_CLOSE_COMPLETE',after='CLOSED',known=True,ordinary=True,accepted=True,family='termination',effect='passive_close_complete')
        packet(slot,'FIN_WAIT1','ACK_FIN',after='FIN_WAIT2',known=True,ordinary=True,accepted=True,family='termination',effect='ACK_server_FIN')
        packet(slot,'FIN_WAIT1','FIN_SIMULTANEOUS_ACKED',after='TIME_WAIT',reply='A',known=True,ordinary=True,flags='FA',accepted=True,family='termination',effect='simultaneous_close_enters_TIME_WAIT',extra_outs={slot+'_A_FIN_SEEN':1})
        packet(slot,'FIN_WAIT1','FIN_SIMULTANEOUS_UNACKED',after='CLOSING',reply='A',known=True,ordinary=True,flags='FA',ack_relation='behind',accepted=True,family='termination',effect='simultaneous_close_enters_CLOSING',extra_outs={slot+'_A_FIN_SEEN':1})
        packet(slot,'FIN_WAIT2','FIN_ACTIVE_COMPLETE',after='TIME_WAIT',reply='A',known=True,ordinary=True,flags='FA',accepted=True,family='termination',effect='active_close_enters_TIME_WAIT',extra_outs={slot+'_A_FIN_SEEN':1})
        packet(slot,'CLOSING','ACK_CLOSE_COMPLETE',after='TIME_WAIT',known=True,ordinary=True,accepted=True,family='termination',effect='closing_ACK_enters_TIME_WAIT')
        trans('WAIT_'+slot+'_TIME_WAIT_EXPIRY',{'ATTACKER_READY':1,slot+'_TIME_WAIT':1},{'ATTACKER_READY':1,slot+'_CLOSED':1},meta=metadata(slot,'TIME_WAIT',kind='wait',actor='environment',flags='',ordinary_progress=True,wait_units=1,family='termination',effect='abstract_TIME_WAIT_expiry'))
        # Full and TTL-only readouts are PNPRO transitions themselves. This token
        # and DATA_EMPTY prevent more than one readout in a measurement replay.
        for delivery in ('full','dpi_only'):
            packet(slot,'ESTABLISHED','READOUT_'+delivery.upper(),reply='A' if delivery=='full' else None,known=True,ordinary=True,flags='PA',payload='readout',delivery=delivery,purpose='readout',accepted=delivery=='full',family='readout',effect='fixed_ClientHello_readout',extra_ins={slot+'_DATA_EMPTY':1},extra_outs={(slot+'_DATA_SEEN' if delivery=='full' else slot+'_DATA_EMPTY'):1,'READOUT_USED':1},guard='#READOUT_USED == 0')
        # Costed cleanup of every live record, with TIME_WAIT expiry above.
        live=('SYN_RECV','ESTABLISHED','CLOSE_WAIT','LAST_ACK','FIN_WAIT1','FIN_WAIT2','CLOSING')
        for ph in live:
            packet(slot,ph,'CLEANUP_RST_'+ph,after='CLOSED',ordinary=True,flags='R',ack_relation='none',purpose='cleanup',accepted=True,family='cleanup',effect='exact_sequence_cleanup_reset',extra_outs=left if ph=='ESTABLISHED' else {})
        # Designated insertion, validation and termination opportunities.
        for ph in (initial,)+live+('TIME_WAIT',):
            know=ph not in (initial,)
            for flags in ('S','R','A','FA'):
                ack='exact' if know and 'A' in flags else 'blind' if 'A' in flags else 'none'
                seq='isn' if ph==initial or flags=='S' else 'exact'
                for delivery,checksum in (('dpi_only','valid'),('full','invalid'),('dpi_only','invalid')):
                    family='visibility' if checksum=='valid' else 'checksum' if delivery=='full' else 'visibility_checksum'
                    packet(slot,ph,f'{family.upper()}_{flags}_{ph}',known=know and 'A' in flags,flags=flags,seq_relation=seq,ack_relation=ack,delivery=delivery,checksum=checksum,family=family,effect='absent_at_Linux' if delivery=='dpi_only' else 'invalid_TCP_checksum_rejected')
            if ph==initial:
                packet(slot,ph,'BLIND_ACK_LISTEN',reply='R',flags='A',seq_relation='isn',ack_relation='blind',family='allocation',effect='listener_rejects_ACK_without_disclosing_ISN')
                packet(slot,ph,'RST_LISTEN',flags='R',seq_relation='isn',ack_relation='none',family='reset',effect='listener_ignores_RST')
                continue
            if ph=='TIME_WAIT':
                packet(slot,ph,'RST_TIME_WAIT',flags='R',ack_relation='none',family='reset',effect='TIME_WAIT_retained_rfc1337_profile')
                continue
            for seq in ('exact','in_window','oow_left'):
                packet(slot,ph,'RST_'+seq.upper()+'_'+ph,after='CLOSED' if seq=='exact' else None,reply='A' if seq=='in_window' else None,
                       flags='R',seq_relation=seq,ack_relation='none',accepted=seq=='exact',family='reset',effect='accepted_reset' if seq=='exact' else 'challenge_ACK_RST' if seq=='in_window' else 'out_of_window_RST_ignored',extra_outs=left if ph=='ESTABLISHED' and seq=='exact' else {})
            for seq in ('in_window','oow_left','oow_right'):
                establishes=ph=='SYN_RECV' and seq=='in_window'
                progressed={'SYN_RECV':'ESTABLISHED','FIN_WAIT1':'FIN_WAIT2','CLOSING':'TIME_WAIT','LAST_ACK':'CLOSED'}.get(ph) if seq=='in_window' else None
                packet(slot,ph,'ACK_SEQ_'+seq.upper()+'_'+ph,after=progressed,
                       reply=None if seq=='in_window' else 'A',known=True,
                       flags='A',seq_relation=seq,family='sequence_validation',effect='inwindow_final_ACK_establishes' if establishes else 'sequence_validation_probe',
                       accepted=establishes,extra_outs={('G0_EVER_EST' if info['generation']==0 else 'G1_EVER_EST'):1} if establishes else {})
            for ack in ('behind','beyond'):
                packet(slot,ph,'ACK_VALUE_'+ack.upper()+'_'+ph,reply='R' if ph=='SYN_RECV' else 'A' if ack=='beyond' and ph!='ESTABLISHED' else None,
                       known=True,flags='A',ack_relation=ack,family='acknowledgment_validation',effect='ACK_validation_probe')
            for seq in ('in_window','oow_left'):
                establishes=ph=='SYN_RECV' and seq=='in_window'
                progressed={'SYN_RECV':'ESTABLISHED','FIN_WAIT1':'FIN_WAIT2','CLOSING':'TIME_WAIT','LAST_ACK':'CLOSED'}.get(ph) if seq=='in_window' else None
                packet(slot,ph,'FIN_SEQ_'+seq.upper()+'_'+ph,after=progressed,reply=None if progressed in ('TIME_WAIT','CLOSED') else 'A',known=True,flags='FA',seq_relation=seq,
                       family='early_fin',effect='unfilled_gap_FIN_retained_outside_explored_payload_range',accepted=establishes,
                       extra_outs={('G0_EVER_EST' if info['generation']==0 else 'G1_EVER_EST'):1} if establishes else {})
            if ph!='SYN_RECV':
                packet(slot,ph,'UNEXPECTED_SYN_'+ph,reply='A',flags='S',seq_relation='isn',ack_relation='none',family='allocation',effect='unexpected_SYN_validation')
            if info['generation']==1:
                for flags in ('R','A'):
                    packet(slot,ph,'OLD_'+flags+'_'+ph,reply=None if flags=='R' else 'R' if ph=='SYN_RECV' else 'A',
                           flags=flags,seq_relation='old',ack_relation='old' if flags=='A' else 'none',client='red',server='pink' if flags=='A' else None,
                           family='incarnation',old_reference=True,effect='old_incarnation_disjoint_sequence_window',reads={'F0_G0_KNOWS_SERVER':'pink'} if flags=='A' else {})
    # All TCP phase/control tokens have explicit fixed arc effects; annotations
    # never define an edge or change a marking in the explorer.
    path=out/'model_guided_tcp_handshake.PNPRO';ET.indent(project,space='  ');ET.ElementTree(project).write(path,encoding='utf-8',xml_declaration=True)
    profile={'title':'Model-guided TCP handshake probes for dMAP','slots':SLOTS,'phases':PHASES,
      'semantics':'Compositional literal-binding colored Petri net; XML arcs and guards are the executable source.',
      'ordinary_progress':'Fixed valid passive setup, ACK/FIN teardown variants, application close and normalized TIME_WAIT expiry.',
      'limitations':['Conservative symbolic TCP profile, not a pinned complete Linux kernel clone.','Passive server only; no server-initiated SYN or simultaneous active open.','Two total incarnation identities and two four-tuples; fresh disjoint sequence windows.','No loss, options, PAWS, backlog, SYN cookies, or segmentation/reassembly.','Ahead sequence representative leaves a 32768-byte gap; 100-byte readout never fills it; arbitrary out-of-order queue completion excluded.','Application close is an explicit modeled environment event; ACK/challenge rate limits assumed permit modeled reply.','TIME_WAIT fast reuse omitted; protected RST handling; wait units are abstract.','No DPI state/outcomes are modeled or measured.','Response ordering is serialized by ATTACKER_READY; one mandatory reply at a time.','No native GreatSPN parser/runtime executed in this environment.'],
      'cpn_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    (out/'annotations.json').write_text(json.dumps({'profile':profile,'transitions':annotations},indent=2))
    summary={'places':len(places),'transitions':len(annotations),'arcs':len(edges),'colored_classes':{'A_ISN':['red','blue'],'S_ISN':['pink','purple']},'construction':'CPN built before search from explicit Petri rules; no endpoint oracle or reachability graph conversion','cpn_sha256':profile['cpn_sha256'],'native_GreatSPN_executed':False}
    (out/'model_build_summary.json').write_text(json.dumps(summary,indent=2))
    return summary

if __name__=='__main__':print(json.dumps(build(),indent=2))
