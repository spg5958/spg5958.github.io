"""Render exact structural schematic; executable CPN is the separate PNPRO file."""
from html import escape
from pathlib import Path


def render(path):
    out=['<svg xmlns="http://www.w3.org/2000/svg" width="1440" height="1080" viewBox="0 0 1440 1080">',
         '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10Z" fill="#64748b"/></marker></defs>',
         '<rect width="1440" height="1080" fill="#f3f6fb"/>']
    def text(x,y,value,size=17,fill='#25334a',weight='400',anchor='start'):
        out.append(f'<text x="{x}" y="{y}" font-family="Arial,Helvetica,sans-serif" font-size="{size}" fill="{fill}" font-weight="{weight}" text-anchor="{anchor}">{escape(value)}</text>')
    def box(x,y,w,h,title,lines,fill='#ffffff',accent='#1d4ed8'):
        out.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{fill}" stroke="#d8e0ec"/>')
        out.append(f'<rect x="{x}" y="{y+17}" width="5" height="25" rx="2" fill="{accent}"/>')
        text(x+20,y+37,title,19,weight='700')
        for i,line in enumerate(lines):text(x+20,y+68+i*25,line,15)
    def arrow(x1,y1,x2,y2,color='#64748b'):
        out.append(f'<path d="M{x1} {y1}L{x2} {y2}" fill="none" stroke="{color}" stroke-width="2" marker-end="url(#arr)"/>')
    text(36,48,'TCP lifecycle: offline reference and executable colored net',31,weight='700')
    text(36,78,'Structural schematic · PNPRO contains the executable bounded graph; this page explains its encoding.',17,fill='#64748b')
    box(36,108,1368,72,'Two incarnations, two four-tuples',[],fill='#eaf0ff')
    for i,(label,color) in enumerate([('red','#cf4c53'),('blue','#3776d2'),('pink','#d96caf'),('purple','#8557c5')]):
        x=600+170*i
        out.append(f'<circle cx="{x}" cy="144" r="11" fill="{color}"/>')
        text(x+20,150,label,18,weight='700')
    box(36,212,244,178,'Attacker action',[
        'Flags + SEQ / ACK relation', 'Flow f0 or f1 + incarnation',
        'Delivery + TCP checksum', 'Readout has length L_readout'])
    box(313,212,244,178,'Visibility / validation',[
        'DPI-only → no Linux event', 'Invalid TCP → reject at Linux',
        'Full + valid → reference TCP', 'DPI processing stays unknown'],accent='#d58221')
    box(590,212,244,178,'Endpoint transition',[
        'Both flow records retained', 'No guessed opaque server ISN',
        'Genuine effects and replies', 'One complete successor marking'])
    box(867,212,244,178,'Ordered wire events',[
        'Attacker send counts in N', 'Forced server sends count in N',
        'Every send has its own firing', 'Wait / observation ≠ send'])
    box(1144,212,260,178,'Attacker observation',[
        'Observe real reply → learn ISN', 'Deferred reply → pending token',
        'Observation is separately fired', 'Censorship bit Y is unmeasured'],accent='#8557c5')
    for x in [280,557,834,1111]:arrow(x+2,300,x+31,300)
    box(36,422,1368,270,'Live CPN marking',[],fill='#ffffff')
    box(58,505,325,155,'Flow f0 projection',[
        'TCP phase token', 'Attacker ISN / opaque server ISN',
        'Permanent passive listener profile'],fill='#f6f9ff')
    box(405,505,325,155,'Flow f1 projection',[
        'TCP phase token', 'Attacker ISN / opaque server ISN',
        'Independent four-tuple; no state erase'],fill='#f6f9ff')
    box(752,505,325,155,'Persistent memory',[
        'Attacker-known server identities', 'Retired client / server identities',
        'Pending unobserved server identity'],fill='#fbf7ff',accent='#8557c5')
    box(1099,505,285,155,'CState token',[
        'Complete encoded endpoint state', 'Guards the enabled source',
        'Mandatory response-chain lock'],fill='#eaf0ff')
    text(58,482,'First event consumes source projections. Last event restores target projections. Intermediate tokens preserve causal order.',16,fill='#53627c')
    text(36,718,'Reference lifecycle branches',23,weight='700')
    rows=[('SETUP',['LISTEN','SYN_RECV','ESTABLISHED'],'Valid third ACK; DEFER_ACCEPT off'),
          ('PASSIVE CLOSE',['ESTABLISHED','CLOSE_WAIT','LAST_ACK','LISTEN'],'Peer FIN, reference application close, ACK'),
          ('ACTIVE CLOSE',['ESTABLISHED','FIN_WAIT1','FIN_WAIT2','TIME_WAIT'],'Then explicit expiry restores LISTEN'),
          ('SIMULTANEOUS',['FIN_WAIT1','CLOSING','TIME_WAIT'],'ACK of own FIN completes closing')]
    for i,(label,states,note) in enumerate(rows):
        y=749+i*64
        text(36,y+25,label,13,fill='#64748b',weight='700')
        for j,state in enumerate(states):
            x=192+j*188
            out.append(f'<rect x="{x}" y="{y}" width="165" height="40" rx="20" fill="#ffffff" stroke="#ccd7e6"/>')
            text(x+82.5,y+25,state,13,weight='700',anchor='middle')
            if j<len(states)-1:arrow(x+167,y+20,x+184,y+20)
        text(978,y+25,note,14,fill='#53627c')
    text(36,1035,'Exact reset can retire an incarnation. Same-tuple reuse preserves closing / TIME_WAIT state until the profile permits reopening.',16,fill='#53627c')
    text(36,1062,'C = N + A + 2W + κT is applied to complete search prefixes; real DPI outcomes and discrimination remain unmeasured.',16,fill='#53627c')
    out.append('</svg>')
    Path(path).write_text('\n'.join(out))


if __name__=='__main__':
    render(Path(__file__).parent/'model/model_overview.svg')
