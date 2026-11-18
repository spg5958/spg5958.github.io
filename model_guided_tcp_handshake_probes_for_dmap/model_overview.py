"""Render a readable skeleton of the executable CPN (Graphviz optional)."""
from pathlib import Path
import subprocess

DOT=r'''digraph CPN {
 graph [rankdir=TB,bgcolor="white",pad="0.4",nodesep="0.4",ranksep="0.55",fontname="Arial",label="Model-guided TCP handshake probes for dMAP\nOrdinary lifecycle skeleton; full colored bindings and probe rules are in PNPRO",labelloc=t,fontsize=20];
 node [fontname="Arial",fontsize=11,color="#507080",fontcolor="#183442",style=filled,fillcolor="#f1f7f8"];
 edge [fontname="Arial",fontsize=9,color="#497384",fontcolor="#42606d",arrowsize=.7];
 subgraph cluster_resources {
 label="Shared resources and scoped attacker knowledge";color="#b8ced7";style=rounded;
 READY [shape=circle,label="ATTACKER\nREADY",fillcolor="#d8efe9"];
 REPLY [shape=circle,label="Mandatory\nreply bank",fillcolor="#e8eff7"];
 PSEND [shape=box,label="Attacker packet\nPNPRO firing",fillcolor="#fff0d8"];
 SSEND [shape=box,label="Genuine server\npacket firing",fillcolor="#d8efe9"];
 KNOWN [shape=circle,label="Known ISN\npink / purple",fillcolor="#f1dff1"];
 READY->PSEND->REPLY->SSEND->READY;
 SSEND->KNOWN [label="SYN-ACK observation only"];
 }
 subgraph cluster_lifecycle {
 label="Per-incarnation phase places and reference transitions";color="#b8ced7";style=rounded;
 LISTEN [shape=circle,label="LISTEN /\nDORMANT"];
 SYN_RECV [shape=circle,label="SYN_RECV"];
 EST [shape=circle,label="ESTABLISHED",fillcolor="#d5efe5"];
 CLOSE_WAIT [shape=circle,label="CLOSE_WAIT"];
 LAST_ACK [shape=circle,label="LAST_ACK"];
 FIN_WAIT1 [shape=circle,label="FIN_WAIT1"];
 FIN_WAIT2 [shape=circle,label="FIN_WAIT2"];
 CLOSING [shape=circle,label="CLOSING"];
 TIME_WAIT [shape=circle,label="TIME_WAIT"];
 CLOSED [shape=circle,label="CLOSED",fillcolor="#e3eaf0"];
 SYN [shape=box,label="SYN + mandatory\nSYN-ACK"];
 ACK [shape=box,label="Knowledge-guarded\nfinal ACK"];
 FIN [shape=box,label="Peer FIN + ACK"];
 PCLOSE [shape=box,label="Application close\n+ FIN-ACK"];
 LAST [shape=box,label="ACK of FIN"];
 ACTIVE [shape=box,label="Application close\n+ FIN-ACK"];
 FINACK [shape=box,label="ACK of FIN"];
 PEERFIN [shape=box,label="Peer FIN + ACK"];
 SIM [shape=box,label="Crossed FIN\nwith old ACK"];
 SIMACK [shape=box,label="ACK of FIN"];
 WAIT [shape=box,label="Explicit normalized\nTIME_WAIT expiry"];
 LISTEN->SYN->SYN_RECV->ACK->EST;
 EST->FIN->CLOSE_WAIT->PCLOSE->LAST_ACK->LAST->CLOSED;
 EST->ACTIVE->FIN_WAIT1->FINACK->FIN_WAIT2->PEERFIN->TIME_WAIT->WAIT->CLOSED;
 FIN_WAIT1->SIM->CLOSING->SIMACK->TIME_WAIT;
 }
 INST [shape=note,label="Three instantiated subnets:\nf0 / g0 = red, pink\nf0 / g1 = blue, purple\nf1 / g1 = blue, purple\n\nG1_FREE permits only one second incarnation.\nSame-tuple g1 requires old f0 record CLOSED.\nDifferent-tuple g1 retains old f0 phase/state."];
 PROBES [shape=note,label="Probe transitions (full PNPRO):\nDPI-only expiry and invalid checksum\nleave endpoint phase/ISNs unchanged.\nSEQ/ACK/RST/FIN validation alternatives\npreserve actual mandatory reply order.\n\nFull readout changes DATA_SEEN;\nDPI-only readout changes only the\nexperiment marker READOUT_USED."];
 KNOWN->ACK [style=dashed,label="read/test arc"];
 CLOSED->INST [style=dashed,arrowhead=none];
 EST->PROBES [style=dashed,arrowhead=none];
}'''

def render(output=None):
    out=Path(output) if output else Path(__file__).with_name('model');out.mkdir(exist_ok=True)
    (out/'model_overview.dot').write_text(DOT)
    subprocess.run(['dot','-Tsvg',str(out/'model_overview.dot'),'-o',str(out/'model_overview.svg')],check=True)
    return out/'model_overview.svg'

if __name__=='__main__':print(render())
