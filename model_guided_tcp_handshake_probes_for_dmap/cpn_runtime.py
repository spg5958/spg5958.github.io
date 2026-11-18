"""Generic fixed-binding colored Petri-net interpreter for the PNPRO subset.

Only XML places, arc multiplicities and guards determine enabling and firing.
Annotations attach observation labels and carry no endpoint transition logic.
"""
from __future__ import annotations
import ast
from collections import Counter, defaultdict
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


class CPNModel:
    def __init__(self, path):
        self.path = Path(path)
        self.sha256 = hashlib.sha256(self.path.read_bytes()).hexdigest()
        tree = ET.parse(self.path)
        nodes = tree.find('.//nodes')
        names=[x.attrib['name'] for x in nodes]
        if len(names)!=len(set(names)):
            raise ValueError('Duplicate native node names in PNPRO')
        self.classes={x.attrib['name']:tuple(y.strip() for y in x.attrib['definition'].strip('{} ').split(',')) for x in nodes.findall('color-class')}
        self.place_defs={x.attrib['name']:x.attrib for x in nodes.findall('place')}
        self.atoms=[]
        for name,p in self.place_defs.items():
            self.atoms.extend((name,c) for c in self.classes[p['domain']]) if p.get('domain') else self.atoms.append((name,None))
        self.atom_index={a:i for i,a in enumerate(self.atoms)}
        self.place_indices={name:[i for i,(n,c) in enumerate(self.atoms) if n==name] for name in self.place_defs}
        initial=[0]*len(self.atoms)
        for name,p in self.place_defs.items():
            for color,num in self._mult(name,p.get('marking','0')).items():initial[self.atom_index[name,color]]+=num
        self._initial=tuple(initial)
        self.transitions=[x.attrib['name'] for x in nodes.findall('transition')]
        self.transition_defs={x.attrib['name']:x.attrib for x in nodes.findall('transition')}
        self.inputs={n:Counter() for n in self.transitions}; self.outputs={n:Counter() for n in self.transitions}
        for arc in tree.findall('.//arc'):
            a=arc.attrib
            if a['tail'] not in names or a['head'] not in names:
                raise ValueError('Dangling native arc endpoint')
            if a['kind']=='INPUT':target=self.inputs[a['head']];p=a['tail']
            elif a['kind']=='OUTPUT':target=self.outputs[a['tail']];p=a['head']
            else:raise ValueError('Unsupported arc kind '+a['kind'])
            for color,num in self._mult(p,a.get('mult','1')).items():target[self.atom_index[p,color]]+=num
        self._guards={}
        for n in self.transitions:
            raw=self.transition_defs[n].get('guard','True')
            refs=sorted(set(re.findall(r'#([A-Za-z_][A-Za-z0-9_]*)',raw)))
            for p in refs:
                if p not in self.place_defs:raise ValueError('unknown guard place '+p)
            expr=re.sub(r'#([A-Za-z_][A-Za-z0-9_]*)',lambda m:'v'+str(refs.index(m.group(1))),raw).replace('&&',' and ').replace('||',' or ')
            parsed=ast.parse(expr,mode='eval')
            allowed=(ast.Expression,ast.BoolOp,ast.And,ast.Or,ast.UnaryOp,ast.Not,ast.Compare,ast.Eq,ast.NotEq,ast.Lt,ast.LtE,ast.Gt,ast.GtE,ast.Constant,ast.Name,ast.Load)
            if any(not isinstance(x,allowed) for x in ast.walk(parsed)):raise ValueError('Unsupported guard '+raw)
            self._guards[n]=(compile(parsed,'<PNPRO guard>','eval'),refs)
        ann=self.path.with_name('annotations.json')
        payload=json.loads(ann.read_text()); self.annotations=payload['transitions']; self.profile=payload['profile']
        if set(self.annotations)!=set(self.transitions):raise ValueError('annotation/native transition mismatch')
        self._successors=lru_cache(maxsize=16000)(self._compute_successors)

    def _mult(self,place,text):
        text=text.strip()
        if text in ('','0'):return Counter()
        if self.place_defs[place].get('domain'):
            result=Counter()
            for part in text.split('+'):
                match=re.fullmatch(r'(?:(\d+)\s*\*?\s*)?<([^<>]+)>',part.strip())
                if not match:raise ValueError('Unsupported colored multiplicity '+text)
                color=match.group(2).strip()
                if color not in self.classes[self.place_defs[place]['domain']]:raise ValueError('Unknown color')
                result[color]+=int(match.group(1) or 1)
            return result
        return Counter({None:int(text)})

    def initial(self):return self._initial
    def key(self,marking):return marking
    def tokens(self,marking,place,color=None):
        if color is not None:return marking[self.atom_index[place,color]]
        return sum(marking[i] for i in self.place_indices.get(place,()))
    def enabled(self,marking,name):
        if any(marking[i]<num for i,num in self.inputs[name].items()):return False
        code,refs=self._guards[name]
        return bool(eval(code,{'__builtins__':{}},{'v'+str(i):self.tokens(marking,p) for i,p in enumerate(refs)}))
    def fire(self,marking,name):
        if not self.enabled(marking,name):raise ValueError('CPN transition is disabled: '+name)
        m=list(marking)
        for i,num in self.inputs[name].items():m[i]-=num
        for i,num in self.outputs[name].items():m[i]+=num
        return tuple(m)
    def _compute_successors(self,marking):
        return tuple((n,self.fire(marking,n),1) for n in self.transitions if self.enabled(marking,n))
    def successors(self,marking):return iter(self._successors(marking))
    def _relation_text(self,marking,meta,which):
        slot=meta.get('slot');base=meta.get('client') if which=='seq' else meta.get('server')
        actor=meta.get('actor')
        if actor=='server' and 'R' in meta.get('flags','') and which=='seq':
            return 'echo(SEG.ACK of triggering packet)'
        if actor=='server':base=meta.get('server') if which=='seq' else meta.get('client')
        relation=meta.get('seq_relation' if which=='seq' else 'ack_relation','none')
        if relation=='none':return '0 (unused)'
        if relation=='blind':return 'FIXED_UNRELATED'
        if not base:return 'FIXED_UNRELATED'
        old=meta.get('old_reference',False)
        if old:return base+'+1 (old incarnation)'
        if relation=='isn':return base
        receive=(which=='seq' and actor=='attacker') or (which=='ack' and actor=='server')
        extra=''
        if slot:
            if receive:
                if self.tokens(marking,slot+'_A_FIN_SEEN'):extra+='+1(FIN)'
                if self.tokens(marking,slot+'_DATA_SEEN'):extra+='+L_readout'
            elif self.tokens(marking,slot+'_S_FIN_SENT') and not (actor=='server' and which=='seq' and 'F' in meta.get('flags','')):extra+='+1(FIN)'
        text=base+'+1'+extra
        if relation=='in_window':return text+'+32768 (unfilled gap)'
        if relation=='oow_left':return text+'-65536'
        if relation=='oow_right':return text+'+131072'
        if relation=='behind':return base
        if relation=='beyond':return text+'+65536'
        return text
    def events(self,before,name,after):
        meta=dict(self.annotations[name]);kind=meta.get('kind','internal')
        if kind=='packet':
            meta['seq']=self._relation_text(before,meta,'seq');meta['ack']=self._relation_text(after if meta.get('actor')=='server' else before,meta,'ack')
            meta['linux_ip_arrival']=meta['actor']=='attacker' and meta.get('delivery')=='full'
            meta['linux_tcp_accepted']=meta.get('accepted',False)
            meta['dpi_visible']=True;meta['dpi_processing']='unmeasured'
        if kind=='wait':meta['units']=meta.get('wait_units',1)
        meta['transition']=name;meta['note']=meta.get('effect','');meta['state_after']=self.summary(after)
        return [meta]
    def summary(self,marking):
        result={}
        for slot in self.profile['slots']:
            phases=[p for p in self.profile['phases'] if self.tokens(marking,slot+'_'+p)]
            result[slot]=phases[0] if phases else 'INTERNAL'
        result['ready']=self.tokens(marking,'ATTACKER_READY')
        return result
    def checkpoint(self,marking):
        if not self.tokens(marking,'ATTACKER_READY'):return []
        result=[]
        for slot,info in self.profile['slots'].items():
            if self.tokens(marking,slot+'_ESTABLISHED'):
                result.append(dict(info,slot=slot,name=info['flow'],phase='ESTABLISHED'))
        return result
    def idle(self,marking):
        return self.tokens(marking,'ATTACKER_READY')==1 and all(self.tokens(marking,s+'_DORMANT') or self.tokens(marking,s+'_LISTEN') or self.tokens(marking,s+'_CLOSED') for s in self.profile['slots'])
