"""Offline, finite symbolic TCP endpoint reference. No sockets or packet emission.

This is a conservative model profile, not an implementation-equivalent Linux
interpreter. In particular TIME_WAIT early reuse, SACK/PAWS, options, congestion,
queues of application data and rate-limiting are outside this pilot.
"""
from __future__ import annotations
from dataclasses import dataclass, replace, asdict
from typing import Optional

ATTACKER_COLORS = ('red', 'blue')
SERVER_COLORS = ('pink', 'purple')
MAX_INCAR = 2
WAIT_UNIT_SECONDS = None  # Abstract configured interval; no wall-clock mapping is asserted.

@dataclass(frozen=True)
class Flow:
    name: str
    phase: str = 'LISTEN'
    generation: int = -1
    client: Optional[str] = None
    server: Optional[str] = None
    established: bool = False
    rcv_offset: int = 0
    snd_offset: int = 0
    timer_age: int = 0
    readout_units: int = 0

@dataclass(frozen=True)
class Pending:
    """A transmitted server reply awaiting attacker observation; no retransmission."""
    flow: str
    generation: int
    server: Optional[str]
    flags: str
    seq: str
    ack: str

@dataclass(frozen=True)
class State:
    flows: tuple[Flow, ...] = (Flow('f0'), Flow('f1'))
    knowledge: tuple[tuple[str, int, str], ...] = ()
    pending: tuple[Pending, ...] = ()
    retired: tuple[Flow, ...] = ()
    next_generation: int = 0
    elapsed_units: int = 0

@dataclass(frozen=True)
class Action:
    kind: str = 'packet'
    flow: str = 'f0'
    flags: str = 'A'
    seq: str = 'exact'
    ack: str = 'exact'
    client: Optional[str] = None
    server: Optional[str] = None
    delivery: str = 'full'
    checksum: str = 'valid'
    payload: str = 'none'
    defer_reply: bool = False

@dataclass(frozen=True)
class Outcome:
    state: State
    events: tuple[dict, ...]
    accepted: bool
    effect: str


def initial_state():
    return State()


def get_flow(state: State, name: str) -> Flow:
    return next(f for f in state.flows if f.name == name)


def state_summary(state: State):
    return {f.name: f'{f.phase}:g{f.generation}:{f.client}/{f.server}' for f in state.flows}


def _put(state, flow):
    return replace(state, flows=tuple(flow if f.name == flow.name else f for f in state.flows))


def _learn(state, flow, generation, server):
    if server is None:
        return state
    item = (flow, generation, server)
    return state if item in state.knowledge else replace(state, knowledge=tuple(sorted(state.knowledge + (item,))))


def knows(state, flow):
    return (flow.name, flow.generation, flow.server) in state.knowledge


def _symbol(color, offset, readout_units=0):
    ordinary_offset = offset - readout_units
    text = str(color) if ordinary_offset == 0 else f'{color}+{ordinary_offset}'
    if readout_units:
        text += '+L_readout' if readout_units == 1 else f'+{readout_units}*L_readout'
    return text


def _relation_text(flow, action, which):
    relation = action.seq if which == 'seq' else action.ack
    color = action.client or flow.client if which == 'seq' else action.server or flow.server
    offset = flow.rcv_offset if which == 'seq' else flow.snd_offset
    if relation == 'exact':
        return _symbol(color or 'OWN_ISN', offset, flow.readout_units if which == 'seq' else 0)
    if relation == 'in_window' and which == 'seq':
        return _symbol(color or 'OWN_ISN', offset, flow.readout_units) + '+32768 (in-window; unfilled gap)'
    if relation == 'isn':
        return str(color or 'OWN_ISN')
    if relation == 'none':
        return '0 (unused)'
    if relation == 'blind':
        return 'FIXED_UNRELATED'
    return f'{relation}({color or "OWN_ISN"};ref+{offset})'


def _packet_event(flow, action):
    return dict(kind='packet', type='packet', actor='attacker', flow=flow.name,
                generation=flow.generation, flags=action.flags,
                seq=_relation_text(flow, action, 'seq'), ack=_relation_text(flow, action, 'ack'),
                seq_relation=action.seq, ack_relation=action.ack,
                client=action.client or flow.client, server=action.server,
                delivery=action.delivery, checksum=action.checksum, payload=action.payload,
                dpi_visible=True, linux_ip_arrival=action.delivery == 'full',
                linux_tcp_accepted=False, dpi_processing='unmeasured',
                payload_length='L_readout' if action.payload == 'readout' else 0, note='')


def _reply(state, flow, flags, events, defer=False, note='', seq=None, ack=None):
    seq = seq or _symbol(flow.server or 'RST_FROM_ACK', max(0, flow.snd_offset - (1 if 'S' in flags or 'F' in flags else 0)))
    ack = ack or _symbol(flow.client or 'SEG.SEQ', flow.rcv_offset, flow.readout_units)
    event = dict(kind='packet', type='packet', actor='server', flow=flow.name,
                 generation=flow.generation, flags=flags, seq=seq, ack=ack,
                 client=flow.client, server=flow.server, delivery='full', checksum='valid',
                 payload='none', dpi_visible=True, linux_ip_arrival=False,
                 linux_tcp_accepted=True, dpi_processing='unmeasured',
                 observed_by_attacker=not defer, note=note)
    events.append(event)
    # A LISTEN reset echoes attacker ACK; it does not disclose a chosen server ISN.
    learnable = flow.server if 'R' not in flags else None
    if defer:
        if state.pending:
            raise ValueError('pilot permits at most one deferred server observation')
        return replace(state, pending=(Pending(flow.name, flow.generation, learnable, flags, seq, ack),))
    return _learn(state, flow.name, flow.generation, learnable)


def _action(flow, **kwargs):
    defaults = dict(flow=flow.name, client=flow.client, server=flow.server,
                    ack='exact' if flow.server else 'none')
    defaults.update(kwargs)
    return Action(**defaults)


def unused_attacker_colors(state: State):
    used = {f.client for f in state.flows + state.retired if f.generation >= 0}
    return tuple(c for c in ATTACKER_COLORS if c not in used)


def ordinary_actions(state: State):
    """Small fixed reference automaton: legitimate setup and close variants."""
    actions = []
    for flow in state.flows:
        if flow.phase == 'LISTEN' and state.next_generation < MAX_INCAR:
            # Both attacker ISNs are available; server identity is selected by endpoint.
            for color in unused_attacker_colors(state):
                actions.append(_action(flow, flags='S', seq='isn', ack='none', client=color, server=None))
        elif flow.phase == 'SYN_RECV' and knows(state, flow):
            actions.append(_action(flow, flags='A'))
        elif flow.phase == 'ESTABLISHED' and knows(state, flow):
            actions.extend((_action(flow, flags='FA'), Action(kind='server_close', flow=flow.name)))
        elif flow.phase == 'CLOSE_WAIT':
            actions.append(Action(kind='server_close', flow=flow.name))
        elif flow.phase in ('FIN_WAIT1', 'CLOSING', 'LAST_ACK') and knows(state, flow):
            actions.append(_action(flow, flags='A'))
            if flow.phase == 'FIN_WAIT1':
                # FIN ACKs the peer FIN: completed simultaneous close in one action.
                actions.append(_action(flow, flags='FA'))
                # FIN whose ACK does not cover server FIN enters CLOSING.
                actions.append(_action(flow, flags='FA', ack='behind'))
        elif flow.phase == 'FIN_WAIT2' and knows(state, flow):
            actions.append(_action(flow, flags='FA'))
    if state.pending:
        actions.append(Action(kind='deliver_pending', flow=state.pending[0].flow))
    if any(f.phase == 'TIME_WAIT' for f in state.flows) and not any(f.phase == 'SYN_RECV' for f in state.flows):
        actions.append(Action(kind='wait', ack='none'))
    return list(dict.fromkeys(actions))


def enabled_actions(state: State, include_departures=True):
    """Finite pilot alphabet, not the Cartesian product of TCP header fields."""
    actions = ordinary_actions(state)
    if not include_departures:
        return actions
    for flow in state.flows:
        client = flow.client or (unused_attacker_colors(state) or ATTACKER_COLORS)[0]
        known = knows(state, flow)
        base = _action(flow, client=client, server=flow.server if known else None,
                       ack='exact' if known else 'blind')
        # Unknown server symbols are never placed in attacker packets.
        controls = [replace(base, flags='S', seq='isn', ack='none', server=None),
                    replace(base, flags='R', ack='none', server=None)]
        if known:
            controls += [replace(base, flags='A'), replace(base, flags='FA'),
                         replace(base, flags='RA'), replace(base, flags='SA')]
        else:
            controls += [replace(base, flags='A', seq='isn', ack='blind', server=None)]
        for action in controls:
            actions.append(action)
            actions.append(replace(action, delivery='dpi_only'))
            actions.append(replace(action, checksum='invalid'))
            actions.append(replace(action, delivery='dpi_only', checksum='invalid'))
        if known and flow.phase != 'LISTEN':
            for seq in ('in_window', 'oow_left', 'oow_right'):
                actions.extend((replace(base, flags='RA', seq=seq), replace(base, flags='FA', seq=seq)))
            for ack in ('behind', 'beyond'):
                actions.append(replace(base, flags='A', ack=ack))
            if flow.phase in ('CLOSE_WAIT', 'LAST_ACK', 'CLOSING'):
                actions.append(replace(base, flags='R', seq='previous', ack='none', server=None))
        # Delayed server observation is a causal ordering opportunity, never packet loss.
        if flow.phase == 'LISTEN' and not state.pending and state.next_generation < MAX_INCAR:
            actions.append(replace(base, flags='S', seq='isn', ack='none', server=None, defer_reply=True))
        for old in state.retired:
            if old.name == flow.name and old.client is not None:
                old_known = (old.name, old.generation, old.server) in state.knowledge
                actions.append(Action(flow=flow.name, flags='RA', seq='old', ack='old' if old_known else 'blind',
                                      client=old.client, server=old.server if old_known else None))
                actions.append(Action(flow=flow.name, flags='FA', seq='old', ack='old' if old_known else 'blind',
                                      client=old.client, server=old.server if old_known else None, delivery='dpi_only'))
    # Explicit waits can test timeout questions even outside TIME_WAIT.
    if not any(f.phase == 'SYN_RECV' for f in state.flows):
        actions.append(Action(kind='wait', ack='none'))
    return list(dict.fromkeys(actions))


def _validate(state, action):
    if action.flow not in ('f0', 'f1'):
        raise ValueError('unknown four-tuple symbol')
    if action.client not in ATTACKER_COLORS + (None,):
        raise ValueError('unknown attacker color')
    if action.server not in SERVER_COLORS + (None,):
        raise ValueError('unknown server color')
    if action.delivery not in ('full', 'dpi_only') or action.checksum not in ('valid', 'invalid'):
        raise ValueError('invalid visibility/checksum attribute')
    if action.kind == 'packet' and action.flags == 'S' and action.delivery == 'full' and action.checksum == 'valid':
        flow = get_flow(state, action.flow)
        if flow.phase == 'LISTEN' and action.client not in unused_attacker_colors(state):
            raise ValueError('pilot requires a distinct attacker ISN identity for each real incarnation')
    if action.kind == 'packet' and action.server is not None:
        if not any(item[2] == action.server for item in state.knowledge):
            raise ValueError('attacker cannot use opaque server ISN before observation')
    if action.kind == 'packet' and 'A' in action.flags and action.ack in ('exact', 'behind', 'beyond'):
        flow = get_flow(state, action.flow)
        if action.server != flow.server or not knows(state, flow):
            raise ValueError('ACK relation requires knowledge of current server incarnation')


def step(state: State, action: Action):
    """Return ordered successors; deterministic within this frozen pilot profile."""
    _validate(state, action)
    flow = get_flow(state, action.flow)
    events = []
    if action.kind == 'deliver_pending':
        if not state.pending:
            return []
        pending = state.pending[0]
        state = replace(state, pending=state.pending[1:])
        state = _learn(state, pending.flow, pending.generation, pending.server)
        event = dict(kind='observation', type='observation', actor='attacker', flow=pending.flow,
                     generation=pending.generation, note=f'observe delayed {pending.flags}; no new transmission')
        return [Outcome(state, (event,), True, 'observe_queued_reply')]
    if action.kind == 'wait':
        if any(f.phase == 'SYN_RECV' for f in state.flows):
            # Request retransmission timers are outside this pilot; do not invent an idle timeout.
            return []
        flows = []
        effects = []
        retired = state.retired
        for f in state.flows:
            if f.phase != 'LISTEN':
                f = replace(f, timer_age=f.timer_age + 1)
            if f.phase == 'TIME_WAIT' and f.timer_age >= 1:
                retired += (f,)
                effects.append(f'{f.name}:TIME_WAIT expires')
                f = Flow(f.name)
            elif f.phase == 'SYN_RECV' and f.timer_age >= 3:
                # Timeout is normalized as full request expiration (no hidden retries).
                retired += (f,)
                effects.append(f'{f.name}:request expires')
                f = Flow(f.name)
            flows.append(f)
        state = replace(state, flows=tuple(flows), retired=retired, elapsed_units=state.elapsed_units + 1)
        events.append(dict(kind='wait', type='wait', actor='environment', units=1,
                           seconds=None, note='; '.join(effects) or 'explicit abstract wait unit; physical duration uncalibrated'))
        return [Outcome(state, tuple(events), True, 'wait')]
    if action.kind == 'server_close':
        if flow.phase not in ('ESTABLISHED', 'CLOSE_WAIT'):
            return []
        newflow = replace(flow, phase='FIN_WAIT1' if flow.phase == 'ESTABLISHED' else 'LAST_ACK',
                          snd_offset=flow.snd_offset + 1, timer_age=0)
        state = _put(state, newflow)
        state = _reply(state, newflow, 'FA', events, note='reference application requests close')
        return [Outcome(state, tuple(events), True, 'server_close')]
    if action.kind != 'packet':
        raise ValueError('unknown action kind')
    event = _packet_event(flow, action)
    events.append(event)
    if action.delivery == 'dpi_only':
        event['note'] = 'calibrated DPI-visible expiry before endpoint; no Linux reply'
        return [Outcome(state, tuple(events), False, 'absent_at_linux')]
    if action.checksum == 'invalid':
        event['note'] = 'TCP checksum remains invalid on arrival; Linux rejects; no reply'
        return [Outcome(state, tuple(events), False, 'checksum_reject')]
    flags, seq, ack = action.flags, action.seq, action.ack
    effect = 'drop'
    accepted = False
    if flow.phase == 'LISTEN':
        if 'R' in flags:
            effect = 'listen_ignore_rst'
        elif 'A' in flags:
            # Listener rejects an ACK with RST whose seq echoes SEG.ACK.
            state = _reply(state, flow, 'R', events, action.defer_reply,
                           'listener reset; does not disclose an opaque ISN',
                           seq=event['ack'], ack='0 (unused)')
            effect = 'listen_reset_ack'
        elif flags == 'S' and state.next_generation < MAX_INCAR:
            generation = state.next_generation
            newflow = Flow(flow.name, 'SYN_RECV', generation,
                           action.client or ATTACKER_COLORS[generation], SERVER_COLORS[generation],
                           False, 1, 1)
            state = replace(state, next_generation=generation + 1)
            state = _put(state, newflow)
            event['generation'] = generation
            event['client'] = newflow.client
            state = _reply(state, newflow, 'SA', events, action.defer_reply, 'genuine SYN-ACK')
            effect, accepted = 'new_request', True
        else:
            effect = 'listen_ignore'
    elif flow.phase == 'TIME_WAIT':
        if 'R' in flags:
            effect = 'time_wait_ignore_rst_conservative'
        elif flags == 'S':
            # Do not invent Linux early reuse without numeric seq/timestamp proof.
            state = _reply(state, flow, 'A', events, action.defer_reply,
                           'TIME_WAIT retained; early reuse outside conservative profile')
            effect = 'time_wait_retained'
        elif flags == 'A' and seq == 'exact' and action.payload == 'none':
            state = _put(state, replace(flow, timer_age=0))
            effect = 'time_wait_ack_silent_retained'
        else:
            state = _reply(state, flow, 'A', events, action.defer_reply, 'TIME_WAIT retained')
            effect = 'time_wait_ack'
    elif seq == 'old' or (action.client is not None and action.client != flow.client):
        if 'R' in flags:
            effect = 'old_incarnation_oow_rst'
        else:
            state = _reply(state, flow, 'A', events, action.defer_reply,
                           'old incarnation symbol is disjoint from current receive window')
            effect = 'old_incarnation_ack'
    elif 'R' in flags:
        fin_exception = seq == 'previous' and flow.phase in ('CLOSE_WAIT', 'LAST_ACK', 'CLOSING')
        if seq == 'exact' or fin_exception:
            retired = state.retired + (flow,)
            state = replace(_put(state, Flow(flow.name)), retired=retired)
            effect, accepted = 'accepted_reset', True
        elif seq == 'in_window':
            state = _reply(state, flow, 'A', events, action.defer_reply, 'challenge ACK for nonexact in-window RST')
            effect = 'challenge_ack_rst'
        else:
            effect = 'oow_rst_drop'
    elif flow.phase == 'SYN_RECV':
        if flags == 'S' and seq == 'isn' and action.client == flow.client:
            state = _reply(state, flow, 'SA', events, action.defer_reply, 'duplicate SYN retransmits SYN-ACK')
            effect = 'duplicate_syn'
        elif 'A' in flags and ack != 'exact':
            state = _reply(state, flow, 'R', events, action.defer_reply,
                           'unacceptable request ACK', seq=event['ack'], ack='0 (unused)')
            effect = 'request_bad_ack'
        elif 'A' in flags and ack == 'exact' and seq in ('exact', 'in_window') and 'S' not in flags:
            newflow = replace(flow, phase='CLOSE_WAIT' if 'F' in flags and seq == 'exact' else 'ESTABLISHED',
                              established=True, rcv_offset=flow.rcv_offset + (1 if 'F' in flags and seq == 'exact' else 0))
            if action.payload == 'readout' and seq == 'exact':
                newflow = replace(newflow, rcv_offset=newflow.rcv_offset + 1, readout_units=newflow.readout_units + 1)
            state = _put(state, newflow)
            if 'F' in flags or action.payload != 'none':
                state = _reply(state, newflow, 'A', events, action.defer_reply, 'ACK accepted data/FIN')
            effect, accepted = 'establish_then_fin' if 'F' in flags and seq == 'exact' else 'establish', True
        else:
            state = _reply(state, flow, 'A', events, action.defer_reply, 'request sequence rejected')
            effect = 'request_sequence_reject'
    elif seq in ('oow_left', 'oow_right', 'isn'):
        state = _reply(state, flow, 'A', events, action.defer_reply, 'out-of-window segment ACK')
        effect = 'oow_ack'
    elif 'S' in flags:
        state = _reply(state, flow, 'A', events, action.defer_reply, 'challenge ACK for unexpected SYN')
        effect = 'challenge_ack_syn'
    elif 'A' not in flags:
        effect = 'missing_ack_drop'
    elif ack == 'beyond':
        if flow.phase != 'ESTABLISHED':
            state = _reply(state, flow, 'A', events, action.defer_reply, 'future ACK rejected; non-established challenge ACK')
        effect = 'future_ack_drop'
    elif seq == 'in_window':
        # Empty ACK can be in-window; payload/FIN beyond RCV.NXT is not consumed.
        if 'F' in flags or action.payload != 'none':
            state = _reply(state, flow, 'A', events, action.defer_reply, 'out-of-order data/FIN; gap is not filled')
            effect = 'out_of_order_not_consumed'
        else:
            effect, accepted = 'inwindow_ack', True
    else:
        phase = flow.phase
        if phase == 'LAST_ACK' and ack == 'exact':
            state = replace(_put(state, Flow(flow.name)), retired=state.retired + (flow,))
            effect, accepted = 'passive_close_complete', True
        elif phase == 'CLOSING' and ack == 'exact':
            newflow = replace(flow, phase='TIME_WAIT', timer_age=0)
            state = _put(state, newflow)
            effect, accepted = 'simultaneous_close_complete', True
        else:
            if phase == 'FIN_WAIT1' and ack == 'exact':
                phase = 'FIN_WAIT2'
            rcv = flow.rcv_offset
            readout_units = flow.readout_units
            if action.payload != 'none' and phase in ('ESTABLISHED', 'FIN_WAIT1', 'FIN_WAIT2'):
                rcv += 1  # A symbolic L_readout, not a one-byte payload.
                readout_units += 1
            if 'F' in flags:
                if phase == 'ESTABLISHED':
                    phase = 'CLOSE_WAIT'
                elif phase == 'FIN_WAIT1':
                    phase = 'CLOSING'
                elif phase == 'FIN_WAIT2':
                    phase = 'TIME_WAIT'
                if flow.phase in ('ESTABLISHED', 'FIN_WAIT1', 'FIN_WAIT2'):
                    rcv += 1
            newflow = replace(flow, phase=phase, rcv_offset=rcv, readout_units=readout_units, timer_age=0 if phase == 'TIME_WAIT' else flow.timer_age)
            state = _put(state, newflow)
            if 'F' in flags or action.payload != 'none':
                state = _reply(state, newflow, 'A', events, action.defer_reply, 'ACK accepted payload/FIN')
            effect, accepted = 'accepted_fin' if 'F' in flags else 'accepted_ack', True
    event['linux_tcp_accepted'] = accepted
    event['note'] = effect
    for e in events:
        e['state_after'] = state_summary(state)
    return [Outcome(state, tuple(events), accepted, effect)]
