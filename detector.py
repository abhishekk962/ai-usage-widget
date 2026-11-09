"""Packet boundary rules and flow orientation from ai-network-activity."""

from collections import deque
from dataclasses import InitVar, dataclass, field


ESTIMATED_END_SPAN = 1.
ESTIMATED_END_QUIET = 3.


@dataclass(frozen=True)
class Rules:
    """Packet size and timing rules for request boundaries."""
    ignore_at_most: int = 80
    first_large_min: int = 16000
    first_large_max: int = 30000
    second_large_min: int = 12000
    second_large_max: int = 18000
    pair_gap: float = .08
    start_span: float = .8
    start_debounce: float = 1.
    end_span: float = 2.
    max_duration: float = 600.
    end_sizes: InitVar[tuple[tuple[int, ...], ...] | None] = None
    end_size_ranges: tuple[tuple[tuple[int, int], ...], ...] = (
        ((386, 388), (441, 442), (490, 494), (508, 516), (657, 659)),
        ((98, 102),),
        ((84, 86),),
    )

    def __post_init__(self, end_sizes):
        from math import isfinite
        for name in ('pair_gap', 'start_span', 'start_debounce', 'end_span', 'max_duration'):
            value = getattr(self, name)
            if not isfinite(value) or value <= 0:
                raise ValueError(f'{name} must be finite and positive')
        if end_sizes is not None:
            # Older session exports store exact byte sizes.
            ranges = tuple(tuple((size, size) for size in group) for group in end_sizes)
            object.__setattr__(self, 'end_size_ranges', ranges)

    def is_first_large(self, size):
        return self.first_large_min <= size <= self.first_large_max

    def is_second_large(self, size):
        return self.second_large_min <= size <= self.second_large_max


@dataclass(frozen=True)
class Packet:
    time: float
    size: int
    outgoing: bool
    id: int | None = None


@dataclass
class Flow:
    outgoing: deque = field(default_factory=lambda: deque(maxlen=2))
    first_pairs: deque = field(default_factory=deque)
    incoming: deque = field(default_factory=lambda: deque(maxlen=3))
    active: dict | None = None
    first_end_marker: Packet | None = None
    pending_end: tuple[Packet, Packet] | None = None
    last_start: float = float('-inf')
    last_seen: float = float('-inf')


def motif(packets, at_end=False):
    first = packets[0].time
    return {
        'time': packets[-1].time if at_end else first,
        'packet_ids': [p.id for p in packets],
        'sizes': [p.size for p in packets],
        'relative_ms': [(p.time-first)*1000 for p in packets],
    }


class PatternMatcher:
    """Shared streaming engine. Input must be ordered by time within each flow.

    Starts join two adjacent meaningful outgoing large/small pairs; other
    pairs may intervene. End matching filters incoming traffic by packet size,
    then looks for the three end markers in order. New starts replace unfinished starts.
    Live callers can also publish and retract estimates from the first and last markers.
    These explicit reconstruction choices are not recovered original source.
    """
    def __init__(self, rules=None, on_event=None, *, on_marker=None, estimate_ends=False):
        self.rules = rules or Rules()
        self.on_event = on_event or (lambda event: None)
        self.on_marker = on_marker
        self.estimate_ends = estimate_ends
        self.end_markers = {
            size: marker
            for marker, bands in enumerate(self.rules.end_size_ranges, 1)
            for low, high in bands
            for size in range(low, high + 1)
        }
        self.flows = {}
        self.next_id = 1

    def emit(self, kind, key, **values):
        self.on_event({'kind': kind, 'flow': key, **values})

    def close_unconfirmed(self, key, state, reason):
        if 'estimated_end' not in state.active:
            self.emit('incomplete', key, **state.active, reason=reason)
        state.active = None
        state.pending_end = None

    def expire(self, now):
        for key, state in list(self.flows.items()):
            if state.active and now-state.active['start'] > self.rules.max_duration:
                self.close_unconfirmed(key, state, 'timeout')
            elif state.active and state.pending_end:
                first, last = state.pending_end
                if now >= last.time + ESTIMATED_END_QUIET:
                    state.pending_end = None
                    state.active['estimated_end'] = last.time
                    self.emit('estimated_end', key, **state.active, end=last.time,
                              end_motif=motif((first, last), at_end=True))
            if not state.active and now-state.last_seen > self.rules.max_duration:
                del self.flows[key]

    def finish(self):
        for key, state in self.flows.items():
            if state.active:
                self.close_unconfirmed(key, state, 'capture stopped')

    def update_end_estimate(self, key, state, packet, end_marker):
        # Every meaningful incoming packet interrupts the previous quiet period.
        state.pending_end = None
        estimate = state.active.pop('estimated_end', None)
        if estimate is not None:
            self.emit('resumed', key, **state.active, estimated_end=estimate, time=packet.time)
        if end_marker == 1:
            state.first_end_marker = packet
        if end_marker == 3 and state.first_end_marker:
            first = state.first_end_marker
            if packet.time <= first.time + ESTIMATED_END_SPAN:
                state.pending_end = (first, packet)

    def feed(self, key, packet):
        r = self.rules
        state = self.flows.setdefault(key, Flow())
        if packet.time < state.last_seen:
            raise ValueError('Packets must be time ordered within a flow')
        state.last_seen = packet.time
        if state.active and packet.time-state.active['start'] > r.max_duration:
            self.close_unconfirmed(key, state, 'timeout')
        if packet.size <= r.ignore_at_most:
            return
        if packet.outgoing:
            if self.on_marker:
                if r.is_first_large(packet.size):
                    self.on_marker('START_1_LARGE', key, packet)
                if r.is_second_large(packet.size):
                    self.on_marker('START_2_LARGE', key, packet)
            state.outgoing.append(packet)
            while state.first_pairs and packet.time-state.first_pairs[0][0].time > r.start_span:
                state.first_pairs.popleft()
            if len(state.outgoing) < 2:
                return
            c, d = state.outgoing
            # No original small-packet bounds were saved; use 81..11999.
            is_pair = (r.ignore_at_most < d.size < r.second_large_min
                       and d.time-c.time <= r.pair_gap)
            if is_pair and r.is_first_large(c.size):
                state.first_pairs.append((c, d))
                if self.on_marker:
                    self.on_marker('START_1_SMALL', key, d)
            if not (is_pair and r.is_second_large(c.size)):
                return
            if self.on_marker:
                self.on_marker('START_2_SMALL', key, d)
            candidates = [(a, b) for a, b in state.first_pairs
                          if b.time <= c.time and a.time < c.time
                          and a.time-state.last_start >= r.start_debounce]
            if not candidates:
                return
            a, b = candidates[0]
            start_motif = motif((a, b, c, d))
            if state.active:
                self.close_unconfirmed(key, state, 'new start')
            state.active = {'id': self.next_id, 'start': a.time, 'start_motif': start_motif}
            self.next_id += 1
            state.last_start = a.time
            state.incoming.clear()
            state.first_end_marker = None
            self.emit('start', key, **state.active)
        else:
            end_marker = self.end_markers.get(packet.size)
            if self.estimate_ends and state.active:
                self.update_end_estimate(key, state, packet, end_marker)
            if end_marker is None:
                return
            if self.on_marker:
                self.on_marker(f'END_{end_marker}', key, packet)
            state.incoming.append(packet)
            if len(state.incoming) < 3:
                return
            a, b, c = state.incoming
            if (self.end_markers[a.size], self.end_markers[b.size], end_marker) != (1, 2, 3):
                return
            if c.time-a.time > r.end_span:
                return
            end_motif = motif((a, b, c), at_end=True)
            self.emit('end', key, end=c.time, end_motif=end_motif)
            if (state.active and a.time >= state.active['start']
                    and 0 < c.time-state.active['start'] <= r.max_duration):
                self.emit('complete', key, **state.active, end=c.time, end_motif=end_motif)
                state.active = None
                state.pending_end = None


def connection_key(src, sport, dst, dport, local_ips):
    """Orient any TCP port pair using discovered local addresses.

    Skip local-to-local and transit packets: neither has an unambiguous
    sent/received direction relative to this computer. No remote IP allowlist.
    """
    src_local, dst_local = src in local_ips, dst in local_ips
    if src_local == dst_local:
        return None
    key = (src, sport, dst, dport) if src_local else (dst, dport, src, sport)
    return key, src_local


def discover_local_ips(addresses):
    if addresses:
        return set(addresses)

    from scapy.all import get_if_addr, get_if_list
    from scapy.arch import in6_getifaddr

    local_ips = set()
    for interface in get_if_list():
        try:
            local_ips.add(get_if_addr(interface))
        except (OSError, ValueError):
            pass
    local_ips.update(address for address, *_ in in6_getifaddr())
    local_ips.discard('0.0.0.0')
    return local_ips
