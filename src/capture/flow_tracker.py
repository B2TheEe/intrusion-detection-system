"""
Maintains per-flow state across raw packets.

A Flow is keyed by a canonical 5-tuple. The first packet seen in each
direction determines which side is "forward" (initiator).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    start_time: float = field(default_factory=time.time)
    end_time: float = field(default_factory=time.time)

    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    ack_count: int = 0

    _fwd_timestamps: list = field(default_factory=list, repr=False)
    _bwd_timestamps: list = field(default_factory=list, repr=False)

    label: str = "normal"  # set by simulator; live capture leaves as "normal"

    # ------------------------------------------------------------------ #
    # Derived properties                                                   #
    # ------------------------------------------------------------------ #

    @property
    def duration(self) -> float:
        return max(self.end_time - self.start_time, 1e-6)

    @property
    def total_pkts(self) -> int:
        return self.fwd_pkts + self.bwd_pkts

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def fwd_pkt_rate(self) -> float:
        return self.fwd_pkts / self.duration

    @property
    def bwd_pkt_rate(self) -> float:
        return self.bwd_pkts / self.duration

    @property
    def fwd_byte_rate(self) -> float:
        return self.fwd_bytes / self.duration

    @property
    def bwd_byte_rate(self) -> float:
        return self.bwd_bytes / self.duration

    @property
    def bytes_ratio(self) -> float:
        return self.fwd_bytes / (self.total_bytes + 1)

    @property
    def pkts_ratio(self) -> float:
        return self.fwd_pkts / (self.total_pkts + 1)

    @property
    def avg_fwd_pkt_size(self) -> float:
        return self.fwd_bytes / max(self.fwd_pkts, 1)

    @property
    def avg_bwd_pkt_size(self) -> float:
        return self.bwd_bytes / max(self.bwd_pkts, 1)

    @property
    def syn_ratio(self) -> float:
        return self.syn_count / max(self.total_pkts, 1)

    @property
    def rst_ratio(self) -> float:
        return self.rst_count / max(self.total_pkts, 1)

    @property
    def fin_ratio(self) -> float:
        return self.fin_count / max(self.total_pkts, 1)

    def _iat(self, timestamps: list) -> tuple[float, float]:
        if len(timestamps) < 2:
            return 0.0, 0.0
        deltas = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        mean = sum(deltas) / len(deltas)
        variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
        return mean, variance ** 0.5

    @property
    def fwd_iat_mean(self) -> float:
        return self._iat(self._fwd_timestamps)[0]

    @property
    def fwd_iat_std(self) -> float:
        return self._iat(self._fwd_timestamps)[1]

    @property
    def is_tcp(self) -> bool:
        return self.protocol == PROTO_TCP

    @property
    def is_udp(self) -> bool:
        return self.protocol == PROTO_UDP

    @property
    def dst_port_privileged(self) -> bool:
        return self.dst_port < 1024


def _canonical_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> tuple:
    """Returns a canonical (sorted) 5-tuple so A→B and B→A share the same key."""
    if (src_ip, src_port) <= (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, proto)
    return (dst_ip, src_ip, dst_port, src_port, proto)


class FlowTracker:
    """Aggregates packets into flows; emits completed Flow objects to a callback."""

    def __init__(
        self,
        on_flow_complete,
        timeout_tcp: float = 30,
        timeout_udp: float = 15,
        timeout_icmp: float = 5,
    ):
        self._on_complete = on_flow_complete
        self._timeouts = {PROTO_TCP: timeout_tcp, PROTO_UDP: timeout_udp, PROTO_ICMP: timeout_icmp}
        self._flows: dict[tuple, Flow] = {}
        # Maps canonical key → which side is "forward" (stored as the original src_ip)
        self._initiator: dict[tuple, str] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def on_packet(self, pkt):
        """Called for every captured packet (scapy Packet object)."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            src_ip, dst_ip = ip.src, ip.dst
            proto = ip.proto
            src_port, dst_port, flags = 0, 0, 0

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                flags = int(tcp.flags)
                pkt_len = len(tcp.payload)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port, dst_port = udp.sport, udp.dport
                pkt_len = len(udp.payload)
            elif pkt.haslayer(ICMP):
                pkt_len = len(ip.payload)
            else:
                return

            self._update(src_ip, dst_ip, src_port, dst_port, proto, pkt_len, flags)
        except Exception:
            pass

    def _update(self, src_ip, dst_ip, src_port, dst_port, proto, pkt_len, tcp_flags):
        key = _canonical_key(src_ip, dst_ip, src_port, dst_port, proto)
        now = time.time()

        with self._lock:
            if key not in self._flows:
                self._counter += 1
                flow = Flow(
                    flow_id=f"f{self._counter:08d}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    start_time=now,
                    end_time=now,
                )
                self._flows[key] = flow
                self._initiator[key] = src_ip

            flow = self._flows[key]
            flow.end_time = now
            is_forward = src_ip == self._initiator[key]

            if is_forward:
                flow.fwd_pkts += 1
                flow.fwd_bytes += pkt_len
                flow._fwd_timestamps.append(now)
            else:
                flow.bwd_pkts += 1
                flow.bwd_bytes += pkt_len
                flow._bwd_timestamps.append(now)

            if proto == PROTO_TCP:
                SYN, FIN, RST, ACK = 0x02, 0x01, 0x04, 0x10
                if tcp_flags & SYN:
                    flow.syn_count += 1
                if tcp_flags & FIN:
                    flow.fin_count += 1
                if tcp_flags & RST:
                    flow.rst_count += 1
                if tcp_flags & ACK:
                    flow.ack_count += 1

                # FIN or RST terminates the flow
                if tcp_flags & (FIN | RST):
                    self._complete_flow(key)

    def _complete_flow(self, key: tuple):
        """Remove flow from active tracking and emit it. Must be called with lock held."""
        flow = self._flows.pop(key, None)
        self._initiator.pop(key, None)
        if flow and flow.total_pkts > 0:
            self._on_complete(flow)

    def expire_old_flows(self):
        """Expire flows that have been idle longer than their protocol timeout."""
        now = time.time()
        expired_keys = []

        with self._lock:
            for key, flow in self._flows.items():
                timeout = self._timeouts.get(flow.protocol, 30)
                if now - flow.end_time > timeout:
                    expired_keys.append(key)

        with self._lock:
            for key in expired_keys:
                self._complete_flow(key)

    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)
