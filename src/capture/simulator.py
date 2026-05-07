"""
Deterministic synthetic traffic generator.

Produces realistic Flow objects without requiring network access or root.
Used for --demo mode and unit tests.
"""
from __future__ import annotations

import random
import threading
import time
from typing import Callable

from .flow_tracker import Flow, PROTO_TCP, PROTO_UDP, PROTO_ICMP

# ------------------------------------------------------------------ #
# Traffic profiles                                                     #
# ------------------------------------------------------------------ #

_NORMAL_PROFILES = [
    # (weight, profile_fn)
    (30, "https"),
    (15, "http"),
    (20, "dns"),
    (10, "ssh"),
    (8,  "smtp"),
    (7,  "ntp"),
    (10, "database"),
]

_ATTACK_PROFILES = [
    (25, "port_scan"),
    (20, "ddos_udp"),
    (25, "brute_force_ssh"),
    (20, "data_exfiltration"),
    (10, "c2_beaconing"),
]


def _random_private_ip(rng: random.Random) -> str:
    return f"192.168.{rng.randint(0,9)}.{rng.randint(1,254)}"


def _random_external_ip(rng: random.Random) -> str:
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def _ephemeral(rng: random.Random) -> int:
    return rng.randint(49152, 65535)


def _make_flow(
    rng: random.Random,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: int,
    duration: float,
    fwd_pkts: int,
    bwd_pkts: int,
    fwd_bytes: int,
    bwd_bytes: int,
    syn: int = 0,
    fin: int = 0,
    rst: int = 0,
    ack: int = 0,
    label: str = "normal",
) -> Flow:
    now = time.time()
    start = now - duration
    fwd_ts = sorted(rng.uniform(start, now) for _ in range(max(fwd_pkts, 1)))
    bwd_ts = sorted(rng.uniform(start, now) for _ in range(max(bwd_pkts, 1)))
    return Flow(
        flow_id=f"sim_{rng.randint(0, 2**32):08x}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        start_time=start,
        end_time=now,
        fwd_pkts=fwd_pkts,
        bwd_pkts=bwd_pkts,
        fwd_bytes=fwd_bytes,
        bwd_bytes=bwd_bytes,
        syn_count=syn,
        fin_count=fin,
        rst_count=rst,
        ack_count=ack,
        _fwd_timestamps=fwd_ts,
        _bwd_timestamps=bwd_ts,
        label=label,
    )


# ------------------------------------------------------------------ #
# Normal flow generators                                              #
# ------------------------------------------------------------------ #

def _gen_https(rng: random.Random) -> Flow:
    dur = rng.uniform(0.5, 8)
    fwd_p = rng.randint(5, 30)
    bwd_p = rng.randint(10, 80)
    fwd_b = rng.randint(300, 3000)
    bwd_b = rng.randint(5000, 800000)
    return _make_flow(
        rng,
        _random_private_ip(rng), _random_external_ip(rng),
        _ephemeral(rng), 443, PROTO_TCP,
        dur, fwd_p, bwd_p, fwd_b, bwd_b,
        syn=1, fin=1, ack=max(bwd_p - 2, 1),
    )


def _gen_http(rng: random.Random) -> Flow:
    dur = rng.uniform(0.2, 5)
    fwd_p = rng.randint(3, 20)
    bwd_p = rng.randint(5, 60)
    fwd_b = rng.randint(200, 2000)
    bwd_b = rng.randint(2000, 300000)
    return _make_flow(
        rng,
        _random_private_ip(rng), _random_external_ip(rng),
        _ephemeral(rng), 80, PROTO_TCP,
        dur, fwd_p, bwd_p, fwd_b, bwd_b,
        syn=1, fin=1, ack=max(bwd_p - 2, 1),
    )


def _gen_dns(rng: random.Random) -> Flow:
    dur = rng.uniform(0.005, 0.2)
    return _make_flow(
        rng,
        _random_private_ip(rng), "8.8.8.8",
        _ephemeral(rng), 53, PROTO_UDP,
        dur, 1, 1,
        rng.randint(40, 120), rng.randint(60, 600),
    )


def _gen_ssh(rng: random.Random) -> Flow:
    dur = rng.uniform(30, 1800)
    fwd_p = rng.randint(100, 5000)
    bwd_p = rng.randint(100, 5000)
    fwd_b = rng.randint(5000, 200000)
    bwd_b = rng.randint(10000, 400000)
    return _make_flow(
        rng,
        _random_private_ip(rng), _random_external_ip(rng),
        _ephemeral(rng), 22, PROTO_TCP,
        dur, fwd_p, bwd_p, fwd_b, bwd_b,
        syn=1, fin=1, ack=fwd_p + bwd_p - 2,
    )


def _gen_smtp(rng: random.Random) -> Flow:
    dur = rng.uniform(1, 20)
    fwd_b = rng.randint(1000, 50000)
    bwd_b = rng.randint(200, 2000)
    return _make_flow(
        rng,
        _random_private_ip(rng), _random_external_ip(rng),
        _ephemeral(rng), rng.choice([25, 587, 465]), PROTO_TCP,
        dur, rng.randint(5, 40), rng.randint(3, 20), fwd_b, bwd_b,
        syn=1, fin=1, ack=10,
    )


def _gen_ntp(rng: random.Random) -> Flow:
    return _make_flow(
        rng,
        _random_private_ip(rng), _random_external_ip(rng),
        _ephemeral(rng), 123, PROTO_UDP,
        rng.uniform(0.001, 0.05), 1, 1,
        rng.randint(48, 80), rng.randint(48, 80),
    )


def _gen_database(rng: random.Random) -> Flow:
    dur = rng.uniform(0.01, 5)
    fwd_b = rng.randint(200, 5000)
    bwd_b = rng.randint(500, 100000)
    return _make_flow(
        rng,
        _random_private_ip(rng), f"10.0.0.{rng.randint(10, 30)}",
        _ephemeral(rng), rng.choice([3306, 5432, 1521, 27017]), PROTO_TCP,
        dur, rng.randint(3, 20), rng.randint(5, 40), fwd_b, bwd_b,
        syn=1, fin=1, ack=10,
    )


_NORMAL_FNS = {
    "https": _gen_https,
    "http": _gen_http,
    "dns": _gen_dns,
    "ssh": _gen_ssh,
    "smtp": _gen_smtp,
    "ntp": _gen_ntp,
    "database": _gen_database,
}


# ------------------------------------------------------------------ #
# Attack flow generators                                              #
# ------------------------------------------------------------------ #

def _gen_port_scan(rng: random.Random) -> Flow:
    src = _random_private_ip(rng)
    return _make_flow(
        rng,
        src, _random_external_ip(rng),
        _ephemeral(rng), rng.randint(1, 65535), PROTO_TCP,
        rng.uniform(0.0005, 0.01),
        rng.randint(1, 2), 0,
        rng.randint(40, 60), 0,
        syn=1, rst=rng.randint(0, 1),
        label="port_scan",
    )


def _gen_ddos_udp(rng: random.Random) -> Flow:
    src = _random_external_ip(rng)
    dur = rng.uniform(0.5, 10)
    fwd_p = rng.randint(2000, 50000)
    return _make_flow(
        rng,
        src, _random_private_ip(rng),
        _ephemeral(rng), rng.randint(1, 1024), PROTO_UDP,
        dur, fwd_p, rng.randint(0, 5),
        fwd_p * rng.randint(500, 1400), rng.randint(0, 500),
        label="ddos_udp",
    )


def _gen_brute_force_ssh(rng: random.Random) -> Flow:
    # Short-lived, low-byte session to port 22 with multiple RSTs (failed auth)
    pkts = rng.randint(4, 9)
    rst_n = rng.randint(2, 4)  # Multiple RSTs per failed attempt
    return _make_flow(
        rng,
        _random_external_ip(rng), _random_private_ip(rng),
        _ephemeral(rng), 22, PROTO_TCP,
        rng.uniform(0.1, 1.5),
        pkts, rng.randint(2, pkts),
        rng.randint(150, 700), rng.randint(80, 500),
        syn=1, rst=rst_n, ack=rng.randint(1, 4),
        label="brute_force_ssh",
    )


def _gen_data_exfiltration(rng: random.Random) -> Flow:
    dur = rng.uniform(20, 300)
    fwd_p = rng.randint(500, 5000)
    fwd_b = rng.randint(5_000_000, 100_000_000)  # 5 MB – 100 MB outbound
    return _make_flow(
        rng,
        _random_private_ip(rng), _random_external_ip(rng),
        _ephemeral(rng), rng.choice([4444, 8888, 9001, 6667, 1337]), PROTO_TCP,
        dur, fwd_p, rng.randint(10, 50),
        fwd_b, rng.randint(500, 5000),
        syn=1, fin=1, ack=fwd_p,
        label="data_exfiltration",
    )


def _gen_c2_beaconing(rng: random.Random) -> Flow:
    dur = rng.uniform(5, 60)
    fwd_p = rng.randint(2, 8)
    bwd_p = rng.randint(2, 6)
    # Very regular timestamps (low IAT std)
    interval = rng.uniform(0.5, 2.0)
    src = _random_private_ip(rng)
    dst = _random_external_ip(rng)
    now = time.time()
    start = now - dur
    fwd_ts = [start + i * interval for i in range(fwd_p)]
    bwd_ts = [t + rng.uniform(0.01, 0.05) for t in fwd_ts[:bwd_p]]
    flow = Flow(
        flow_id=f"sim_{rng.randint(0, 2**32):08x}",
        src_ip=src,
        dst_ip=dst,
        src_port=_ephemeral(rng),
        dst_port=rng.choice([443, 80, 8080]),
        protocol=PROTO_TCP,
        start_time=start,
        end_time=now,
        fwd_pkts=fwd_p,
        bwd_pkts=bwd_p,
        fwd_bytes=rng.randint(100, 600) * fwd_p,
        bwd_bytes=rng.randint(50, 300) * bwd_p,
        syn_count=1,
        fin_count=0,
        rst_count=0,
        ack_count=fwd_p + bwd_p - 1,
        _fwd_timestamps=fwd_ts,
        _bwd_timestamps=bwd_ts,
        label="c2_beaconing",
    )
    return flow


_ATTACK_FNS = {
    "port_scan": _gen_port_scan,
    "ddos_udp": _gen_ddos_udp,
    "brute_force_ssh": _gen_brute_force_ssh,
    "data_exfiltration": _gen_data_exfiltration,
    "c2_beaconing": _gen_c2_beaconing,
}


# ------------------------------------------------------------------ #
# Simulator                                                           #
# ------------------------------------------------------------------ #

def _weighted_choice(rng: random.Random, options: list[tuple]) -> str:
    weights, names = zip(*((w, n) for w, n in options))
    total = sum(weights)
    r = rng.uniform(0, total)
    cumulative = 0
    for w, name in zip(weights, names):
        cumulative += w
        if r <= cumulative:
            return name
    return names[-1]


def generate_flow(rng: random.Random, attack_probability: float = 0.0) -> Flow:
    """Generate a single synthetic flow."""
    if rng.random() < attack_probability:
        profile = _weighted_choice(rng, _ATTACK_PROFILES)
        return _ATTACK_FNS[profile](rng)
    profile = _weighted_choice(rng, _NORMAL_PROFILES)
    return _NORMAL_FNS[profile](rng)


def generate_baseline(n: int, seed: int = 42) -> list[Flow]:
    """Generate n normal flows for model training."""
    rng = random.Random(seed)
    return [generate_flow(rng, attack_probability=0.0) for _ in range(n)]


class TrafficSimulator:
    """Emits synthetic Flow objects to a callback at a target rate."""

    def __init__(
        self,
        on_flow: Callable[[Flow], None],
        flows_per_second: float = 8.0,
        attack_probability: float = 0.07,
        seed: int = 42,
    ):
        self._on_flow = on_flow
        self._rate = flows_per_second
        self._attack_prob = attack_probability
        self._rng = random.Random(seed)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _run(self):
        interval = 1.0 / max(self._rate, 0.1)
        while not self._stop_event.is_set():
            flow = generate_flow(self._rng, self._attack_prob)
            self._on_flow(flow)
            self._stop_event.wait(interval)
