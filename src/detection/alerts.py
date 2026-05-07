"""
Alert data model and alert manager.

Heuristics classify detected anomalies into human-readable attack types.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from src.capture.flow_tracker import Flow


@dataclass
class Alert:
    timestamp: float
    flow: Flow
    score: float
    severity: str      # "LOW" | "MEDIUM" | "HIGH"
    attack_type: str   # heuristic label

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))


def classify_attack_type(flow: Flow) -> str:
    """Rule-based heuristic to label the likely attack category."""
    if flow.rst_ratio > 0.4 and flow.duration < 0.1 and flow.fwd_bytes < 200:
        return "Port Scan"
    if flow.is_udp and flow.fwd_pkt_rate > 500:
        return "DDoS / UDP Flood"
    if flow.is_tcp and flow.fwd_pkt_rate > 200 and flow.syn_ratio > 0.5:
        return "SYN Flood"
    if flow.dst_port == 22 and flow.duration < 5.0 and flow.rst_count >= 1:
        return "SSH Brute Force"
    if flow.fwd_bytes > 5_000_000:
        return "Data Exfiltration"
    if (
        flow.fwd_iat_std < 0.5
        and flow.fwd_pkts >= 2
        and flow.fwd_bytes < 10_000
        and flow.duration > 5
    ):
        return "C2 Beaconing"
    return "Unknown Anomaly"


def _severity(score: float, thresholds: dict) -> str:
    if score >= thresholds.get("high", 0.80):
        return "HIGH"
    if score >= thresholds.get("medium", 0.60):
        return "MEDIUM"
    return "LOW"


class AlertManager:
    def __init__(
        self,
        severity_thresholds: dict | None = None,
        cooldown_seconds: float = 10.0,
        max_recent: int = 15,
    ):
        self._thresholds = severity_thresholds or {"high": 0.80, "medium": 0.60, "low": 0.40}
        self._cooldown = cooldown_seconds
        self._max_recent = max_recent
        self._recent: Deque[Alert] = deque(maxlen=max_recent)
        # last alert time per source IP
        self._last_alert: dict[str, float] = {}
        self._total = 0

    def maybe_alert(self, flow: Flow, score: float, threshold: float) -> Alert | None:
        if score < threshold:
            return None
        now = time.time()
        last = self._last_alert.get(flow.src_ip, 0)
        if now - last < self._cooldown:
            return None  # suppress duplicate alerts during cooldown

        self._last_alert[flow.src_ip] = now
        alert = Alert(
            timestamp=now,
            flow=flow,
            score=score,
            severity=_severity(score, self._thresholds),
            attack_type=classify_attack_type(flow),
        )
        self._recent.append(alert)
        self._total += 1
        return alert

    @property
    def recent(self) -> list[Alert]:
        return list(self._recent)

    @property
    def total(self) -> int:
        return self._total
