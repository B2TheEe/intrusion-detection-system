"""
Live packet capture using scapy's AsyncSniffer.

Requires root/CAP_NET_RAW. Raises PermissionError if not available.
"""
from __future__ import annotations

import threading
import time

from .flow_tracker import FlowTracker


class LiveSniffer:
    """Wraps scapy AsyncSniffer and a periodic timeout sweeper."""

    def __init__(
        self,
        tracker: FlowTracker,
        iface: str | None = None,
        bpf_filter: str = "ip",
        timeout_check_interval: float = 5.0,
    ):
        self._tracker = tracker
        self._iface = iface
        self._filter = bpf_filter
        self._check_interval = timeout_check_interval
        self._sniffer = None
        self._sweeper: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self):
        try:
            from scapy.all import AsyncSniffer
        except ImportError as exc:
            raise ImportError("scapy is required for live capture: pip install scapy") from exc

        kwargs = dict(prn=self._tracker.on_packet, store=False, filter=self._filter)
        if self._iface:
            kwargs["iface"] = self._iface

        self._sniffer = AsyncSniffer(**kwargs)
        try:
            self._sniffer.start()
        except PermissionError:
            raise PermissionError(
                "Live capture requires root privileges. Run with sudo, or use --demo mode."
            )

        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True)
        self._sweeper.start()

    def stop(self):
        self._stop_event.set()
        if self._sniffer:
            self._sniffer.stop()

    def _sweep_loop(self):
        while not self._stop_event.wait(self._check_interval):
            self._tracker.expire_old_flows()
