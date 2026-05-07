"""
Rich terminal dashboard.

Renders a live-updating layout with:
  - Stats bar (flows, alerts, uptime, model state)
  - Recent flows table with per-flow anomaly scores
  - Active alerts panel
  - Event log
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from src.capture.flow_tracker import Flow
from src.detection.alerts import Alert


_SEVERITY_STYLE = {
    "HIGH":   "bold red",
    "MEDIUM": "bold yellow",
    "LOW":    "bold cyan",
}

_SCORE_STYLE = {
    "HIGH":   "red",
    "MEDIUM": "yellow",
    "LOW":    "cyan",
    "NORMAL": "green",
}


@dataclass
class FlowEntry:
    flow: Flow
    score: float
    is_anomaly: bool
    timestamp: float = field(default_factory=time.time)

    @property
    def score_label(self) -> str:
        if not self.is_anomaly:
            return "NORMAL"
        if self.score >= 0.80:
            return "HIGH"
        if self.score >= 0.60:
            return "MEDIUM"
        return "LOW"


class Dashboard:
    def __init__(self, mode: str = "DEMO", max_flows: int = 20, refresh_rate: float = 4.0):
        self._mode = mode
        self._max_flows = max_flows
        self._refresh_rate = refresh_rate
        self._console = Console()
        self._live: Live | None = None

        self._flows: Deque[FlowEntry] = deque(maxlen=max_flows)
        self._alerts: list[Alert] = []
        self._logs: Deque[str] = deque(maxlen=8)
        self._start_time = time.time()
        self._flows_processed = 0
        self._model_state = "UNTRAINED"

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def start(self):
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=self._refresh_rate,
            screen=False,
        )
        self._live.start()

    def stop(self):
        if self._live:
            self._live.stop()

    def add_flow(self, flow: Flow, score: float, is_anomaly: bool):
        self._flows.append(FlowEntry(flow, score, is_anomaly))
        self._flows_processed += 1
        if self._live:
            self._live.update(self._render())

    def add_alert(self, alert: Alert):
        self._alerts = [alert] + self._alerts
        self._alerts = self._alerts[:15]
        self.log(
            f"[{_SEVERITY_STYLE[alert.severity]}]{alert.severity}[/] "
            f"{alert.flow.src_ip} → {alert.flow.dst_ip}:{alert.flow.dst_port} "
            f"| {alert.attack_type} | score={alert.score:.3f}"
        )

    def log(self, message: str):
        ts = time.strftime("%H:%M:%S")
        self._logs.append(f"[dim]{ts}[/dim] {message}")
        if self._live:
            self._live.update(self._render())

    def set_model_state(self, state: str):
        self._model_state = state
        if self._live:
            self._live.update(self._render())

    # ------------------------------------------------------------------ #
    # Rendering                                                            #
    # ------------------------------------------------------------------ #

    def _render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._header(), size=3),
            Layout(name="main"),
            Layout(self._log_panel(), size=10),
        )
        layout["main"].split_row(
            Layout(self._flows_panel(), ratio=3),
            Layout(self._alerts_panel(), ratio=2),
        )
        return layout

    def _header(self) -> Panel:
        uptime = int(time.time() - self._start_time)
        h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
        alert_count = len(self._alerts)
        rate = self._flows_processed / max(uptime, 1)

        state_color = "green" if self._model_state == "DETECTING" else (
            "yellow" if self._model_state == "LEARNING" else "dim"
        )

        text = Text(justify="center")
        text.append(" AI Network Anomaly Detection System ", style="bold white on dark_blue")
        text.append(f"  Mode: {self._mode}", style="bold cyan")
        text.append(f"  |  Model: ", style="dim")
        text.append(self._model_state, style=state_color)
        text.append(f"  |  Flows: {self._flows_processed:,}", style="white")
        text.append(f"  |  Alerts: {alert_count}", style="bold red" if alert_count else "white")
        text.append(f"  |  Rate: {rate:.1f}/s", style="white")
        text.append(f"  |  Uptime: {h:02d}:{m:02d}:{s:02d}", style="dim")

        return Panel(text, style="on grey11")

    def _flows_panel(self) -> Panel:
        table = Table(
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            expand=True,
            show_edge=False,
        )
        table.add_column("Time", width=8, style="dim")
        table.add_column("Source IP", min_width=13)
        table.add_column("Destination", min_width=20)
        table.add_column("Proto", width=5, justify="center")
        table.add_column("Bytes ↑", width=9, justify="right")
        table.add_column("Bytes ↓", width=9, justify="right")
        table.add_column("Score", width=7, justify="right")
        table.add_column("Status", width=8, justify="center")

        for entry in reversed(list(self._flows)):
            f = entry.flow
            ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
            proto_str = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(f.protocol, "???")
            dst = f"{f.dst_ip}:{f.dst_port}"

            score_str = f"{entry.score:.3f}"
            label = entry.score_label
            status_style = _SCORE_STYLE[label]

            table.add_row(
                ts,
                f.src_ip,
                dst,
                proto_str,
                _fmt_bytes(f.fwd_bytes),
                _fmt_bytes(f.bwd_bytes),
                Text(score_str, style=status_style),
                Text(label, style=status_style),
            )

        return Panel(table, title="[bold]Recent Flows[/bold]", border_style="blue")

    def _alerts_panel(self) -> Panel:
        table = Table(
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            expand=True,
            show_edge=False,
        )
        table.add_column("Time", width=8, style="dim")
        table.add_column("Source IP", min_width=13)
        table.add_column("Attack Type", min_width=18)
        table.add_column("Sev", width=6, justify="center")
        table.add_column("Score", width=6, justify="right")

        for alert in self._alerts:
            sev_style = _SEVERITY_STYLE.get(alert.severity, "white")
            table.add_row(
                alert.time_str,
                alert.flow.src_ip,
                alert.attack_type,
                Text(alert.severity, style=sev_style),
                Text(f"{alert.score:.2f}", style=sev_style),
            )

        return Panel(table, title="[bold red]Alerts[/bold red]", border_style="red")

    def _log_panel(self) -> Panel:
        lines = "\n".join(list(self._logs)[-8:]) or "[dim]No events yet[/dim]"
        return Panel(Text.from_markup(lines), title="[bold]Event Log[/bold]", border_style="dim")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
