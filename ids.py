#!/usr/bin/env python3
"""
AI-Driven Network Anomaly Detection System
==========================================

Usage:
  python ids.py demo                          # Simulated traffic, no root needed
  sudo python ids.py learn [--iface eth0]     # Capture baseline, train model
  sudo python ids.py detect [--iface eth0]    # Live detection with trained model
  python ids.py evaluate                      # Measure model quality on labelled data
"""
from __future__ import annotations

import argparse
import os
import queue
import signal
import sys
import time

import yaml

# Ensure src/ is importable when running from project root
sys.path.insert(0, os.path.dirname(__file__))

from src.capture.flow_tracker import Flow, FlowTracker
from src.capture.simulator import TrafficSimulator, generate_baseline
from src.detection.alerts import AlertManager
from src.features.extractor import extract, extract_batch
from src.models.detector import AnomalyDetector
from src.ui.dashboard import Dashboard


# ------------------------------------------------------------------ #
# Config loading                                                       #
# ------------------------------------------------------------------ #

def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ------------------------------------------------------------------ #
# Shared detection loop                                               #
# ------------------------------------------------------------------ #

def _run_detection_loop(
    flow_queue: queue.Queue,
    detector: AnomalyDetector,
    alert_mgr: AlertManager,
    dashboard: Dashboard,
    threshold: float,
    stop_event,
):
    """Consume flows from queue, score them, and update dashboard."""
    while not stop_event.is_set() or not flow_queue.empty():
        try:
            flow: Flow = flow_queue.get(timeout=0.1)
        except queue.Empty:
            continue

        x = extract(flow)
        score = detector.score_single(x)
        is_anomaly = score >= threshold
        dashboard.add_flow(flow, score, is_anomaly)

        alert = alert_mgr.maybe_alert(flow, score, threshold)
        if alert:
            dashboard.add_alert(alert)


# ------------------------------------------------------------------ #
# demo mode                                                           #
# ------------------------------------------------------------------ #

def cmd_demo(cfg: dict):
    """Train on synthetic normal traffic then detect with simulated attack mix."""
    demo_cfg = cfg.get("demo", {})
    model_cfg = cfg.get("models", {})
    det_cfg = cfg.get("detection", {})
    alert_cfg = cfg.get("alerts", {})

    model_path = os.path.join(model_cfg.get("save_dir", "saved_models"), "model.pkl")
    threshold = det_cfg.get("score_threshold", 0.55)
    min_train = model_cfg.get("min_train_samples", 200)
    n_train = max(min_train, 2000)

    dashboard = Dashboard(mode="DEMO")
    dashboard.start()
    dashboard.log("Demo mode started — no root access required")

    # --- Phase 1: train on synthetic normal flows ---
    dashboard.set_model_state("LEARNING")
    dashboard.log(f"Generating {n_train:,} normal baseline flows for training…")

    baseline_flows = generate_baseline(n_train, seed=demo_cfg.get("seed", 42))
    X_train = extract_batch(baseline_flows)

    if_cfg = model_cfg.get("isolation_forest", {})
    detector = AnomalyDetector(
        n_estimators=if_cfg.get("n_estimators", 200),
        contamination=if_cfg.get("contamination", 0.01),
        random_state=if_cfg.get("random_state", 42),
    )
    detector.fit(X_train)
    detector.save(model_path)

    dashboard.set_model_state("DETECTING")
    dashboard.log(f"Model trained on {n_train:,} flows — saved to {model_path}")
    dashboard.log(f"Starting live simulation (attack_prob={demo_cfg.get('attack_probability', 0.07):.0%})…")

    alert_mgr = AlertManager(
        severity_thresholds=alert_cfg.get("severity_thresholds"),
        cooldown_seconds=det_cfg.get("cooldown_seconds", 10),
        max_recent=alert_cfg.get("max_recent_display", 15),
    )

    # --- Phase 2: simulated live detection ---
    flow_queue: queue.Queue = queue.Queue()
    stop = _StopEvent()

    simulator = TrafficSimulator(
        on_flow=flow_queue.put,
        flows_per_second=demo_cfg.get("flows_per_second", 8),
        attack_probability=demo_cfg.get("attack_probability", 0.07),
        seed=demo_cfg.get("seed", 42) + 1,
    )

    def _handle_sigint(sig, frame):
        dashboard.log("Stopping — received SIGINT")
        stop.set()
        simulator.stop()

    signal.signal(signal.SIGINT, _handle_sigint)
    simulator.start()

    try:
        _run_detection_loop(flow_queue, detector, alert_mgr, dashboard, threshold, stop)
    finally:
        simulator.stop()
        time.sleep(0.3)
        dashboard.stop()
        print(f"\nSession summary: {dashboard._flows_processed:,} flows processed, "
              f"{alert_mgr.total} alerts raised.")


# ------------------------------------------------------------------ #
# learn mode                                                          #
# ------------------------------------------------------------------ #

def cmd_learn(cfg: dict, iface: str | None, duration: float):
    """Capture live traffic for <duration> seconds, train, and save model."""
    try:
        from src.capture.sniffer import LiveSniffer
    except ImportError as e:
        sys.exit(f"Error: {e}")

    model_cfg = cfg.get("models", {})
    cap_cfg = cfg.get("capture", {})
    model_path = os.path.join(model_cfg.get("save_dir", "saved_models"), "model.pkl")
    min_train = model_cfg.get("min_train_samples", 200)

    dashboard = Dashboard(mode="LEARN")
    dashboard.start()
    dashboard.set_model_state("LEARNING")
    dashboard.log(f"Capturing baseline on {'all interfaces' if not iface else iface} "
                  f"for {duration:.0f}s…")
    dashboard.log("Only capture normal traffic in this phase — no attacks!")

    captured_flows: list[Flow] = []
    flow_queue: queue.Queue = queue.Queue()

    def _on_flow(flow: Flow):
        flow_queue.put(flow)
        captured_flows.append(flow)
        dashboard.add_flow(flow, score=0.0, is_anomaly=False)

    tracker = FlowTracker(
        on_flow_complete=_on_flow,
        timeout_tcp=cap_cfg.get("flow_timeout_tcp", 30),
        timeout_udp=cap_cfg.get("flow_timeout_udp", 15),
        timeout_icmp=cap_cfg.get("flow_timeout_icmp", 5),
    )

    sniffer = LiveSniffer(
        tracker=tracker,
        iface=iface,
        timeout_check_interval=cap_cfg.get("timeout_check_interval", 5),
    )

    try:
        sniffer.start()
    except PermissionError as e:
        dashboard.stop()
        sys.exit(f"Error: {e}")

    deadline = time.time() + duration
    while time.time() < deadline:
        remaining = int(deadline - time.time())
        dashboard.log(f"Capturing… {remaining}s remaining | {len(captured_flows)} flows so far")
        time.sleep(5)

    sniffer.stop()
    dashboard.log(f"Capture complete: {len(captured_flows)} flows collected")

    if len(captured_flows) < min_train:
        dashboard.stop()
        sys.exit(
            f"Only {len(captured_flows)} flows captured; need at least {min_train}. "
            "Try a longer --duration or busier interface."
        )

    X = extract_batch(captured_flows)
    if_cfg = model_cfg.get("isolation_forest", {})
    detector = AnomalyDetector(
        n_estimators=if_cfg.get("n_estimators", 200),
        contamination=if_cfg.get("contamination", 0.01),
        random_state=if_cfg.get("random_state", 42),
    )
    detector.fit(X)
    detector.save(model_path)

    dashboard.set_model_state("TRAINED")
    dashboard.log(f"Model trained on {len(captured_flows)} flows and saved to {model_path}")
    time.sleep(2)
    dashboard.stop()
    print(f"\nBaseline model saved to {model_path}")
    print(f"Run 'sudo python ids.py detect' to start live detection.")


# ------------------------------------------------------------------ #
# detect mode                                                         #
# ------------------------------------------------------------------ #

def cmd_detect(cfg: dict, iface: str | None):
    """Load saved model and run live anomaly detection."""
    try:
        from src.capture.sniffer import LiveSniffer
    except ImportError as e:
        sys.exit(f"Error: {e}")

    model_cfg = cfg.get("models", {})
    cap_cfg = cfg.get("capture", {})
    det_cfg = cfg.get("detection", {})
    alert_cfg = cfg.get("alerts", {})

    model_path = os.path.join(model_cfg.get("save_dir", "saved_models"), "model.pkl")
    if not os.path.exists(model_path):
        sys.exit(f"No trained model found at {model_path}. Run 'sudo python ids.py learn' first.")

    detector = AnomalyDetector.load(model_path)
    threshold = det_cfg.get("score_threshold", 0.55)

    dashboard = Dashboard(mode="LIVE")
    dashboard.start()
    dashboard.set_model_state("DETECTING")
    dashboard.log(f"Model loaded from {model_path}")
    dashboard.log(f"Sniffing on {'all interfaces' if not iface else iface}…")

    flow_queue: queue.Queue = queue.Queue()

    tracker = FlowTracker(
        on_flow_complete=flow_queue.put,
        timeout_tcp=cap_cfg.get("flow_timeout_tcp", 30),
        timeout_udp=cap_cfg.get("flow_timeout_udp", 15),
        timeout_icmp=cap_cfg.get("flow_timeout_icmp", 5),
    )
    sniffer = LiveSniffer(
        tracker=tracker,
        iface=iface,
        timeout_check_interval=cap_cfg.get("timeout_check_interval", 5),
    )

    try:
        sniffer.start()
    except PermissionError as e:
        dashboard.stop()
        sys.exit(f"Error: {e}")

    alert_mgr = AlertManager(
        severity_thresholds=alert_cfg.get("severity_thresholds"),
        cooldown_seconds=det_cfg.get("cooldown_seconds", 10),
        max_recent=alert_cfg.get("max_recent_display", 15),
    )

    stop = _StopEvent()

    def _handle_sigint(sig, frame):
        dashboard.log("Stopping — received SIGINT")
        stop.set()
        sniffer.stop()

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        _run_detection_loop(flow_queue, detector, alert_mgr, dashboard, threshold, stop)
    finally:
        sniffer.stop()
        time.sleep(0.3)
        dashboard.stop()
        print(f"\nSession summary: {dashboard._flows_processed:,} flows processed, "
              f"{alert_mgr.total} alerts raised.")


# ------------------------------------------------------------------ #
# evaluate mode                                                       #
# ------------------------------------------------------------------ #

def cmd_evaluate(cfg: dict):
    """Evaluate the saved model on a labelled synthetic dataset."""
    import numpy as np
    from src.capture.simulator import generate_flow
    import random

    model_cfg = cfg.get("models", {})
    det_cfg = cfg.get("detection", {})
    model_path = os.path.join(model_cfg.get("save_dir", "saved_models"), "model.pkl")

    if not os.path.exists(model_path):
        sys.exit(f"No model at {model_path}. Run demo or learn first.")

    detector = AnomalyDetector.load(model_path)
    threshold = det_cfg.get("score_threshold", 0.55)

    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print("\n[bold]Evaluating model on labelled synthetic test set…[/bold]\n")

    rng = random.Random(999)
    n_normal = 1000
    n_per_attack = 200

    normal_flows = [generate_flow(rng, 0.0) for _ in range(n_normal)]
    attack_types = ["port_scan", "ddos_udp", "brute_force_ssh", "data_exfiltration", "c2_beaconing"]

    from src.capture.simulator import (
        _gen_port_scan, _gen_ddos_udp, _gen_brute_force_ssh,
        _gen_data_exfiltration, _gen_c2_beaconing,
    )
    attack_fns = {
        "port_scan": _gen_port_scan,
        "ddos_udp": _gen_ddos_udp,
        "brute_force_ssh": _gen_brute_force_ssh,
        "data_exfiltration": _gen_data_exfiltration,
        "c2_beaconing": _gen_c2_beaconing,
    }

    # Score normal flows
    X_normal = extract_batch(normal_flows)
    s_normal = detector.score(X_normal)
    fp = int((s_normal >= threshold).sum())
    tn = n_normal - fp
    fpr = fp / n_normal

    table = Table(title="Detection Results", show_header=True, header_style="bold")
    table.add_column("Attack Type", min_width=22)
    table.add_column("Detected", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("Avg Score", justify="right")

    total_detected = 0
    total_attacks = 0
    for atype in attack_types:
        flows = [attack_fns[atype](rng) for _ in range(n_per_attack)]
        X = extract_batch(flows)
        scores = detector.score(X)
        detected = int((scores >= threshold).sum())
        recall = detected / n_per_attack
        avg_score = float(scores.mean())
        total_detected += detected
        total_attacks += n_per_attack
        color = "green" if recall >= 0.7 else ("yellow" if recall >= 0.4 else "red")
        table.add_row(
            atype,
            str(detected),
            str(n_per_attack),
            f"[{color}]{recall:.1%}[/{color}]",
            f"{avg_score:.3f}",
        )

    console.print(table)

    overall_recall = total_detected / total_attacks
    console.print(f"\n[bold]Overall recall:[/bold] {overall_recall:.1%}  "
                  f"({total_detected}/{total_attacks} attacks detected)")
    console.print(f"[bold]False positive rate (normal traffic):[/bold] {fpr:.1%}  "
                  f"({fp}/{n_normal} normal flows mis-classified)")
    console.print(f"[bold]Threshold:[/bold] {threshold}")
    console.print()


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

class _StopEvent:
    def __init__(self):
        self._set = False

    def set(self):
        self._set = True

    def is_set(self):
        return self._set


# ------------------------------------------------------------------ #
# Entry point                                                         #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description="AI-Driven Network Anomaly Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Simulated traffic demo — no root required")

    learn_p = sub.add_parser("learn", help="Capture baseline traffic and train model (needs root)")
    learn_p.add_argument("--iface", default=None, help="Network interface (e.g. eth0)")
    learn_p.add_argument("--duration", type=float, default=120, help="Capture duration in seconds")

    detect_p = sub.add_parser("detect", help="Live anomaly detection with trained model (needs root)")
    detect_p.add_argument("--iface", default=None, help="Network interface (e.g. eth0)")

    sub.add_parser("evaluate", help="Evaluate model quality on labelled synthetic data")

    args = parser.parse_args()
    cfg = load_config(args.config)

    if args.command == "demo":
        cmd_demo(cfg)
    elif args.command == "learn":
        cmd_learn(cfg, args.iface, args.duration)
    elif args.command == "detect":
        cmd_detect(cfg, args.iface)
    elif args.command == "evaluate":
        cmd_evaluate(cfg)


if __name__ == "__main__":
    main()
