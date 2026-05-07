import time
import random

from src.capture.simulator import generate_flow
from src.detection.alerts import Alert, AlertManager, classify_attack_type
from src.capture.simulator import (
    _gen_port_scan, _gen_ddos_udp, _gen_brute_force_ssh,
    _gen_data_exfiltration, _gen_c2_beaconing,
)


def _rng():
    return random.Random(42)


def test_classify_port_scan():
    flow = _gen_port_scan(_rng())
    label = classify_attack_type(flow)
    assert label == "Port Scan"


def test_classify_ddos():
    flow = _gen_ddos_udp(_rng())
    label = classify_attack_type(flow)
    assert label == "DDoS / UDP Flood"


def test_classify_brute_force():
    flow = _gen_brute_force_ssh(_rng())
    label = classify_attack_type(flow)
    assert label == "SSH Brute Force"


def test_classify_exfiltration():
    flow = _gen_data_exfiltration(_rng())
    label = classify_attack_type(flow)
    assert label == "Data Exfiltration"


def test_classify_c2():
    flow = _gen_c2_beaconing(_rng())
    label = classify_attack_type(flow)
    assert label == "C2 Beaconing"


def test_alert_manager_suppresses_below_threshold():
    mgr = AlertManager(cooldown_seconds=0)
    flow = generate_flow(_rng(), 0.0)
    alert = mgr.maybe_alert(flow, score=0.2, threshold=0.55)
    assert alert is None
    assert mgr.total == 0


def test_alert_manager_raises_above_threshold():
    mgr = AlertManager(cooldown_seconds=0)
    flow = _gen_port_scan(_rng())
    alert = mgr.maybe_alert(flow, score=0.9, threshold=0.55)
    assert alert is not None
    assert alert.severity == "HIGH"
    assert mgr.total == 1


def test_alert_manager_cooldown():
    mgr = AlertManager(cooldown_seconds=60)
    flow = _gen_port_scan(_rng())
    a1 = mgr.maybe_alert(flow, score=0.9, threshold=0.55)
    a2 = mgr.maybe_alert(flow, score=0.9, threshold=0.55)
    assert a1 is not None
    assert a2 is None  # suppressed by cooldown
    assert mgr.total == 1


def test_alert_severity_high():
    mgr = AlertManager(severity_thresholds={"high": 0.80, "medium": 0.60})
    flow = _gen_ddos_udp(_rng())
    alert = mgr.maybe_alert(flow, score=0.95, threshold=0.4)
    assert alert.severity == "HIGH"


def test_alert_severity_medium():
    mgr = AlertManager(severity_thresholds={"high": 0.80, "medium": 0.60})
    flow = _gen_brute_force_ssh(_rng())
    alert = mgr.maybe_alert(flow, score=0.65, threshold=0.4)
    assert alert.severity == "MEDIUM"


def test_alert_time_str_format():
    mgr = AlertManager(cooldown_seconds=0)
    flow = _gen_data_exfiltration(_rng())
    alert = mgr.maybe_alert(flow, score=0.9, threshold=0.5)
    ts = alert.time_str
    assert len(ts) == 8 and ts[2] == ":" and ts[5] == ":"
