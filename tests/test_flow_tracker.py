import time
from src.capture.flow_tracker import FlowTracker, Flow, PROTO_TCP, PROTO_UDP


def _make_tracker():
    completed = []
    tracker = FlowTracker(on_flow_complete=completed.append, timeout_tcp=1, timeout_udp=0.5)
    return tracker, completed


def test_new_flow_created_on_first_packet():
    tracker, completed = _make_tracker()
    tracker._update("1.2.3.4", "5.6.7.8", 12345, 80, PROTO_TCP, 100, 0x02)
    assert tracker.active_flow_count() == 1


def test_bidirectional_tracking():
    tracker, completed = _make_tracker()
    tracker._update("1.2.3.4", "5.6.7.8", 12345, 80, PROTO_TCP, 100, 0x02)  # SYN fwd
    tracker._update("5.6.7.8", "1.2.3.4", 80, 12345, PROTO_TCP, 60, 0x12)   # SYN-ACK bwd
    assert tracker.active_flow_count() == 1

    with tracker._lock:
        key = list(tracker._flows.keys())[0]
        flow = tracker._flows[key]

    assert flow.fwd_pkts == 1
    assert flow.bwd_pkts == 1
    assert flow.fwd_bytes == 100
    assert flow.bwd_bytes == 60


def test_rst_completes_flow():
    tracker, completed = _make_tracker()
    tracker._update("1.2.3.4", "5.6.7.8", 12345, 80, PROTO_TCP, 100, 0x02)  # SYN
    tracker._update("1.2.3.4", "5.6.7.8", 12345, 80, PROTO_TCP, 50, 0x04)   # RST
    assert tracker.active_flow_count() == 0
    assert len(completed) == 1


def test_fin_completes_flow():
    tracker, completed = _make_tracker()
    tracker._update("10.0.0.1", "8.8.8.8", 55000, 443, PROTO_TCP, 200, 0x02)
    tracker._update("10.0.0.1", "8.8.8.8", 55000, 443, PROTO_TCP, 100, 0x01)  # FIN
    assert len(completed) == 1
    assert completed[0].total_bytes == 300


def test_udp_flow_stays_open():
    tracker, completed = _make_tracker()
    tracker._update("1.2.3.4", "8.8.8.8", 50000, 53, PROTO_UDP, 60, 0)
    tracker._update("8.8.8.8", "1.2.3.4", 53, 50000, PROTO_UDP, 200, 0)
    assert tracker.active_flow_count() == 1
    assert len(completed) == 0


def test_flow_timeout():
    tracker, completed = _make_tracker()
    tracker._update("1.2.3.4", "8.8.8.8", 50000, 53, PROTO_UDP, 60, 0)
    # Manually backdate the flow's end_time
    with tracker._lock:
        key = list(tracker._flows.keys())[0]
        tracker._flows[key].end_time = time.time() - 10  # far past timeout

    tracker.expire_old_flows()
    assert tracker.active_flow_count() == 0
    assert len(completed) == 1


def test_flow_derived_properties():
    tracker, completed = _make_tracker()
    tracker._update("10.0.0.1", "1.2.3.4", 40000, 80, PROTO_TCP, 1000, 0x02)
    tracker._update("1.2.3.4", "10.0.0.1", 80, 40000, PROTO_TCP, 5000, 0x01)  # FIN

    f: Flow = completed[0]
    assert f.total_bytes == 6000
    assert f.bytes_ratio == 1000 / 6001
    assert f.is_tcp
    assert not f.is_udp
    assert f.fwd_pkts == 1
    assert f.bwd_pkts == 1
    assert f.duration > 0
    assert f.fwd_pkt_rate > 0
