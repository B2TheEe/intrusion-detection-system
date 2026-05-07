# AI-Driven Network Anomaly Detection System

Detects network anomalies in real time using an **Isolation Forest** trained on normal traffic patterns. Supports live packet capture (scapy) and a fully self-contained demo mode that requires no root access.

## Architecture

```
Packets → FlowTracker → FeatureExtractor → IsolationForest → AlertManager → Dashboard
```

| Component | File | Purpose |
|---|---|---|
| FlowTracker | `src/capture/flow_tracker.py` | Aggregates raw packets into bidirectional flows |
| LiveSniffer | `src/capture/sniffer.py` | Scapy-based async packet capture |
| TrafficSimulator | `src/capture/simulator.py` | Synthetic flow generator (no root needed) |
| FeatureExtractor | `src/features/extractor.py` | 21-feature log-normalised vector per flow |
| AnomalyDetector | `src/models/detector.py` | Isolation Forest with calibrated [0,1] scores |
| AlertManager | `src/detection/alerts.py` | Threshold gating, cooldown, attack classification |
| Dashboard | `src/ui/dashboard.py` | Live Rich terminal UI |

## Detected attack types

| Attack | Detection approach |
|---|---|
| Port scan | Very short TCP flows, RST flags, tiny byte count |
| DDoS / UDP flood | Extreme packet rate on UDP |
| SYN flood | High SYN ratio, very short duration |
| SSH brute force | Port 22, multiple RSTs, short session |
| Data exfiltration | Outbound bytes > 5 MB |
| C2 beaconing | Regular inter-arrival times, small payload |

## Detection quality (on synthetic labelled test set)

| Attack Type | Recall |
|---|---|
| Port scan | 100% |
| DDoS / UDP flood | 100% |
| Data exfiltration | 100% |
| C2 beaconing | ~99.5% |
| SSH brute force | ~53% |
| **Overall** | **~90.5%** |

False positive rate on normal traffic: ~8% at default threshold (0.60).

## Quick start

```bash
pip install -r requirements.txt

# Demo mode — no root, simulated traffic
python ids.py demo

# Evaluate model quality on labelled synthetic data
python ids.py evaluate
```

## Live capture (requires root / CAP_NET_RAW)

```bash
# 1. Collect baseline (normal traffic only, 2 minutes)
sudo python ids.py learn --duration 120 --iface eth0

# 2. Start live detection
sudo python ids.py detect --iface eth0
```

## Configuration

All parameters live in `config.yaml`:

- `detection.score_threshold` — anomaly score cutoff (0–1), default 0.60
- `detection.cooldown_seconds` — minimum seconds between alerts for same source IP
- `models.isolation_forest.*` — `n_estimators`, `contamination`, `random_state`
- `demo.attack_probability` — fraction of simulated flows that are attacks
- `alerts.severity_thresholds` — score cutoffs for LOW / MEDIUM / HIGH

## Running tests

```bash
python -m pytest tests/ -v
```
