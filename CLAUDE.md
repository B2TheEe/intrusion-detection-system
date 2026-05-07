# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_detector.py -v

# Run a single test
python -m pytest tests/test_alerts.py::test_classify_port_scan -v

# Demo mode (no root required)
python ids.py demo

# Evaluate model quality on labelled synthetic data
python ids.py evaluate

# Live capture — requires root
sudo python ids.py learn --iface eth0 --duration 120
sudo python ids.py detect --iface eth0
```

## Architecture

The pipeline is: **Packets → FlowTracker → FeatureExtractor → IsolationForest → AlertManager → Dashboard**

`ids.py` is the single entry point with four subcommands: `demo`, `learn`, `detect`, `evaluate`. `demo` trains on synthetic normal flows and then streams simulated attack-mixed traffic — it requires no root and is the primary way to develop and test end-to-end.

### Data flow

**Live path** (`learn` / `detect`): `LiveSniffer` (`src/capture/sniffer.py`) runs scapy's `AsyncSniffer` in a background thread alongside a timeout-sweeper thread. Both feed into `FlowTracker` (`src/capture/flow_tracker.py`), which aggregates raw packets into bidirectional `Flow` objects keyed by a canonical 5-tuple. A flow is closed on TCP FIN/RST or protocol-specific idle timeout, then emitted to a `queue.Queue`.

**Demo path**: `TrafficSimulator` (`src/capture/simulator.py`) generates `Flow` objects directly at a configurable rate and puts them into the same queue, bypassing scapy entirely.

The main thread consumes completed flows from the queue, calls `extract()` (`src/features/extractor.py`) to produce a 21-feature log-normalised numpy vector, then calls `AnomalyDetector.score_single()` (`src/models/detector.py`).

### Key design decisions

- **Features** (`src/features/extractor.py`): Count/size features are `log1p`-transformed to compress dynamic range before StandardScaler + IsolationForest. Feature names are in `FEATURE_NAMES`; the vector dimension is `N_FEATURES = 21`.
- **Scoring** (`src/models/detector.py`): Raw IsolationForest scores are calibrated against the training set min/max and normalised to `[0, 1]` (1 = most anomalous). The model and scaler are saved together via joblib to `saved_models/model.pkl`.
- **Alert classification** (`src/detection/alerts.py`): `classify_attack_type()` applies rule-based heuristics on the raw `Flow` fields (not features) to label alert type. The `AlertManager` enforces a per-source-IP cooldown to suppress alert storms.
- **Dashboard** (`src/ui/dashboard.py`): Uses `rich.live.Live` and requires a real TTY — it will not render in a backgrounded process.

### Simulator attack profiles

`src/capture/simulator.py` contains generators for five attack types (`_gen_port_scan`, `_gen_ddos_udp`, `_gen_brute_force_ssh`, `_gen_data_exfiltration`, `_gen_c2_beaconing`) and seven normal profiles. `generate_baseline(n)` produces normal-only flows for training. Each generator produces a `Flow` with `label` set to the attack name.

### Configuration

All tunable parameters are in `config.yaml`. Key ones:
- `detection.score_threshold` — anomaly cutoff (default 0.60)
- `detection.cooldown_seconds` — min seconds between alerts per source IP
- `models.isolation_forest.*` — sklearn IsolationForest parameters
- `demo.attack_probability` — fraction of simulated flows that are attacks
