"""
Converts a Flow into a fixed-length numpy feature vector.

All count/size features are log1p-transformed to compress the dynamic
range before feeding into the Isolation Forest.
"""
from __future__ import annotations

import numpy as np

from src.capture.flow_tracker import Flow

FEATURE_NAMES = [
    "log_duration",
    "log_fwd_pkts",
    "log_bwd_pkts",
    "log_fwd_bytes",
    "log_bwd_bytes",
    "log_fwd_pkt_rate",
    "log_bwd_pkt_rate",
    "log_fwd_byte_rate",
    "log_bwd_byte_rate",
    "bytes_ratio",
    "pkts_ratio",
    "log_avg_fwd_pkt",
    "log_avg_bwd_pkt",
    "is_tcp",
    "is_udp",
    "dst_port_privileged",
    "syn_ratio",
    "rst_ratio",
    "fin_ratio",
    "log_fwd_iat_mean",
    "log_fwd_iat_std",
]

N_FEATURES = len(FEATURE_NAMES)


def extract(flow: Flow) -> np.ndarray:
    """Return a 1-D float64 array of shape (N_FEATURES,)."""
    v = np.array(
        [
            np.log1p(flow.duration),
            np.log1p(flow.fwd_pkts),
            np.log1p(flow.bwd_pkts),
            np.log1p(flow.fwd_bytes),
            np.log1p(flow.bwd_bytes),
            np.log1p(flow.fwd_pkt_rate),
            np.log1p(flow.bwd_pkt_rate),
            np.log1p(flow.fwd_byte_rate),
            np.log1p(flow.bwd_byte_rate),
            flow.bytes_ratio,
            flow.pkts_ratio,
            np.log1p(flow.avg_fwd_pkt_size),
            np.log1p(flow.avg_bwd_pkt_size),
            float(flow.is_tcp),
            float(flow.is_udp),
            float(flow.dst_port_privileged),
            flow.syn_ratio,
            flow.rst_ratio,
            flow.fin_ratio,
            np.log1p(flow.fwd_iat_mean),
            np.log1p(flow.fwd_iat_std),
        ],
        dtype=np.float64,
    )
    # Guard against NaN/Inf from edge cases
    np.nan_to_num(v, nan=0.0, posinf=0.0, neginf=0.0, copy=False)
    return v


def extract_batch(flows: list[Flow]) -> np.ndarray:
    """Return array of shape (len(flows), N_FEATURES)."""
    return np.vstack([extract(f) for f in flows])
