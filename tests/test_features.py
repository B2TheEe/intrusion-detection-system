import numpy as np
import pytest

from src.capture.simulator import generate_baseline, generate_flow
from src.features.extractor import extract, extract_batch, N_FEATURES, FEATURE_NAMES
import random


def _simple_flow():
    return generate_flow(random.Random(1), attack_probability=0.0)


def test_extract_shape():
    flow = _simple_flow()
    v = extract(flow)
    assert v.shape == (N_FEATURES,)


def test_extract_dtype():
    v = extract(_simple_flow())
    assert v.dtype == np.float64


def test_no_nan_or_inf():
    rng = random.Random(42)
    for _ in range(200):
        flow = generate_flow(rng, attack_probability=0.5)
        v = extract(flow)
        assert not np.any(np.isnan(v)), f"NaN in features for flow {flow}"
        assert not np.any(np.isinf(v)), f"Inf in features for flow {flow}"


def test_extract_batch_shape():
    flows = generate_baseline(50, seed=7)
    X = extract_batch(flows)
    assert X.shape == (50, N_FEATURES)


def test_feature_names_count():
    assert len(FEATURE_NAMES) == N_FEATURES


def test_log_transforms_non_negative():
    rng = random.Random(0)
    for _ in range(100):
        flow = generate_flow(rng, 0.0)
        v = extract(flow)
        # Log-transformed features (first 13) should be >= 0
        assert np.all(v[:13] >= 0), "log1p features must be non-negative"


def test_ratio_features_in_unit_interval():
    rng = random.Random(0)
    for _ in range(100):
        flow = generate_flow(rng, 0.0)
        v = extract(flow)
        ratio_indices = [FEATURE_NAMES.index("bytes_ratio"), FEATURE_NAMES.index("pkts_ratio")]
        for idx in ratio_indices:
            assert 0.0 <= v[idx] <= 1.0, f"Ratio feature {FEATURE_NAMES[idx]}={v[idx]} out of [0,1]"
