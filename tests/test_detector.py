import numpy as np
import os
import tempfile

import pytest

from src.capture.simulator import generate_baseline, generate_flow
from src.features.extractor import extract_batch
from src.models.detector import AnomalyDetector
import random


def _trained_detector(n=500) -> AnomalyDetector:
    flows = generate_baseline(n, seed=1)
    X = extract_batch(flows)
    d = AnomalyDetector(n_estimators=50, random_state=0)
    d.fit(X)
    return d


def test_fit_marks_trained():
    d = _trained_detector()
    assert d.is_trained()


def test_score_shape():
    d = _trained_detector()
    flows = generate_baseline(10, seed=2)
    X = extract_batch(flows)
    scores = d.score(X)
    assert scores.shape == (10,)


def test_scores_in_unit_interval():
    d = _trained_detector()
    rng = random.Random(3)
    flows = [generate_flow(rng, 0.5) for _ in range(100)]
    X = extract_batch(flows)
    scores = d.score(X)
    assert np.all(scores >= 0.0) and np.all(scores <= 1.0)


def test_attacks_score_higher_than_normal():
    """Anomalous flows should have a higher median score than normal flows."""
    d = _trained_detector(n=1000)
    rng = random.Random(99)

    normal_flows = [generate_flow(rng, 0.0) for _ in range(200)]
    attack_flows = [generate_flow(rng, 1.0) for _ in range(200)]

    s_normal = d.score(extract_batch(normal_flows))
    s_attack = d.score(extract_batch(attack_flows))

    assert np.median(s_attack) > np.median(s_normal), (
        f"Attacks median={np.median(s_attack):.3f} should exceed "
        f"normal median={np.median(s_normal):.3f}"
    )


def test_untrained_raises():
    d = AnomalyDetector()
    X = np.random.rand(5, 21)
    with pytest.raises(RuntimeError):
        d.score(X)


def test_save_load_roundtrip():
    d = _trained_detector()
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "model.pkl")
        d.save(path)
        d2 = AnomalyDetector.load(path)

    rng = random.Random(7)
    flows = [generate_flow(rng, 0.5) for _ in range(20)]
    X = extract_batch(flows)
    np.testing.assert_allclose(d.score(X), d2.score(X))


def test_score_single():
    d = _trained_detector()
    rng = random.Random(5)
    flow = generate_flow(rng, 0.0)
    x = extract_batch([flow])[0]
    s = d.score_single(x)
    assert isinstance(s, float)
    assert 0.0 <= s <= 1.0
