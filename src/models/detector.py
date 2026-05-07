"""
Isolation Forest anomaly detector.

Scores are normalised to [0, 1] where 1 = most anomalous.
The model is trained on normal-only traffic; high-reconstruction-error
outliers are flagged as anomalies.
"""
from __future__ import annotations

import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.01,
        max_samples: int | str = "auto",
        random_state: int = 42,
    ):
        self._scaler = StandardScaler()
        self._forest = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
        )
        self._trained = False
        # Calibration bounds from training set (used for score normalisation)
        self._score_min: float = -0.5
        self._score_max: float = 0.0

    # ------------------------------------------------------------------ #
    # Training                                                             #
    # ------------------------------------------------------------------ #

    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """Train on a matrix of shape (n_samples, n_features)."""
        Xs = self._scaler.fit_transform(X)
        self._forest.fit(Xs)

        # Calibrate score range on training data so we can normalise later.
        raw = self._forest.score_samples(Xs)
        self._score_min = float(raw.min())
        self._score_max = float(raw.max())
        self._trained = True
        return self

    # ------------------------------------------------------------------ #
    # Inference                                                            #
    # ------------------------------------------------------------------ #

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Return anomaly scores in [0, 1] for each row.
        Higher = more anomalous.
        """
        self._require_trained()
        Xs = self._scaler.transform(X)
        raw = self._forest.score_samples(Xs)  # lower (more negative) = more anomalous
        # Flip and clip to [0, 1]
        span = max(self._score_max - self._score_min, 1e-9)
        normalised = np.clip((self._score_max - raw) / span, 0.0, 1.0)
        return normalised

    def score_single(self, x: np.ndarray) -> float:
        return float(self.score(x.reshape(1, -1))[0])

    def predict(self, X: np.ndarray, threshold: float = 0.55) -> np.ndarray:
        """Return True where flow is anomalous."""
        return self.score(X) >= threshold

    # ------------------------------------------------------------------ #
    # Persistence                                                          #
    # ------------------------------------------------------------------ #

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        joblib.dump(
            {
                "scaler": self._scaler,
                "forest": self._forest,
                "score_min": self._score_min,
                "score_max": self._score_max,
            },
            path,
        )

    @classmethod
    def load(cls, path: str) -> "AnomalyDetector":
        data = joblib.load(path)
        obj = cls.__new__(cls)
        obj._scaler = data["scaler"]
        obj._forest = data["forest"]
        obj._score_min = data["score_min"]
        obj._score_max = data["score_max"]
        obj._trained = True
        return obj

    def is_trained(self) -> bool:
        return self._trained

    def _require_trained(self):
        if not self._trained:
            raise RuntimeError("Detector has not been trained yet. Call fit() first.")
