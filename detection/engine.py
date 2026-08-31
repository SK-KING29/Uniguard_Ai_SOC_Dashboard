"""
Real-time detection engine.

Operates on 1-second traffic windows built from ACTUAL logged HTTP requests
(see app.py middleware). No values here are randomly generated - everything
is a function of real observed traffic.
"""
import numpy as np
from collections import deque
from sklearn.ensemble import IsolationForest

BASELINE_BUFFER_SIZE = 120   # ~2 min of calm windows
FEATURE_BUFFER_SIZE = 300
MIN_WINDOWS_TO_TRAIN = 30
RETRAIN_EVERY = 15


class DetectionEngine:
    def __init__(self):
        self.baseline_buffer = deque(maxlen=BASELINE_BUFFER_SIZE)
        self.feature_buffer = deque(maxlen=FEATURE_BUFFER_SIZE)
        self.model = None
        self.windows_since_train = 0
        self.baseline_rate = 0.5  # req/s, seeded low, adapts from real traffic

    def _features(self, window):
        return np.array([
            window["req_per_sec"],
            window["bytes_per_sec"] / 1000.0,
            window["unique_ips"],
            window["endpoint_concentration"],
            window["burst_indicator"],
        ], dtype=float)

    def update_baseline(self, window):
        """Fold window into baseline only if it looks like calm traffic."""
        if window["req_per_sec"] <= max(3.0, self.baseline_rate * 2.5):
            self.baseline_buffer.append(window["req_per_sec"])
            if self.baseline_buffer:
                self.baseline_rate = float(np.mean(self.baseline_buffer))

    def analyze(self, window):
        feat = self._features(window)
        self.feature_buffer.append(feat)
        self.windows_since_train += 1

        anomaly_score = 0.0
        model_ready = False
        if len(self.feature_buffer) >= MIN_WINDOWS_TO_TRAIN:
            if self.model is None or self.windows_since_train >= RETRAIN_EVERY:
                X = np.array(self.feature_buffer)
                try:
                    # contamination is intentionally very low: this trains mostly on
                    # calm/normal windows, so the model's baseline is "this is normal",
                    # not "20% of everything must be flagged" (that was a real bug -
                    # a fixed contamination rate flags outliers even in perfectly calm,
                    # repetitive traffic, since it forces a fixed proportion regardless
                    # of the actual distribution).
                    self.model = IsolationForest(
                        n_estimators=150, contamination=0.03, random_state=42
                    ).fit(X)
                    # calibration reference: raw decision_function scores of the
                    # training data itself, used below for percentile-based scoring
                    self._train_scores = self.model.decision_function(X)
                except Exception:
                    self.model = None
                self.windows_since_train = 0
            if self.model is not None and getattr(self, "_train_scores", None) is not None:
                raw = float(self.model.decision_function([feat])[0])  # higher = more normal
                # percentile rank against recent calibration data: robust and
                # self-scaling, instead of an arbitrary fixed linear transform
                pct_more_normal = float(np.mean(self._train_scores <= raw))  # 0..1
                anomaly_score = float(np.clip((1.0 - pct_more_normal) * 100, 0, 100))
                model_ready = True

        baseline_deviation_pct = 0.0
        if self.baseline_rate > 0:
            baseline_deviation_pct = max(
                0.0, (window["req_per_sec"] - self.baseline_rate) / self.baseline_rate
            ) * 100

        return {
            "anomaly_score": round(anomaly_score, 1),
            "model_ready": model_ready,
            "baseline_deviation_pct": round(baseline_deviation_pct, 1),
            "baseline_rate": round(self.baseline_rate, 2),
        }
