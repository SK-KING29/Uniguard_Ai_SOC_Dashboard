"""
Real throughput / detection-latency benchmark.

Every number here is measured from the actual analysis loop in app.py -
detection latency is the real wall-clock time the engine/risk/incident
pipeline took to process each 1s window (time.perf_counter, not a
guess); throughput is the real req/s already computed from logged
traffic. Nothing is hardcoded. Until enough windows have been measured,
stats() reports NOT BENCHMARKED rather than a fabricated number.

Scope: this backend monitors application-layer HTTP requests, not raw
packets, so packets/sec and Mbps are not measurable here and are not
reported. That's a real ceiling of this implementation, not something to
paper over with an invented figure.
"""
from collections import deque

MIN_SAMPLES_FOR_BENCHMARK = 10
SAMPLE_WINDOW = 300  # ~5 min of 1s windows


class Benchmark:
    def __init__(self):
        self.latencies_ms = deque(maxlen=SAMPLE_WINDOW)
        self.throughput_samples = deque(maxlen=SAMPLE_WINDOW)
        self.alert_timestamps = deque(maxlen=SAMPLE_WINDOW)
        self.windows_processed = 0

    def record_window(self, process_seconds: float, req_per_sec: float, is_alert: bool, now: float):
        self.latencies_ms.append(max(0.0, process_seconds) * 1000.0)
        self.throughput_samples.append(max(0.0, req_per_sec))
        self.windows_processed += 1
        if is_alert:
            self.alert_timestamps.append(now)

    def stats(self, now: float = None):
        import time as _time
        now = _time.time() if now is None else now

        if len(self.latencies_ms) < MIN_SAMPLES_FOR_BENCHMARK:
            return {
                "benchmarked": False,
                "status": "NOT BENCHMARKED",
                "samples_collected": len(self.latencies_ms),
                "samples_required": MIN_SAMPLES_FOR_BENCHMARK,
                "measurement_scope": (
                    "Application-layer HTTP requests/sec only - no raw packet "
                    "capture in this build, so packets/sec and Mbps are not measured."
                ),
            }

        lat_sorted = sorted(self.latencies_ms)
        avg_latency = sum(lat_sorted) / len(lat_sorted)
        p95_idx = max(0, int(round(len(lat_sorted) * 0.95)) - 1)
        p95_latency = lat_sorted[p95_idx]
        avg_throughput = sum(self.throughput_samples) / len(self.throughput_samples)
        recent_alerts = [t for t in self.alert_timestamps if now - t <= 60]

        return {
            "benchmarked": True,
            "status": "BENCHMARKED",
            "avg_detection_latency_ms": round(avg_latency, 2),
            "p95_detection_latency_ms": round(p95_latency, 2),
            "throughput_requests_per_sec": round(avg_throughput, 2),
            "alerts_per_sec": round(len(recent_alerts) / 60.0, 3),
            "windows_processed": self.windows_processed,
            "samples_in_window": len(self.latencies_ms),
            "measurement_scope": (
                "Application-layer HTTP requests/sec only - no raw packet "
                "capture in this build, so packets/sec and Mbps are not measured."
            ),
        }
