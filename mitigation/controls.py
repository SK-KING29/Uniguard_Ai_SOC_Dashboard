"""
Real, in-memory defensive controls. These are actually checked by the
request middleware in app.py on every incoming request - when a judge
clicks a mitigation button, this store is what makes subsequent requests
from the target actually get rejected (403/429), for real.

Everything auto-expires (TTL) so a demo can never leave anything blocked
permanently, per the "safe defensive implementation" requirement.
"""
import time
import threading


class MitigationStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.blocked = {}              # ip -> expires_at
        self.rate_limited = {}         # ip -> {"limit": n, "expires_at": t}
        self.protected_endpoints = {}  # path -> {"limit": n, "expires_at": t}
        self._buckets = {}             # ip -> (tokens, last_refill)
        self._ep_buckets = {}          # path -> (tokens, last_refill)
        self.audit_log = []            # every action taken, for the event log / timeline

    def _cleanup_locked(self):
        now = time.time()
        self.blocked = {k: v for k, v in self.blocked.items() if v > now}
        self.rate_limited = {k: v for k, v in self.rate_limited.items() if v["expires_at"] > now}
        self.protected_endpoints = {k: v for k, v in self.protected_endpoints.items() if v["expires_at"] > now}

    def block_ip(self, ip: str, ttl: int = 120):
        with self.lock:
            self.blocked[ip] = time.time() + ttl
            self.audit_log.append({"time": time.time(), "action": "BLOCK_SOURCE", "target": ip, "ttl": ttl})

    def rate_limit_ip(self, ip: str, limit_per_sec: float = 2.0, ttl: int = 120):
        with self.lock:
            self.rate_limited[ip] = {"limit": limit_per_sec, "expires_at": time.time() + ttl}
            self.audit_log.append({"time": time.time(), "action": "RATE_LIMIT_SOURCE", "target": ip,
                                    "limit": limit_per_sec, "ttl": ttl})

    def protect_endpoint(self, path: str, limit_per_sec: float = 10.0, ttl: int = 120):
        with self.lock:
            self.protected_endpoints[path] = {"limit": limit_per_sec, "expires_at": time.time() + ttl}
            self.audit_log.append({"time": time.time(), "action": "PROTECT_ENDPOINT", "target": path,
                                    "limit": limit_per_sec, "ttl": ttl})

    def monitor_only(self):
        with self.lock:
            self.audit_log.append({"time": time.time(), "action": "MONITOR_ONLY", "target": None})

    def reset(self):
        with self.lock:
            self.blocked.clear()
            self.rate_limited.clear()
            self.protected_endpoints.clear()
            self._buckets.clear()
            self._ep_buckets.clear()
            self.audit_log.append({"time": time.time(), "action": "RESET_DEMO", "target": None})

    def check(self, ip: str, path: str):
        """Called by middleware on EVERY request. Returns (allowed, reason)."""
        with self.lock:
            self._cleanup_locked()
            now = time.time()

            if ip in self.blocked:
                return False, "blocked"

            if ip in self.rate_limited:
                limit = self.rate_limited[ip]["limit"]
                tokens, last = self._buckets.get(ip, (limit, now))
                tokens = min(limit, tokens + (now - last) * limit)
                if tokens < 1:
                    self._buckets[ip] = (tokens, now)
                    return False, "rate_limited"
                self._buckets[ip] = (tokens - 1, now)

            if path in self.protected_endpoints:
                limit = self.protected_endpoints[path]["limit"]
                tokens, last = self._ep_buckets.get(path, (limit, now))
                tokens = min(limit, tokens + (now - last) * limit)
                if tokens < 1:
                    self._ep_buckets[path] = (tokens, now)
                    return False, "endpoint_protected"
                self._ep_buckets[path] = (tokens - 1, now)

            return True, None

    def status(self):
        with self.lock:
            self._cleanup_locked()
            now = time.time()
            return {
                "blocked": [{"ip": ip, "seconds_remaining": round(exp - now)} for ip, exp in self.blocked.items()],
                "rate_limited": [{"ip": ip, "limit": v["limit"], "seconds_remaining": round(v["expires_at"] - now)}
                                  for ip, v in self.rate_limited.items()],
                "protected_endpoints": [{"path": p, "limit": v["limit"], "seconds_remaining": round(v["expires_at"] - now)}
                                         for p, v in self.protected_endpoints.items()],
            }
