"""
Benchmark helper: resource usage monitoring.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Samples CPU% and RSS memory of the current process (and any child
processes it spawns, e.g. nmap/nikto subprocess calls) at a fixed
interval on a background thread, for the duration of a `with` block.

Real measurements only — if psutil isn't available, this raises rather
than silently returning fabricated/zero numbers.
"""

import threading
import time

import psutil


class ResourceMonitor:
    """Usage:
    with ResourceMonitor(interval=0.5) as mon:
        do_the_thing()
    print(mon.result())
    """

    def __init__(self, interval: float = 0.5):
        self.interval = interval
        self._process = psutil.Process()
        self._samples_cpu = []
        self._samples_rss_mb = []
        self._stop = threading.Event()
        self._thread = None
        self._start_time = None
        self._end_time = None

    def _sample_loop(self):
        # Prime cpu_percent() — its first call always returns 0.0 by design
        # (it needs a preceding call to establish a baseline).
        self._process.cpu_percent()
        for child in self._safe_children():
            try:
                child.cpu_percent()
            except psutil.NoSuchProcess:
                pass

        while not self._stop.is_set():
            try:
                cpu = self._process.cpu_percent()
                rss = self._process.memory_info().rss
                for child in self._safe_children():
                    try:
                        cpu += child.cpu_percent()
                        rss += child.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self._samples_cpu.append(cpu)
                self._samples_rss_mb.append(rss / (1024 * 1024))
            except psutil.NoSuchProcess:
                pass
            self._stop.wait(self.interval)

    def _safe_children(self):
        try:
            return self._process.children(recursive=True)
        except psutil.NoSuchProcess:
            return []

    def __enter__(self):
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._end_time = time.time()
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval * 2)
        return False

    def result(self) -> dict:
        duration = (self._end_time or time.time()) - (self._start_time or time.time())
        if not self._samples_cpu:
            return {
                "duration_seconds": round(duration, 2),
                "cpu_percent_avg": None,
                "cpu_percent_peak": None,
                "rss_mb_avg": None,
                "rss_mb_peak": None,
                "sample_count": 0,
                "note": "no samples collected — duration too short for the sampling interval",
            }
        return {
            "duration_seconds": round(duration, 2),
            "cpu_percent_avg": round(sum(self._samples_cpu) / len(self._samples_cpu), 2),
            "cpu_percent_peak": round(max(self._samples_cpu), 2),
            "rss_mb_avg": round(sum(self._samples_rss_mb) / len(self._samples_rss_mb), 2),
            "rss_mb_peak": round(max(self._samples_rss_mb), 2),
            "sample_count": len(self._samples_cpu),
        }
