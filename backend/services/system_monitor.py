"""
HorusShield 2.0 — System Monitor Service
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Real-time Windows system telemetry, resource utilization monitoring,
and safe, audited process management using psutil.

Architecture:
  Windows OS / psutil
         ↓
  Central System Monitor Sampler (CpuSampler singleton, 1-sec loop)
         ↓
  Cached Telemetry Snapshot & Bounded History (60 samples)
         ↓
  API Endpoints (/api/sysmon/overview, /api/sysmon/processes, etc.)
         ↓
  Frontend Dashboard (reads cached state; polling does not trigger CPU sampling)

Key Highlights:
  - SINGLE source of truth for system CPU utilization.
  - Overall CPU and per-core CPU percentages calculated simultaneously
    from the exact same timed 1-second delta over psutil.cpu_times(percpu=True).
  - Background sampler starts once, runs as a controlled daemon thread.
  - Initial 0.1s prime prevents displaying 0.0% or uninitialized states.
  - Historical rolling buffer (60s) sent to frontend for smooth graph rendering.
  - Process CPU percentages normalized by logical CPU count (0-100% total system)
    matching Windows Task Manager semantics. System Idle Process (PID 0) active CPU
    is clamped to 0.0% so idle time is not reported as active CPU load.
  - Zero fake or fabricated data.
"""

import os
import platform
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from database.db_manager import db
from utils.logger import get_logger

logger = get_logger("system_monitor", "services")

# ── Protected Windows process names / PIDs that must NEVER be terminated ──────
PROTECTED_PROCESS_NAMES = {
    "system idle process",
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe",
}
PROTECTED_PIDS = {0, 4}

# Stale-data threshold: if the last sample is older than this, flag it
_STALE_THRESHOLD_SEC = 5.0

# History buffer length (number of 1-second samples kept in memory)
_HISTORY_LEN = 60


# ═══════════════════════════════════════════════════════════════
#  CpuSnapshot — immutable snapshot of one CPU sampling cycle
# ═══════════════════════════════════════════════════════════════
class CpuSnapshot:
    """Thread-safe snapshot from one CPU sampling interval."""

    __slots__ = (
        "percent",
        "per_core",
        "frequency_mhz",
        "frequency_max_mhz",
        "logical_cores",
        "physical_cores",
        "sampled_at",
        "valid",
    )

    def __init__(
        self,
        percent: float,
        per_core: List[float],
        frequency_mhz: float,
        frequency_max_mhz: float,
        logical_cores: int,
        physical_cores: int,
    ):
        self.percent = round(percent, 1)
        self.per_core = [round(v, 1) for v in (per_core or [])]
        self.frequency_mhz = frequency_mhz
        self.frequency_max_mhz = frequency_max_mhz
        self.logical_cores = logical_cores
        self.physical_cores = physical_cores
        self.sampled_at = time.monotonic()
        self.valid = True

    @classmethod
    def unavailable(cls, logical_cores: int = 1, physical_cores: int = 1) -> "CpuSnapshot":
        snap = object.__new__(cls)
        snap.percent = 0.0
        snap.per_core = []
        snap.frequency_mhz = 0.0
        snap.frequency_max_mhz = 0.0
        snap.logical_cores = logical_cores
        snap.physical_cores = physical_cores
        snap.sampled_at = time.monotonic()
        snap.valid = False
        return snap

    def age_seconds(self) -> float:
        return time.monotonic() - self.sampled_at

    def is_stale(self) -> bool:
        return self.age_seconds() > _STALE_THRESHOLD_SEC


# ═══════════════════════════════════════════════════════════════
#  CpuSampler — single background thread, centralized sampler
# ═══════════════════════════════════════════════════════════════
class CpuSampler:
    """
    Background CPU & Memory telemetry sampler.

    Runs exactly ONE daemon thread per process. Samples CPU times once per second
    using direct delta calculations on psutil.cpu_times(percpu=True).

    This guarantees:
      1. Overall CPU and per-core CPU come from the EXACT same time interval.
      2. No reliance on psutil thread-local state or uncoordinated interval calls.
      3. Zero baseline reset when API requests are processed.
      4. Bounded 60-second telemetry history is available immediately.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._started = False

        self._logical_cores = psutil.cpu_count(logical=True) or 1
        self._physical_cores = psutil.cpu_count(logical=False) or self._logical_cores

        self._cpu_history: deque = deque(maxlen=_HISTORY_LEN)
        self._mem_history: deque = deque(maxlen=_HISTORY_LEN)
        self._snapshot: CpuSnapshot = CpuSnapshot.unavailable(
            self._logical_cores, self._physical_cores
        )

        # Quick 0.1s initial baseline prime so snapshot is immediately valid
        try:
            self._prime_initial_baseline()
        except Exception as e:
            logger.debug(f"Initial CPU prime warning: {e}")

    def _calculate_cpu_deltas(self, tot1, tot2):
        """Calculate per-core and overall CPU percentages from two cpu_times snapshots."""
        per_core = []
        tot_busy = 0.0
        tot_all = 0.0

        for t1, t2 in zip(tot1, tot2):
            user = t2.user - t1.user
            system = t2.system - t1.system
            idle = t2.idle - t1.idle
            interrupt = getattr(t2, "interrupt", 0) - getattr(t1, "interrupt", 0)
            dpc = getattr(t2, "dpc", 0) - getattr(t1, "dpc", 0)

            all_time = user + system + idle + interrupt + dpc
            busy_time = all_time - idle

            if all_time > 0:
                core_pct = min(100.0, max(0.0, (busy_time / all_time) * 100.0))
            else:
                core_pct = 0.0

            per_core.append(core_pct)
            tot_busy += busy_time
            tot_all += all_time

        overall_pct = (
            min(100.0, max(0.0, (tot_busy / tot_all) * 100.0))
            if tot_all > 0
            else 0.0
        )
        return overall_pct, per_core

    def _prime_initial_baseline(self) -> None:
        """Collect a fast 0.1s sample during startup to seed initial state."""
        t1 = psutil.cpu_times(percpu=True)
        time.sleep(0.1)
        t2 = psutil.cpu_times(percpu=True)
        overall, per_core = self._calculate_cpu_deltas(t1, t2)

        freq_mhz = freq_max_mhz = 0.0
        try:
            freq = psutil.cpu_freq()
            if freq:
                freq_mhz = round(freq.current, 1)
                freq_max_mhz = round(freq.max, 1)
        except Exception:
            pass

        snap = CpuSnapshot(
            percent=overall,
            per_core=per_core,
            frequency_mhz=freq_mhz,
            frequency_max_mhz=freq_max_mhz,
            logical_cores=self._logical_cores,
            physical_cores=self._physical_cores,
        )
        ts = datetime.now(timezone.utc).isoformat()
        self._snapshot = snap
        self._cpu_history.append({"timestamp": ts, "value": snap.percent})

        try:
            vmem = psutil.virtual_memory()
            self._mem_history.append({"timestamp": ts, "value": round(vmem.percent, 1)})
        except Exception:
            pass

    def start(self) -> None:
        """Start the background sampler thread (idempotent)."""
        with self._lock:
            if self._started and self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._sampler_loop,
                daemon=True,
                name="SystemMonitorSampler",
            )
            self._thread.start()
            self._started = True
            logger.info("SystemMonitorSampler background thread started.")

    def stop(self) -> None:
        """Stop background sampler thread cleanly."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.5)
        logger.info("SystemMonitorSampler stopped.")

    def get_snapshot(self) -> CpuSnapshot:
        """Return the latest cached CPU snapshot (never calls psutil)."""
        with self._lock:
            return self._snapshot

    def get_cpu_history(self) -> List[Dict[str, Any]]:
        """Return rolling history of CPU utilization."""
        with self._lock:
            return list(self._cpu_history)

    def get_mem_history(self) -> List[Dict[str, Any]]:
        """Return rolling history of RAM utilization."""
        with self._lock:
            return list(self._mem_history)

    def _sampler_loop(self) -> None:
        """Continuous 1-second sampling loop."""
        logger.info("SystemMonitorSampler loop active (1s interval).")

        # Initial baseline timestamp
        try:
            last_times = psutil.cpu_times(percpu=True)
        except Exception as e:
            logger.error(f"Failed to read initial cpu_times: {e}")
            last_times = None

        while not self._stop_event.is_set():
            # Wait for exactly 1.0 second (interruptible on shutdown)
            if self._stop_event.wait(1.0):
                break

            try:
                curr_times = psutil.cpu_times(percpu=True)
                if last_times is not None:
                    overall, per_core = self._calculate_cpu_deltas(last_times, curr_times)
                else:
                    overall, per_core = 0.0, [0.0] * self._logical_cores
                last_times = curr_times

                freq_mhz = freq_max_mhz = 0.0
                try:
                    freq = psutil.cpu_freq()
                    if freq and freq.current:
                        freq_mhz = round(freq.current, 1)
                        freq_max_mhz = round(freq.max, 1)
                except Exception:
                    pass

                snap = CpuSnapshot(
                    percent=overall,
                    per_core=per_core,
                    frequency_mhz=freq_mhz,
                    frequency_max_mhz=freq_max_mhz,
                    logical_cores=self._logical_cores,
                    physical_cores=self._physical_cores,
                )

                ts = datetime.now(timezone.utc).isoformat()
                cpu_entry = {"timestamp": ts, "value": snap.percent}

                mem_val = 0.0
                try:
                    vmem = psutil.virtual_memory()
                    mem_val = round(vmem.percent, 1)
                except Exception:
                    pass
                mem_entry = {"timestamp": ts, "value": mem_val}

                with self._lock:
                    self._snapshot = snap
                    self._cpu_history.append(cpu_entry)
                    self._mem_history.append(mem_entry)

            except Exception as exc:
                logger.warning(f"SystemMonitorSampler loop exception: {exc}")
                self._stop_event.wait(1.0)


# ── Global Singleton CpuSampler Instance ──────────────────────────────────────
_sampler_instance: Optional[CpuSampler] = None
_sampler_lock = threading.Lock()


def get_global_cpu_sampler() -> CpuSampler:
    """Return the application-wide singleton CpuSampler."""
    global _sampler_instance
    with _sampler_lock:
        if _sampler_instance is None:
            _sampler_instance = CpuSampler()
            _sampler_instance.start()
        return _sampler_instance


# ═══════════════════════════════════════════════════════════════
#  SystemMonitorService
# ═══════════════════════════════════════════════════════════════
class SystemMonitorService:
    """
    Service providing live Windows system metrics and process management.

    All CPU telemetry is read from the centralized CpuSampler singleton cache.
    API requests never perform direct CPU sampling.
    """

    def __init__(self):
        self._io_lock = threading.Lock()

        # I/O delta tracking
        self._last_disk_io = None
        self._last_disk_time: float = 0.0
        self._last_net_io = None
        self._last_net_time: float = 0.0

        # Boot time
        try:
            self._boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except Exception:
            self._boot_time = "Unknown"

        # Reference to centralized sampler singleton
        self.cpu_sampler = get_global_cpu_sampler()

    def get_system_overview(self) -> Dict[str, Any]:
        """
        Return real-time system metrics.

        Reads cached CPU snapshot and bounded history directly from the sampler.
        """
        now = time.time()

        # ── CPU ──
        cpu_snap = self.cpu_sampler.get_snapshot()
        cpu_history = self.cpu_sampler.get_cpu_history()

        freq_ghz = (
            round(cpu_snap.frequency_mhz / 1000.0, 2)
            if cpu_snap.frequency_mhz > 0
            else None
        )
        freq_max_ghz = (
            round(cpu_snap.frequency_max_mhz / 1000.0, 2)
            if cpu_snap.frequency_max_mhz > 0
            else None
        )

        cpu_section = {
            "usage_percent": cpu_snap.percent,
            "per_cpu": cpu_snap.per_core,
            "logical_cores": cpu_snap.logical_cores,
            "physical_cores": cpu_snap.physical_cores,
            "frequency_ghz": freq_ghz if freq_ghz is not None else 0.0,
            "frequency_current_ghz": freq_ghz,
            "frequency_max_ghz": freq_max_ghz if freq_max_ghz is not None else 0.0,
            "sample_age_ms": round(cpu_snap.age_seconds() * 1000),
            "stale": cpu_snap.is_stale(),
            "history": cpu_history,
            "initializing": not cpu_snap.valid,
        }

        # ── Memory ──
        vmem = psutil.virtual_memory()
        mem_total_gb = round(vmem.total / (1024 ** 3), 2)
        mem_used_gb = round(vmem.used / (1024 ** 3), 2)
        mem_avail_gb = round(vmem.available / (1024 ** 3), 2)
        mem_percent = round(vmem.percent, 1)
        mem_cached_gb = round(getattr(vmem, "cached", 0) / (1024 ** 3), 2)
        mem_history = self.cpu_sampler.get_mem_history()

        # ── Disk ──
        disk_partitions = []
        total_disk_bytes = used_disk_bytes = free_disk_bytes = 0
        try:
            for part in psutil.disk_partitions(all=False):
                if os.name == "nt" and ("cdrom" in part.opts or not part.fstype):
                    continue
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    total_disk_bytes += usage.total
                    used_disk_bytes += usage.used
                    free_disk_bytes += usage.free
                    disk_partitions.append(
                        {
                            "device": part.device,
                            "mountpoint": part.mountpoint,
                            "fstype": part.fstype,
                            "total_gb": round(usage.total / (1024 ** 3), 2),
                            "used_gb": round(usage.used / (1024 ** 3), 2),
                            "free_gb": round(usage.free / (1024 ** 3), 2),
                            "percent": round(usage.percent, 1),
                        }
                    )
                except (PermissionError, OSError):
                    continue
        except Exception as e:
            logger.debug(f"Disk partition enumeration warning: {e}")

        disk_total_gb = round(total_disk_bytes / (1024 ** 3), 2) if total_disk_bytes else 0.0
        disk_used_gb = round(used_disk_bytes / (1024 ** 3), 2) if used_disk_bytes else 0.0
        disk_free_gb = round(free_disk_bytes / (1024 ** 3), 2) if free_disk_bytes else 0.0
        disk_percent = (
            round((used_disk_bytes / total_disk_bytes) * 100, 1) if total_disk_bytes else 0.0
        )

        read_mb_s = write_mb_s = 0.0
        try:
            curr_disk_io = psutil.disk_io_counters()
            with self._io_lock:
                if curr_disk_io and self._last_disk_io and self._last_disk_time:
                    elapsed = now - self._last_disk_time
                    if elapsed > 0:
                        read_mb_s = round(
                            max(0, curr_disk_io.read_bytes - self._last_disk_io.read_bytes)
                            / (elapsed * (1024 ** 2)),
                            2,
                        )
                        write_mb_s = round(
                            max(0, curr_disk_io.write_bytes - self._last_disk_io.write_bytes)
                            / (elapsed * (1024 ** 2)),
                            2,
                        )
                self._last_disk_io = curr_disk_io
                self._last_disk_time = now
        except Exception:
            pass

        # ── Network ──
        download_mb_s = upload_mb_s = 0.0
        bytes_sent = bytes_recv = packets_sent = packets_recv = 0
        try:
            curr_net_io = psutil.net_io_counters()
            if curr_net_io:
                bytes_sent = curr_net_io.bytes_sent
                bytes_recv = curr_net_io.bytes_recv
                packets_sent = curr_net_io.packets_sent
                packets_recv = curr_net_io.packets_recv
                with self._io_lock:
                    if self._last_net_io and self._last_net_time:
                        elapsed = now - self._last_net_time
                        if elapsed > 0:
                            download_mb_s = round(
                                (max(0, curr_net_io.bytes_recv - self._last_net_io.bytes_recv) * 8)
                                / (elapsed * 1_000_000),
                                2,
                            )
                            upload_mb_s = round(
                                (max(0, curr_net_io.bytes_sent - self._last_net_io.bytes_sent) * 8)
                                / (elapsed * 1_000_000),
                                2,
                            )
                    self._last_net_io = curr_net_io
                    self._last_net_time = now
        except Exception:
            pass

        active_conns = 0
        try:
            active_conns = len(psutil.net_connections(kind="inet"))
        except Exception:
            pass

        # ── System info ──
        try:
            boot_ts = psutil.boot_time()
            uptime_sec = int(now - boot_ts)
        except Exception:
            uptime_sec = 0

        days, rem = divmod(uptime_sec, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        uptime_str = f"{days}d {hours}h {minutes}m" if days else f"{hours}h {minutes}m"
        os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"

        return {
            "cpu": cpu_section,
            "memory": {
                "total_gb": mem_total_gb,
                "used_gb": mem_used_gb,
                "available_gb": mem_avail_gb,
                "percent": mem_percent,
                "cached_gb": mem_cached_gb,
                "history": mem_history,
            },
            "disk": {
                "total_gb": disk_total_gb,
                "used_gb": disk_used_gb,
                "free_gb": disk_free_gb,
                "percent": disk_percent,
                "read_mb_s": read_mb_s,
                "write_mb_s": write_mb_s,
                "partitions": disk_partitions,
            },
            "network": {
                "download_mb_s": download_mb_s,
                "upload_mb_s": upload_mb_s,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "packets_sent": packets_sent,
                "packets_recv": packets_recv,
                "active_connections": active_conns,
            },
            "system": {
                "os": os_name,
                "hostname": platform.node(),
                "platform": platform.platform(),
                "processor": platform.processor(),
                "boot_time": self._boot_time,
                "uptime": uptime_str,
                "uptime_seconds": uptime_sec,
                "python_version": platform.python_version(),
                "server_pid": os.getpid(),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_processes(
        self,
        sort_by: str = "cpu",
        order: str = "desc",
        limit: int = 50,
        search: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Enumerate real running Windows processes with normalized CPU percentages.

        Process CPU percentages are normalized across all logical cores (0-100% total system),
        matching Windows Task Manager semantics. System Idle Process (PID 0) active CPU
        is treated as 0.0% so idle time is not sorted as active system load.
        """
        processes = []
        limit = min(max(limit, 1), 200)
        search_lower = (search or "").strip().lower()
        logical_cores = self.cpu_sampler._logical_cores or 1

        for proc in psutil.process_iter(
            attrs=[
                "pid",
                "name",
                "cpu_percent",
                "memory_percent",
                "memory_info",
                "status",
                "username",
                "exe",
                "create_time",
                "num_threads",
            ]
        ):
            try:
                info = proc.info
                pid = info.get("pid")
                if pid is None:
                    continue

                name = info.get("name") or "Unknown"

                if search_lower and (
                    search_lower not in name.lower() and str(pid) != search_lower
                ):
                    continue

                mem_info = info.get("memory_info")
                rss_mb = round(mem_info.rss / (1024 ** 2), 1) if mem_info else 0.0

                created = info.get("create_time")
                created_str = (
                    datetime.fromtimestamp(created).strftime("%H:%M:%S")
                    if created
                    else "--"
                )

                # Process CPU normalization:
                # Raw psutil cpu_percent is summed across cores (0 to 100 * N).
                # Normalize to 0-100% total system CPU like Task Manager.
                cpu_raw = info.get("cpu_percent") or 0.0
                if pid == 0 or name.lower() == "system idle process":
                    cpu_val = 0.0
                else:
                    cpu_val = round(min(100.0, max(0.0, cpu_raw / logical_cores)), 1)

                mem_pct = round(info.get("memory_percent") or 0.0, 1)
                is_protected = (pid in PROTECTED_PIDS) or (
                    name.lower() in PROTECTED_PROCESS_NAMES
                )

                processes.append(
                    {
                        "pid": pid,
                        "name": name,
                        "cpu_percent": cpu_val,
                        "memory_percent": mem_pct,
                        "memory_mb": rss_mb,
                        "status": info.get("status") or "running",
                        "username": info.get("username") or "SYSTEM",
                        "exe": info.get("exe") or "",
                        "create_time": created_str,
                        "num_threads": info.get("num_threads") or 1,
                        "is_protected": is_protected,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Process enumeration item skipped: {e}")
                continue

        reverse = order.lower() != "asc"
        if sort_by == "memory":
            processes.sort(key=lambda p: (p["memory_mb"], p["cpu_percent"]), reverse=reverse)
        elif sort_by == "name":
            processes.sort(key=lambda p: (p["name"].lower(), p["cpu_percent"]), reverse=reverse)
        elif sort_by == "pid":
            processes.sort(key=lambda p: p["pid"], reverse=reverse)
        else:
            processes.sort(key=lambda p: (p["cpu_percent"], p["memory_mb"]), reverse=reverse)

        return processes[:limit]

    def get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        """Return deep process metadata (sanitized)."""
        logical_cores = self.cpu_sampler._logical_cores or 1
        try:
            proc = psutil.Process(pid)
            info = proc.as_dict(
                attrs=[
                    "pid",
                    "name",
                    "status",
                    "username",
                    "create_time",
                    "num_threads",
                    "exe",
                    "cwd",
                ]
            )

            mem_info = proc.memory_info()
            rss_mb = round(mem_info.rss / (1024 ** 2), 2)
            vms_mb = round(mem_info.vms / (1024 ** 2), 2)
            mem_pct = round(proc.memory_percent(), 2)

            # Single process CPU sample with 0.1s interval for details modal
            try:
                cpu_raw = proc.cpu_percent(interval=0.1)
                if pid == 0 or (info.get("name") or "").lower() == "system idle process":
                    cpu_pct = 0.0
                else:
                    cpu_pct = round(min(100.0, max(0.0, cpu_raw / logical_cores)), 1)
            except Exception:
                cpu_pct = 0.0

            cmdline = []
            try:
                raw_cmd = proc.cmdline()
                for arg in raw_cmd:
                    if any(k in arg.lower() for k in ["password", "token", "secret", "key="]):
                        cmdline.append("[REDACTED]")
                    else:
                        cmdline.append(arg)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = [info.get("exe") or info.get("name") or "Access Denied"]

            connections = []
            try:
                for c in proc.net_connections(kind="inet"):
                    connections.append(
                        {
                            "type": "TCP" if c.type == 1 else "UDP",
                            "local_address": c.laddr.ip if c.laddr else "*",
                            "local_port": c.laddr.port if c.laddr else 0,
                            "remote_address": c.raddr.ip if c.raddr else "*",
                            "remote_port": c.raddr.port if c.raddr else 0,
                            "status": c.status or "ESTABLISHED",
                        }
                    )
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass

            created_ts = info.get("create_time")
            created_str = (
                datetime.fromtimestamp(created_ts).strftime("%Y-%m-%d %H:%M:%S")
                if created_ts
                else "Unknown"
            )

            is_protected = (pid in PROTECTED_PIDS) or (
                (info.get("name") or "").lower() in PROTECTED_PROCESS_NAMES
            )

            return {
                "pid": pid,
                "name": info.get("name") or "Unknown",
                "status": info.get("status") or "running",
                "username": info.get("username") or "SYSTEM",
                "exe": info.get("exe") or "Unavailable",
                "exe_path": info.get("exe") or "Unavailable",
                "cwd": info.get("cwd") or "Unavailable",
                "cmdline": " ".join(cmdline),
                "create_time": created_str,
                "num_threads": info.get("num_threads") or 1,
                "cpu_percent": cpu_pct,
                "memory_percent": mem_pct,
                "memory_rss_mb": rss_mb,
                "memory_vms_mb": vms_mb,
                "is_protected": is_protected,
                "connections": connections,
            }
        except psutil.NoSuchProcess:
            return None
        except psutil.AccessDenied:
            return {
                "pid": pid,
                "name": f"PID {pid}",
                "status": "access_denied",
                "username": "SYSTEM / Protected",
                "exe": "Access Denied (Elevated Privileges Required)",
                "exe_path": "Access Denied",
                "cwd": "Access Denied",
                "cmdline": "Access Denied",
                "create_time": "Unknown",
                "num_threads": 1,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "memory_rss_mb": 0.0,
                "memory_vms_mb": 0.0,
                "is_protected": True,
                "connections": [],
            }
        except Exception as e:
            logger.error(f"Error getting details for PID {pid}: {e}")
            return None

    def terminate_process(
        self, pid: int, username: str = "admin", client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """Safely terminate a process with validation and audit logging."""
        if pid in PROTECTED_PIDS:
            db.add_audit_log(
                action="kill_process_rejected",
                username=username,
                status="blocked",
                ip_address=client_ip,
                details=f"Attempted to terminate critical system PID: {pid}",
            )
            return {
                "success": False,
                "error": "Cannot terminate critical system process (PID 0/4)",
                "status": 403,
            }

        if pid == os.getpid():
            return {
                "success": False,
                "error": "Cannot terminate the HorusShield server process itself",
                "status": 400,
            }

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()

            if proc_name.lower() in PROTECTED_PROCESS_NAMES:
                db.add_audit_log(
                    action="kill_process_rejected",
                    username=username,
                    status="blocked",
                    ip_address=client_ip,
                    details=f"Attempted to terminate protected process: {proc_name} (PID: {pid})",
                )
                return {
                    "success": False,
                    "error": f"Cannot terminate protected Windows process: {proc_name}",
                    "status": 403,
                }

            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)

            db.add_audit_log(
                action="kill_process",
                username=username,
                status="success",
                ip_address=client_ip,
                details=f"Terminated process {proc_name} (PID: {pid})",
            )
            logger.info(
                f"Process {proc_name} (PID: {pid}) terminated by {username} ({client_ip})"
            )
            return {
                "success": True,
                "message": f"Process {proc_name} (PID {pid}) terminated successfully",
            }

        except psutil.NoSuchProcess:
            return {"success": True, "message": f"Process {pid} has already exited"}
        except psutil.AccessDenied:
            db.add_audit_log(
                action="kill_process_failed",
                username=username,
                status="access_denied",
                ip_address=client_ip,
                details=f"Access denied terminating PID: {pid}",
            )
            return {
                "success": False,
                "error": f"Access Denied: Insufficient permissions to terminate PID {pid}",
                "status": 403,
            }
        except Exception as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
            return {
                "success": False,
                "error": f"Failed to terminate process: {str(e)}",
                "status": 500,
            }


# ── Module singleton export ───────────────────────────────────────────────────
system_monitor_service = SystemMonitorService()
