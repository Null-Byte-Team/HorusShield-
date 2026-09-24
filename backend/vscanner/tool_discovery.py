"""Cross-platform discovery and health checks for V-8 scanner tools."""
import os
import shutil
import subprocess
from typing import Any, Dict, Iterable, Optional


def _path_value(value: Optional[str]) -> str:
    return (value or "").strip().strip('"')


def resolve_path(explicit: Optional[str], names: Iterable[str], candidates: Iterable[str] = ()) -> Optional[str]:
    """Resolve an explicit path/name, then PATH, then known safe candidates."""
    value = _path_value(explicit)
    if value:
        direct = os.path.abspath(os.path.expandvars(os.path.expanduser(value)))
        if os.path.isfile(direct):
            return direct
        found = shutil.which(value)
        if found:
            return os.path.abspath(found)
        return None
    for name in names:
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    for candidate in candidates:
        candidate = os.path.expandvars(candidate)
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return None


def resolve_nmap(explicit: Optional[str]) -> Optional[str]:
    return resolve_path(explicit, ("nmap", "nmap.exe"), (
        r"%ProgramFiles%\Nmap\nmap.exe",
        r"%ProgramFiles(x86)%\Nmap\nmap.exe",
    ))


def resolve_perl(explicit: Optional[str]) -> Optional[str]:
    return resolve_path(explicit, ("perl", "perl.exe"), (
        r"%ProgramFiles%\Strawberry\perl\bin\perl.exe",
        r"%ProgramFiles(x86)%\Strawberry\perl\bin\perl.exe",
        r"C:\Strawberry\perl\bin\perl.exe",
        r"C:\Program Files\Strawberry\perl\bin\perl.exe",
        r"C:\Program Files (x86)\Strawberry\perl\bin\perl.exe",
    ))


def resolve_nikto(explicit: Optional[str]) -> Optional[str]:
    value = _path_value(explicit)
    if value and os.path.isdir(os.path.expanduser(value)):
        value = os.path.join(value, "nikto.pl")
    return resolve_path(value, ("nikto.pl", "nikto", "nikto.bat", "nikto.cmd"), (
        r"%ProgramFiles%\Nikto\program\nikto.pl",
        r"%ProgramFiles(x86)%\Nikto\program\nikto.pl",
        r"C:\Nikto\program\nikto.pl",
        r"C:\Program Files\Nikto\program\nikto.pl",
        r"C:\Program Files (x86)\Nikto\program\nikto.pl",
    ))


def resolve_zap(explicit: Optional[str]) -> Optional[str]:
    value = _path_value(explicit)
    if value and os.path.isdir(os.path.expanduser(value)):
        value = os.path.join(value, "zap.bat" if os.name == "nt" else "zap.sh")
    return resolve_path(value, ("zap.bat", "zap.sh", "zap.exe"), (
        r"%ProgramFiles%\OWASP\Zed Attack Proxy\zap.bat",
        r"%ProgramFiles(x86)%\OWASP\Zed Attack Proxy\zap.bat",
        r"%ProgramFiles%\OWASP\Zed Attack Proxy\zap.exe",
        r"%ProgramFiles(x86)%\OWASP\Zed Attack Proxy\zap.exe",
        r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
        r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
        r"C:\Program Files\OWASP\Zed Attack Proxy\zap.exe",
        r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.exe",
    ))


def _version(command: list[str], timeout: int = 8) -> tuple[str, Optional[str]]:
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout,
                                shell=False)
        output = (result.stdout or result.stderr or "").strip()
        if result.returncode != 0:
            return "", output[:300] or f"exited with code {result.returncode}"
        return output.splitlines()[0][:200] if output else "unknown", None
    except subprocess.TimeoutExpired:
        return "", "version check timed out"
    except OSError as exc:
        return "", str(exc)[:300]


def health(explicit_nmap: Optional[str], explicit_nikto: Optional[str],
           explicit_zap: Optional[str], explicit_perl: Optional[str]) -> Dict[str, Dict[str, Any]]:
    nmap = resolve_nmap(explicit_nmap)
    nikto = resolve_nikto(explicit_nikto)
    zap = resolve_zap(explicit_zap)

    result: Dict[str, Dict[str, Any]] = {}
    for name, path, command in (
        ("nmap", nmap, [nmap, "--version"] if nmap else []),
        ("zap", zap, [zap, "-version"] if zap else []),
        ("nikto", nikto, [nikto, "-Version"] if nikto else []),
    ):
        version, error = _version(command) if path else ("", "executable not found")
        result[name] = {"available": bool(path and not error), "version": version,
                        "path": path, "error": error or ""}
    return result
