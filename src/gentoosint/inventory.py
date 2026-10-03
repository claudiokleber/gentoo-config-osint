"""Read-only collection. Never executes shell configuration or external commands."""
import os
import platform
import re
import shutil
import stat
from pathlib import Path

from .catalog import TOOLS


def read_text(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, encoding="utf-8", errors="replace") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            return stream.read(262144)
    except (OSError, ValueError):
        return None


def parse_os_release(text):
    result = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {"ID", "VERSION_ID"}:
            result[key] = value.strip().strip('"').strip("'")
    return result


def memory_kib(text, name):
    match = re.search(r"^" + re.escape(name) + r":\s+(\d+)\s+kB\s*$", text or "", re.M)
    return int(match.group(1)) if match and len(match.group(1)) <= 16 else None


def windows_memory():
    try:
        import ctypes
        from ctypes import wintypes
        class MemoryStatus(ctypes.Structure):
            _fields_ = [('length', wintypes.DWORD), ('load', wintypes.DWORD)] + [
                (name, ctypes.c_ulonglong) for name in
                ('total', 'available', 'page_total', 'page_available', 'virtual_total', 'virtual_available', 'extended')]
        state = MemoryStatus()
        state.length = ctypes.sizeof(state)
        function = ctypes.WinDLL('kernel32', use_last_error=True).GlobalMemoryStatusEx
        function.argtypes = [ctypes.POINTER(MemoryStatus)]
        function.restype = wintypes.BOOL
        if function(ctypes.byref(state)):
            return state.total // 1024, state.available // 1024
    except (AttributeError, OSError):
        pass
    return None, None


def collect(root=None, system=None, machine=None, which=None):
    root = Path(root) if root is not None else Path(Path.cwd().anchor)
    system = system or platform.system()
    which = which or shutil.which
    release = parse_os_release(read_text(root / "etc/os-release")) if system == "Linux" else {}
    is_gentoo = system == "Linux" and release.get("ID") == "gentoo"
    mem = read_text(root / "proc/meminfo") if system == "Linux" else None
    total, available = (windows_memory() if system == 'Windows' else
                        (memory_kib(mem, 'MemTotal'), memory_kib(mem, 'MemAvailable')))
    pid1 = read_text(root / "proc/1/comm") if system == "Linux" else None
    init = "unknown"
    if pid1 and pid1.strip() == "systemd":
        init = "systemd"
    elif (root / "run/openrc/softlevel").is_file():
        init = "openrc"
    profile = None
    profile_path = root / "etc/portage/make.profile"
    try:
        if profile_path.is_symlink():
            target = os.readlink(profile_path).replace("\\", "/")
            if "/profiles/" in target:
                profile = target.split("/profiles/", 1)[1]
    except OSError:
        pass
    try:
        disk = shutil.disk_usage(root)
        disk_data = {"total_gib": round(disk.total / 2**30, 2),
                     "free_gib": round(disk.free / 2**30, 2)}
    except OSError:
        disk_data = None
    return {
        "system": system, "architecture": machine or platform.machine(),
        "python": platform.python_version(), "distribution": release.get("ID"),
        "distribution_version": release.get("VERSION_ID"), "is_gentoo": is_gentoo,
        "cpu_logical": os.cpu_count(), "memory_total_kib": total,
        "memory_available_kib": available,
        "swap_total_kib": memory_kib(mem, "SwapTotal"), "disk_root": disk_data,
        "init": init, "profile": profile, "emerge_available": bool(which("emerge")),
        "executables": {t["id"]: bool(which(t["binary"])) for t in TOOLS},
    }
