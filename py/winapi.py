"""Windows API helpers — registry, process, service, privilege queries.

Uses only stdlib (winreg, ctypes, subprocess). No third-party deps.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes as wt
import os
import platform
import socket
import subprocess
import tempfile
import time
import winreg
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
_HKLM = winreg.HKEY_LOCAL_MACHINE
_HKCU = winreg.HKEY_CURRENT_USER

def reg_dword(root: int, path: str, name: str) -> tuple[int, bool]:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            val, typ = winreg.QueryValueEx(k, name)
            if typ in (winreg.REG_DWORD, winreg.REG_QWORD):
                return int(val), True
    except OSError:
        pass
    return 0, False


def reg_string(root: int, path: str, name: str) -> tuple[str, bool]:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            val, typ = winreg.QueryValueEx(k, name)
            if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                return str(val), True
    except OSError:
        pass
    return "", False


def reg_key_exists(root: int, path: str) -> bool:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        return False


def reg_subkeys(root: int, path: str) -> list[str]:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            keys = []
            i = 0
            while True:
                try:
                    keys.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
            return keys
    except OSError:
        return []


def reg_value_names(root: int, path: str) -> list[str]:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            names = []
            i = 0
            while True:
                try:
                    name, _, _ = winreg.EnumValue(k, i)
                    names.append(name)
                    i += 1
                except OSError:
                    break
            return names
    except OSError:
        return []


def reg_string_values(root: int, path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            i = 0
            while True:
                try:
                    name, val, typ = winreg.EnumValue(k, i)
                    if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                        out[name] = str(val)
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return out


def can_reg_write(root: int, path: str) -> bool:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    exit_code: int = 0
    output: str = ""
    timed_out: bool = False
    error: Optional[str] = None


def run_cmd(timeout: float, path: str, *args: str) -> RunResult:
    try:
        proc = subprocess.run(
            [path, *args],
            capture_output=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
        return RunResult(
            exit_code=proc.returncode,
            output=(stdout + stderr).strip(),
        )
    except subprocess.TimeoutExpired:
        return RunResult(exit_code=-1, timed_out=True, error="timeout")
    except Exception as e:
        return RunResult(exit_code=-1, error=str(e))


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------
_PROCESS_QUERY_LIMITED = 0x1000
_PROCESS_VM_READ = 0x0010

_kernel32 = ctypes.windll.kernel32
_advapi32 = ctypes.windll.advapi32
_ntdll = ctypes.windll.ntdll


def _snap_processes() -> dict[str, int]:
    """Return {lower_name: pid} via CreateToolhelp32Snapshot."""
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return {}
    result: dict[str, int] = {}
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    if _kernel32.Process32First(snap, ctypes.byref(pe)):
        while True:
            name = pe.szExeFile.decode("utf-8", errors="replace").lower()
            result[name] = pe.th32ProcessID
            if not _kernel32.Process32Next(snap, ctypes.byref(pe)):
                break
    _kernel32.CloseHandle(snap)
    return result


def find_process_id(name: str) -> tuple[int, bool]:
    procs = _snap_processes()
    pid = procs.get(name.lower(), 0)
    return pid, pid != 0


def can_open_process_vm_read(pid: int) -> tuple[bool, str]:
    h = _kernel32.OpenProcess(_PROCESS_VM_READ, False, pid)
    if h:
        _kernel32.CloseHandle(h)
        return True, ""
    return False, f"OpenProcess failed: {ctypes.get_last_error()}"


# ---------------------------------------------------------------------------
# Privilege / Token helpers
# ---------------------------------------------------------------------------
def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def integrity_level() -> str:
    TOKEN_QUERY = 0x0008
    TokenIntegrityLevel = 25

    h_process = _kernel32.GetCurrentProcess()
    h_token = wt.HANDLE()
    if not _advapi32.OpenProcessToken(h_process, TOKEN_QUERY, ctypes.byref(h_token)):
        return "Unknown"
    try:
        buf_size = wt.DWORD()
        _advapi32.GetTokenInformation(h_token, TokenIntegrityLevel, None, 0, ctypes.byref(buf_size))
        buf = ctypes.create_string_buffer(buf_size.value)
        if not _advapi32.GetTokenInformation(h_token, TokenIntegrityLevel, buf, buf_size, ctypes.byref(buf_size)):
            return "Unknown"
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents.value
        if sid_ptr:
            sub_count_ptr = ctypes.cast(sid_ptr + 1, ctypes.POINTER(ctypes.c_ubyte))
            count = sub_count_ptr.contents.value
            if count > 0:
                rid_ptr = ctypes.cast(sid_ptr + 8 + (count - 1) * 4, ctypes.POINTER(wt.DWORD))
                rid = rid_ptr.contents.value
                if rid >= 0x4000:
                    return "High"
                elif rid >= 0x2000:
                    return "Medium"
                elif rid >= 0x1000:
                    return "Low"
                return "Untrusted"
    except Exception:
        pass
    finally:
        _kernel32.CloseHandle(h_token)
    return "Unknown"


def get_privileges() -> list[str]:
    """Return list of privilege names for the current token."""
    TOKEN_QUERY = 0x0008
    TokenPrivileges = 3

    h_process = _kernel32.GetCurrentProcess()
    h_token = wt.HANDLE()
    if not _advapi32.OpenProcessToken(h_process, TOKEN_QUERY, ctypes.byref(h_token)):
        return []
    try:
        buf_size = wt.DWORD()
        _advapi32.GetTokenInformation(h_token, TokenPrivileges, None, 0, ctypes.byref(buf_size))
        buf = ctypes.create_string_buffer(buf_size.value)
        if not _advapi32.GetTokenInformation(h_token, TokenPrivileges, buf, buf_size, ctypes.byref(buf_size)):
            return []
        count = ctypes.cast(buf, ctypes.POINTER(wt.DWORD)).contents.value
        offset = 4
        privs = []
        for _ in range(count):
            luid_low = int.from_bytes(buf[offset:offset + 4], "little")
            luid_high = int.from_bytes(buf[offset + 4:offset + 8], "little")
            offset += 12  # LUID(8) + Attributes(4)

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]

            luid = LUID(luid_low, luid_high)
            name_buf = ctypes.create_unicode_buffer(256)
            name_size = wt.DWORD(256)
            if _advapi32.LookupPrivilegeNameW(None, ctypes.byref(luid), name_buf, ctypes.byref(name_size)):
                privs.append(name_buf.value)
        return privs
    except Exception:
        return []
    finally:
        _kernel32.CloseHandle(h_token)


# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------
def service_installed(name: str) -> bool:
    return reg_key_exists(_HKLM, rf"SYSTEM\CurrentControlSet\Services\{name}")


# ---------------------------------------------------------------------------
# User & group helpers (net user / net localgroup via subprocess)
# ---------------------------------------------------------------------------
def list_local_users() -> list[str]:
    res = run_cmd(10, "net", "user")
    if res.exit_code != 0:
        return []
    users = []
    capture = False
    for line in res.output.splitlines():
        if "---" in line:
            capture = True
            continue
        if capture:
            if line.strip().startswith("Komut") or line.strip().startswith("The command"):
                break
            users.extend(line.split())
    return users


def list_local_groups() -> list[str]:
    res = run_cmd(10, "net", "localgroup")
    if res.exit_code != 0:
        return []
    groups = []
    capture = False
    for line in res.output.splitlines():
        if "---" in line:
            capture = True
            continue
        if capture:
            if line.strip().startswith("Komut") or line.strip().startswith("The command"):
                break
            g = line.strip().lstrip("*")
            if g:
                groups.append(g)
    return groups


def group_members(group: str) -> list[str]:
    res = run_cmd(10, "net", "localgroup", group)
    if res.exit_code != 0:
        return []
    members = []
    capture = False
    for line in res.output.splitlines():
        if "---" in line:
            capture = True
            continue
        if capture:
            if line.strip().startswith("Komut") or line.strip().startswith("The command"):
                break
            m = line.strip()
            if m:
                members.append(m)
    return members


def try_create_user(username: str, password: str) -> RunResult:
    return run_cmd(15, "net", "user", username, password, "/add")


def try_delete_user(username: str) -> RunResult:
    return run_cmd(15, "net", "user", username, "/delete")


def try_add_to_group(username: str, group: str) -> RunResult:
    return run_cmd(15, "net", "localgroup", group, username, "/add")


def try_remove_from_group(username: str, group: str) -> RunResult:
    return run_cmd(15, "net", "localgroup", group, username, "/delete")


# ---------------------------------------------------------------------------
# Hash dump helpers (SAM hive readability, shadow copy check)
# ---------------------------------------------------------------------------
def sam_hive_readable() -> list[str]:
    sr = os.environ.get("SystemRoot", r"C:\Windows")
    readable = []
    for h in ("SAM", "SYSTEM", "SECURITY"):
        p = os.path.join(sr, "System32", "config", h)
        try:
            with open(p, "rb") as f:
                f.read(1)
            readable.append(h)
        except OSError:
            pass
    return readable


def shadow_copies_exist() -> bool:
    res = run_cmd(15, "vssadmin", "list", "shadows")
    return "Shadow Copy" in res.output or "Golge Kopya" in res.output


# ---------------------------------------------------------------------------
# Environment discovery
# ---------------------------------------------------------------------------
@dataclass
class EnvInfo:
    hostname: str = ""
    device_id: str = ""
    os_build: str = ""
    arch: str = ""
    tier: int = 2
    tier_reason: str = ""
    domain_join: str = ""
    intune_managed: bool = False
    edr_detected: str = ""


def discover() -> EnvInfo:
    info = EnvInfo()
    info.hostname = socket.gethostname()
    info.device_id = info.hostname
    info.arch = platform.machine()
    ver = platform.version()
    info.os_build = f"{platform.release()}.{ver}"

    domain, ok = reg_string(_HKLM, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain")
    if ok and domain:
        info.domain_join = domain
        info.tier = 3
        info.tier_reason = "domain-joined"
    else:
        info.tier = 2
        info.tier_reason = "workgroup"

    intune = reg_key_exists(_HKLM, r"SOFTWARE\Microsoft\Enrollments")
    info.intune_managed = intune

    edr_list = []
    for svc in ("MsSense", "CrowdStrike", "SentinelAgent", "CylanceSvc", "cb", "TaniumClient"):
        if service_installed(svc):
            edr_list.append(svc)
    info.edr_detected = ", ".join(edr_list) if edr_list else "none"

    return info


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------
def system_root() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows")


def file_exists(p: str) -> bool:
    return os.path.isfile(p)


def bin_paths(name: str) -> list[str]:
    sr = system_root()
    found = []
    for d in ("System32", "SysWOW64"):
        p = os.path.join(sr, d, name)
        if file_exists(p):
            found.append(p)
    return found


def try_write_probe(dir_path: str) -> bool:
    try:
        os.makedirs(dir_path, exist_ok=True)
        p = os.path.join(dir_path, ".cht-probe")
        with open(p, "w") as f:
            f.write("x")
        os.remove(p)
        return True
    except OSError:
        return False


def expand_env(p: str) -> str:
    return os.path.expandvars(p)
