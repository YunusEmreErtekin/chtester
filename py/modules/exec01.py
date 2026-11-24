"""Module 01 — Kod Calistirma Yetenegi (Execution)."""
from __future__ import annotations
import os
from pathlib import Path

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi


CAT = "01-Execution"

LOLBINS = [
    ("CHT-01-011", "rundll32 proxy execution", "rundll32.exe", "T1218.011"),
    ("CHT-01-012", "regsvr32 (scrobj)", "regsvr32.exe", "T1218.010"),
    ("CHT-01-013", "mshta (hta/inline)", "mshta.exe", "T1218.005"),
    ("CHT-01-014", "msbuild inline task", "msbuild.exe", "T1127.001"),
    ("CHT-01-016", "msiexec paket/uzak", "msiexec.exe", "T1218.007"),
    ("CHT-01-017", "certutil decode/download", "certutil.exe", "T1140"),
    ("CHT-01-018", "bitsadmin download+exec", "bitsadmin.exe", "T1197"),
    ("CHT-01-019", "wmic XSL/process call", "wbem\\wmic.exe", "T1047"),
    ("CHT-01-020", "cmstp INF execution", "cmstp.exe", "T1218.003"),
    ("CHT-01-025", "hh/control/verclsid/odbcconf", "hh.exe", "T1218"),
    ("CHT-01-026", "schtasks/winrs", "schtasks.exe", "T1218"),
]

WRITABLE_CANDIDATES = [
    "%TEMP%", "%LOCALAPPDATA%", "%APPDATA%",
    "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Downloads",
    "%PUBLIC%", "%ProgramData%",
    "%SystemRoot%\\Tasks", "%SystemRoot%\\Temp", "%SystemRoot%\\tracing",
    "%SystemRoot%\\System32\\spool\\drivers\\color",
    "C:\\PerfLogs",
]


class Module01:
    def id(self) -> str: return "01"
    def name(self) -> str: return "Kod Calistirma Yetenegi"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)
        sr = winapi.system_root()
        ps_path = os.path.join(sr, r"System32\WindowsPowerShell\v1.0\powershell.exe")

        # 01.1 PowerShell
        def test_ps(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.attempted_methods = ["os.path.isfile powershell.exe", "launch -Command"]
            if not winapi.file_exists(ps_path):
                r.result = schema.RESULT_NOT_APPLICABLE
                r.evidence = "powershell.exe diskte yok"
                return
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"powershell.exe mevcut: {ps_path}"
            if ctx.active_allowed():
                res = winapi.run_cmd(8, ps_path, "-NoProfile", "-NonInteractive", "-Command", "Write-Output OK")
                _classify_exec(r, res, "powershell -Command")
            else:
                r.evidence += " (pasif: aktif launch yapilmadi)"
        b.add("CHT-01-001", "powershell.exe / pwsh / ISE acma", test_ps)

        # 01.2 PS bypass flags
        def test_ps_bypass(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.attempted_methods = ["-ExecutionPolicy Bypass", "-EncodedCommand"]
            if not ctx.gate_active(r, 2, False):
                return
            if not winapi.file_exists(ps_path):
                r.result = schema.RESULT_NOT_APPLICABLE
                r.evidence = "powershell.exe yok"
                return
            res = winapi.run_cmd(8, ps_path, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Write-Output BYPASS_OK")
            enc = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABFAE4AQwBfAE8ASwA="
            res2 = winapi.run_cmd(8, ps_path, "-NoProfile", "-EncodedCommand", enc)
            ok1 = "BYPASS_OK" in res.output
            ok2 = "ENC_OK" in res2.output
            if ok1 and ok2:
                r.result = schema.RESULT_ALLOWED
                r.evidence = "ExecutionPolicy Bypass VE EncodedCommand calisti — kisitlama yok"
                r.recommendation = "Constrained Language Mode + WDAC dusunulmeli."
            elif ok1 or ok2:
                r.result = schema.RESULT_PARTIAL
                r.evidence = f"bypass={ok1} encoded={ok2}"
            else:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = schema.BLOCK_UNKNOWN
                r.evidence = "Her iki bayrak da sonuc uretmedi"
        b.add("CHT-01-002", "PS bayraklari: Bypass / EncodedCommand", test_ps_bypass)

        # 01.4 PS v2 downgrade
        def test_ps_v2(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.attempted_methods = ["registry PS2 engine"]
            has_v2 = winapi.reg_key_exists(winapi._HKLM, r"SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine")
            if not has_v2:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "PS v2 engine mevcut degil (iyi)"
                return
            r.result = schema.RESULT_PARTIAL
            r.evidence = "PS v2 engine mevcut — AMSI/logging atlatma yuzeyi"
            r.recommendation = "PowerShell v2 engine kaldirilmali."
            if ctx.active_allowed() and winapi.file_exists(ps_path):
                res = winapi.run_cmd(8, ps_path, "-NoProfile", "-Version", "2", "-Command", "Write-Output V2_OK")
                if "V2_OK" in res.output:
                    r.result = schema.RESULT_ALLOWED
                    r.evidence = "PS v2 ile gercekten calisti"
        b.add("CHT-01-004", "PS v2 downgrade yuzeyi (-Version 2)", test_ps_v2)

        # 01.7 cmd.exe
        def test_cmd(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            cmd_path = os.path.join(sr, "System32", "cmd.exe")
            r.attempted_methods = ["os.path.isfile", "launch"]
            if not winapi.file_exists(cmd_path):
                r.result = schema.RESULT_NOT_APPLICABLE
                r.evidence = "cmd.exe diskte yok"
                return
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"mevcut: {cmd_path}"
            if ctx.active_allowed():
                res = winapi.run_cmd(8, cmd_path, "/c", "echo CMD_OK")
                _classify_exec(r, res, "cmd.exe")
        b.add("CHT-01-007", "cmd.exe erisimi", test_cmd)

        # 01.10 WSL/bash
        def test_wsl(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.attempted_methods = ["os.path.isfile wsl.exe/bash.exe"]
            found = []
            for n in ("wsl.exe", "bash.exe"):
                p = os.path.join(sr, "System32", n)
                if winapi.file_exists(p):
                    found.append(n)
            if not found:
                r.result = schema.RESULT_NOT_APPLICABLE
                r.evidence = "wsl/bash diskte yok"
                return
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"mevcut: {', '.join(found)}"
            r.recommendation = "WSL kurumsal cihazda gerekmiyorsa devre disi birakilmali."
        b.add("CHT-01-010", "wsl.exe / bash.exe ile kacis", test_wsl)

        # LOLBAS binary varligi
        for lid, lname, lbin, lattack in LOLBINS:
            def test_lolbin(r: schema.Result, _bin=lbin, _att=lattack):
                r.risk_when_open = schema.RISK_MEDIUM
                r.mapping.attack = _att
                r.attempted_methods = ["os.path.isfile System32/SysWOW64"]
                paths = winapi.bin_paths(_bin)
                if not paths:
                    r.result = schema.RESULT_NOT_APPLICABLE
                    r.evidence = f"{_bin} bulunamadi"
                    return
                r.result = schema.RESULT_PARTIAL
                r.evidence = f"mevcut (proxy-exec yuzeyi): {'; '.join(paths)}"
                r.recommendation = "AppLocker/WDAC ile bu LOLBin kisitlanmali."
            b.add(lid, f"LOLBAS: {lname}", test_lolbin)

        # 01.27 Canary .cmd
        def test_canary_cmd(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1059.003"
            r.attempted_methods = ["Temp'e .cmd yaz", "cmd /c calistir"]
            if not ctx.gate_active(r, 2, False):
                return
            canary = os.path.join(winapi.expand_env("%TEMP%"), "cht-canary.cmd")
            try:
                with open(canary, "w") as f:
                    f.write("@echo off\r\necho CANARY_OK\r\n")
                res = winapi.run_cmd(8, os.path.join(sr, "System32", "cmd.exe"), "/c", canary)
                if "CANARY_OK" in res.output:
                    r.result = schema.RESULT_ALLOWED
                    r.evidence = "Temp'ten .cmd kanarya calisti — script-exec kisitlamasi yok"
                    r.recommendation = "AppLocker Script kurali Temp'ten calistirmayi engellemeli."
                elif res.timed_out:
                    r.result = schema.RESULT_ERROR
                    r.skip_reason = schema.SKIP_TIMEOUT
                    r.evidence = "kanarya timeout"
                else:
                    r.result = schema.RESULT_BLOCKED
                    r.blocking_mechanism = schema.BLOCK_UNKNOWN
                    r.evidence = f"kanarya engellendi (exit={res.exit_code}): {res.output[:120]}"
            finally:
                try:
                    os.remove(canary)
                except OSError:
                    pass
        b.add("CHT-01-027", "Kanarya .cmd calistirma (Temp'ten)", test_canary_cmd)

        # 01.31 Writable+executable dir hunt
        def test_writable_dirs(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1059"
            r.attempted_methods = ["yazma probe (AppLocker default-rule boslukları)"]
            writable = []
            seen = set()
            for c in WRITABLE_CANDIDATES:
                p = winapi.expand_env(c)
                if not p or p in seen:
                    continue
                seen.add(p)
                if winapi.try_write_probe(p):
                    writable.append(p)
            if not writable:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Bilinen AppLocker-bypass dizinlerine yazilamiyor"
                return
            r.result = schema.RESULT_ALLOWED
            r.evidence = f"{len(writable)} yazilabilir konum: {'; '.join(writable)}"
            r.recommendation = "Bu dizinlerden calistirma AppLocker/WDAC ile engellenmeli."
        b.add("CHT-01-031", "Yazilabilir + calistirilabilir dizin avi", test_writable_dirs)

        return b.results()


def _classify_exec(r: schema.Result, res: winapi.RunResult, method: str):
    if res.timed_out:
        r.result = schema.RESULT_ERROR
        r.skip_reason = schema.SKIP_TIMEOUT
        r.evidence = f"{method}: timeout"
    elif res.error is None or res.exit_code == 0:
        r.result = schema.RESULT_ALLOWED
        r.evidence = f"{method} calisti (exit={res.exit_code}): {res.output[:120]}"
    else:
        r.result = schema.RESULT_BLOCKED
        r.blocking_mechanism = schema.BLOCK_UNKNOWN
        r.evidence = f"{method} engellendi (exit={res.exit_code}): {res.output[:160]}"
