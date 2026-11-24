"""Module 20 — Uzak Erisim (Remote Access)."""
from __future__ import annotations
import os

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "20-RemoteAccess"


class Module20:
    def id(self) -> str: return "20"
    def name(self) -> str: return "Uzak Erisim"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 20.1 WinRM
        def test_winrm(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1021.006"
            r.attempted_methods = ["service WinRM", "registry WinRM"]
            svc = winapi.service_installed("WinRM")
            start, _ = winapi.reg_dword(winapi._HKLM,
                r"SYSTEM\CurrentControlSet\Services\WinRM", "Start")
            allow_auto, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowAutoConfig")
            reg_text = winapi.reg_export_text(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service")
            ctx.save_poc(r, "winrm_registry.txt", reg_text, "WinRM service policy", "registry")
            r.evidence = f"WinRM service={svc}; Start={start}; AllowAutoConfig={allow_auto}"
            if svc and start == 2:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "WinRM auto-start — gerekmiyorsa devre disi birakilmali."
            elif svc:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — yuklu ama auto-start degil"
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — WinRM yuklu degil"
        b.add("CHT-20-001", "WinRM servisi ve yapilandirmasi", test_winrm)

        # 20.2 SSH Server
        def test_ssh(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1021.004"
            r.attempted_methods = ["service sshd", "OpenSSH varlik"]
            sshd = winapi.service_installed("sshd")
            ssh_path = os.path.join(winapi.system_root(), "System32", "OpenSSH", "sshd.exe")
            has_binary = winapi.file_exists(ssh_path)
            start, _ = winapi.reg_dword(winapi._HKLM,
                r"SYSTEM\CurrentControlSet\Services\sshd", "Start")
            r.evidence = f"sshd service={sshd}; binary={has_binary}; Start={start}"
            if sshd and start == 2:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "OpenSSH Server auto-start — gerekmiyorsa devre disi birakilmali."
            elif sshd:
                r.result = schema.RESULT_PARTIAL
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — SSH server yuklu degil"
        b.add("CHT-20-002", "OpenSSH Server", test_ssh)

        # 20.3 RDP ayarlari
        def test_rdp(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1021.001"
            r.attempted_methods = ["registry Terminal Server"]
            ts_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            deny, _ = winapi.reg_dword(winapi._HKLM, ts_path, "fDenyTSConnections")
            nla, _ = winapi.reg_dword(winapi._HKLM,
                ts_path + r"\WinStations\RDP-Tcp", "UserAuthentication")
            sec_layer, _ = winapi.reg_dword(winapi._HKLM,
                ts_path + r"\WinStations\RDP-Tcp", "SecurityLayer")
            min_enc, _ = winapi.reg_dword(winapi._HKLM,
                ts_path + r"\WinStations\RDP-Tcp", "MinEncryptionLevel")
            reg_text = winapi.reg_export_text(winapi._HKLM, ts_path)
            reg_text += "\n" + winapi.reg_export_text(winapi._HKLM, ts_path + r"\WinStations\RDP-Tcp")
            ctx.save_poc(r, "rdp_registry.txt", reg_text, "RDP yapilandirma registry", "registry")
            r.evidence = f"fDenyTSConnections={deny}; NLA={nla}; SecurityLayer={sec_layer}; MinEncryption={min_enc}"
            if deny == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — RDP kapali"
            elif nla == 0:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "RDP acik VE NLA kapali — kritik. NLA etkinlestirilmeli."
            elif sec_layer == 0:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "SecurityLayer=0 (RDP Security); TLS (2) olmali."
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — RDP acik, NLA aktif"
        b.add("CHT-20-003", "RDP ayarlari (NLA/sifreleme)", test_rdp)

        # 20.4 Uzak yonetim araclari
        def test_remote_tools(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1219"
            r.attempted_methods = ["service/registry/process check"]
            tools = {
                "TeamViewer": ("TeamViewer", r"SOFTWARE\TeamViewer"),
                "AnyDesk": ("AnyDesk", r"SOFTWARE\AnyDesk"),
                "LogMeIn": ("LogMeIn", r"SOFTWARE\LogMeIn"),
                "RustDesk": ("RustDesk", r"SOFTWARE\RustDesk"),
                "ScreenConnect": ("ScreenConnect Client", r"SOFTWARE\ScreenConnect Client"),
                "Bomgar": ("BeyondTrust", r"SOFTWARE\Bomgar"),
            }
            found = []
            for name, (svc, reg) in tools.items():
                if winapi.service_installed(svc) or winapi.reg_key_exists(winapi._HKLM, reg):
                    found.append(name)
            procs = {}
            try:
                from ..winapi import _snap_processes
                procs = _snap_processes()
            except Exception:
                pass
            for proc_name, label in [("teamviewer.exe", "TeamViewer"), ("anydesk.exe", "AnyDesk"),
                                      ("rustdesk.exe", "RustDesk"), ("screenconnect.exe", "ScreenConnect")]:
                if proc_name in procs and label not in found:
                    found.append(f"{label}(proses)")
            r.evidence = f"Tespit edilen uzak erisim araclari: {', '.join(found) if found else 'yok'}"
            if found:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = f"Uzak erisim araclari ({', '.join(found)}) kurumsal politikayla uyumlu mu kontrol edilmeli."
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — ucuncu parti uzak erisim araci yok"
        b.add("CHT-20-004", "Ucuncu parti uzak erisim araclari", test_remote_tools)

        # 20.5 PSRemoting
        def test_psremoting(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1021.006"
            r.attempted_methods = ["registry PSRemoting"]
            enabled, ok = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowRemoteShellAccess")
            r.evidence = f"AllowRemoteShellAccess={enabled}(set={ok})"
            if ok and enabled == 0:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — PSRemoting kapali"
            elif ok and enabled == 1:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "PSRemoting acik — gerekmiyorsa kapatilmali."
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — GPO ile yapilandirilmamis"
        b.add("CHT-20-005", "PowerShell Remoting", test_psremoting)

        return b.results()
