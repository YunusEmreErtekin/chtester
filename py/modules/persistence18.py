"""Module 18 — Kalicilik Mekanizmalari (Persistence)."""
from __future__ import annotations
import os

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "18-Persistence"


class Module18:
    def id(self) -> str: return "18"
    def name(self) -> str: return "Kalicilik Mekanizmalari"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 18.1 Run/RunOnce registry
        def test_run_keys(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1547.001"
            r.attempted_methods = ["registry Run/RunOnce (HKLM+HKCU)"]
            entries = []
            paths = [
                (winapi._HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
                (winapi._HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
                (winapi._HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (winapi._HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
            ]
            reg_text = ""
            for root, path, label in paths:
                vals = winapi.reg_string_values(root, path)
                for name, val in vals.items():
                    entries.append(f"{label}\\{name} = {val}")
                reg_text += winapi.reg_export_text(root, path) + "\n\n"
            ctx.save_poc(r, "run_keys.txt", reg_text, "Run/RunOnce registry icerigi", "registry")
            r.evidence = f"{len(entries)} Run/RunOnce girisi"
            if entries:
                r.evidence += f": {'; '.join(entries[:5])}"
                if len(entries) > 5:
                    r.evidence += f" ... (+{len(entries) - 5})"
            suspicious = [e for e in entries if any(s in e.lower() for s in
                ["temp", "appdata", "public", "powershell", "cmd", "script", "wscript", "cscript"])]
            if suspicious:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = f"Suphe: {'; '.join(suspicious[:3])}"
            elif entries:
                r.result = schema.RESULT_PARTIAL
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Run/RunOnce girisi yok"
        b.add("CHT-18-001", "Run/RunOnce registry girisleri", test_run_keys)

        # 18.2 Scheduled tasks
        def test_schtasks(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1053.005"
            r.attempted_methods = ["schtasks /query"]
            res = winapi.run_cmd(15, "schtasks", "/query", "/fo", "CSV", "/nh")
            if res.exit_code != 0:
                r.result = schema.RESULT_PARTIAL
                r.evidence = f"schtasks calistirilamadi: {res.output[:160]}"
                return
            ctx.save_poc(r, "scheduled_tasks.csv", res.output, "Zamanlanmis gorevler listesi", "command_output")
            lines = [l for l in res.output.splitlines() if l.strip() and not l.startswith("INFO")]
            suspicious_dirs = ["temp", "appdata", "public", "downloads", "users"]
            suspicious = []
            for line in lines:
                low = line.lower()
                if any(d in low for d in suspicious_dirs):
                    suspicious.append(line.split(",")[0].strip('"') if "," in line else line[:80])
            r.evidence = f"Toplam gorev={len(lines)}; suphe={len(suspicious)}"
            if suspicious:
                r.result = schema.RESULT_ALLOWED
                r.evidence += f": {'; '.join(suspicious[:5])}"
                r.recommendation = "Suphe uyandiran zamanlanmis gorevler incelenmeli."
            else:
                r.result = schema.RESULT_PARTIAL
        b.add("CHT-18-002", "Zamanlanmis gorevler (schtasks)", test_schtasks)

        # 18.3 Startup folder
        def test_startup(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1547.001"
            r.attempted_methods = ["Startup folder icerigi"]
            dirs = [
                os.path.join(os.environ.get("APPDATA", ""),
                    r"Microsoft\Windows\Start Menu\Programs\Startup"),
                os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                    r"Microsoft\Windows\Start Menu\Programs\Startup"),
            ]
            items = []
            for d in dirs:
                if os.path.isdir(d):
                    for f in os.listdir(d):
                        fp = os.path.join(d, f)
                        if os.path.isfile(fp) and not f.lower() == "desktop.ini":
                            items.append(f"{d}\\{f}")
            r.evidence = f"Startup oge={len(items)}"
            if items:
                r.evidence += f": {'; '.join(items[:5])}"
                ctx.save_poc(r, "startup_items.txt", "\n".join(items), "Startup klasor icerigi", "file_copy")
            writable_sys = False
            sys_startup = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                r"Microsoft\Windows\Start Menu\Programs\Startup")
            if winapi.try_write_probe(sys_startup):
                writable_sys = True
                r.evidence += "; SYSTEM Startup YAZILABILIR"
            if writable_sys:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "System Startup klasoru yazilabilir — kalicilik yuzeyi."
            elif items:
                r.result = schema.RESULT_PARTIAL
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — temiz"
        b.add("CHT-18-003", "Startup folder icerigi + yazilabilirlik", test_startup)

        # 18.4 Services auto-start
        def test_services(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1543.003"
            r.attempted_methods = ["registry Services (Start=2)"]
            base = r"SYSTEM\CurrentControlSet\Services"
            subs = winapi.reg_subkeys(winapi._HKLM, base)
            auto_start = []
            for s in subs:
                start, ok = winapi.reg_dword(winapi._HKLM, base + "\\" + s, "Start")
                if ok and start == 2:
                    img, _ = winapi.reg_string(winapi._HKLM, base + "\\" + s, "ImagePath")
                    if img:
                        auto_start.append(f"{s}: {img[:80]}")
            r.evidence = f"Auto-start servis sayisi={len(auto_start)}"
            non_system = [s for s in auto_start if not any(
                x in s.lower() for x in ["system32", "syswow64", "svchost", "microsoft"])]
            if non_system:
                r.evidence += f"; ucuncu-parti: {'; '.join(non_system[:5])}"
                ctx.save_poc(r, "autostart_services.txt",
                    "\n".join(auto_start), "Tum auto-start servisler", "command_output")
            r.result = schema.RESULT_PARTIAL
            if len(non_system) > 10:
                r.recommendation = f"{len(non_system)} ucuncu parti auto-start servis — gozden gecirilmeli."
        b.add("CHT-18-004", "Auto-start servisler", test_services)

        # 18.5 WMI event subscriptions
        def test_wmi(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1546.003"
            r.attempted_methods = ["wmic /namespace EventFilter"]
            ps = os.path.join(winapi.system_root(), r"System32\WindowsPowerShell\v1.0\powershell.exe")
            if not winapi.file_exists(ps):
                r.result = schema.RESULT_PARTIAL
                r.evidence = "powershell.exe yok"
                return
            res = winapi.run_cmd(10, ps, "-NoProfile", "-Command",
                "Get-WmiObject -Namespace root\\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query | Format-List")
            if not res.output.strip():
                r.result = schema.RESULT_BLOCKED
                r.evidence = "WMI event subscription bulunamadi (iyi)"
                return
            ctx.save_poc(r, "wmi_subscriptions.txt", res.output, "WMI event subscription listesi", "command_output")
            r.result = schema.RESULT_ALLOWED
            r.evidence = f"WMI event subscription mevcut: {res.output[:200]}"
            r.recommendation = "WMI event subscription'lar incelenmeli — kalicilik mekanizmasi olabilir."
        b.add("CHT-18-005", "WMI event subscriptions", test_wmi)

        return b.results()
