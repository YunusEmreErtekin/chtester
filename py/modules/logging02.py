"""Module 02 — Loglama & Denetim (Logging & Audit)."""
from __future__ import annotations
import os, winreg

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "02-Logging"


class Module02:
    def id(self) -> str: return "02"
    def name(self) -> str: return "Loglama & Denetim"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 02.1 Audit policy
        def test_audit_policy(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping = schema.Mapping(cis="Advanced Audit Policy", attack="T1562.002")
            r.attempted_methods = ["auditpol /get /category:*"]
            res = winapi.run_cmd(10, "auditpol", "/get", "/category:*")
            if res.exit_code != 0:
                r.result = schema.RESULT_PARTIAL
                r.evidence = f"auditpol calistirilamadi: {res.output[:160]}"
                return
            ctx.save_poc(r, "auditpol_output.txt", res.output, "Audit policy tam cikti", "command_output")
            no_audit_count = res.output.lower().count("no auditing") + res.output.lower().count("denetim yok")
            success_count = res.output.lower().count("success")
            lines = [l.strip() for l in res.output.splitlines() if l.strip()]
            r.evidence = f"Toplam satir={len(lines)}; 'No Auditing' sayisi={no_audit_count}; 'Success' sayisi={success_count}"
            if no_audit_count > 20:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Cok sayida kategori denetlenmiyor; Advanced Audit Policy yapilandirilmali."
            elif no_audit_count > 5:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "Bazi kategoriler denetlenmiyor; gozden gecirilmeli."
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — audit policy kapsamli gorunuyor"
        b.add("CHT-02-001", "Audit Policy durumu (auditpol)", test_audit_policy)

        # 02.2 Sysmon
        def test_sysmon(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1562.001"
            r.attempted_methods = ["service Sysmon/Sysmon64", "registry driver"]
            sysmon = winapi.service_installed("Sysmon") or winapi.service_installed("Sysmon64")
            driver = winapi.reg_key_exists(winapi._HKLM, r"SYSTEM\CurrentControlSet\Services\SysmonDrv")
            r.evidence = f"Sysmon service={sysmon}; SysmonDrv={driver}"
            if sysmon and driver:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Sysmon"
                r.evidence += " — Sysmon aktif"
            elif sysmon or driver:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "Sysmon kismi yuklu; tam yapilandirilmali."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Sysmon yuklu degil — gelismis proses/ag izleme eksik."
        b.add("CHT-02-002", "Sysmon varligi ve durumu", test_sysmon)

        # 02.3 PowerShell ScriptBlock logging
        def test_ps_scriptblock(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1059.001"
            r.attempted_methods = ["registry ScriptBlockLogging"]
            path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            enabled, ok = winapi.reg_dword(winapi._HKLM, path, "EnableScriptBlockLogging")
            inv_header, _ = winapi.reg_dword(winapi._HKLM, path, "EnableScriptBlockInvocationLogging")
            reg_text = winapi.reg_export_text(winapi._HKLM, path)
            ctx.save_poc(r, "ps_scriptblock_registry.txt", reg_text, "ScriptBlock logging registry", "registry")
            r.evidence = f"EnableScriptBlockLogging={enabled}(set={ok}); InvocationLogging={inv_header}"
            if ok and enabled == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — ScriptBlock logging aktif"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "PowerShell ScriptBlock logging etkinlestirilmeli (GPO)."
        b.add("CHT-02-003", "PowerShell ScriptBlock logging", test_ps_scriptblock)

        # 02.4 PowerShell Module logging
        def test_ps_module(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1059.001"
            r.attempted_methods = ["registry ModuleLogging"]
            path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
            enabled, ok = winapi.reg_dword(winapi._HKLM, path, "EnableModuleLogging")
            r.evidence = f"EnableModuleLogging={enabled}(set={ok})"
            if ok and enabled == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — Module logging aktif"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "PowerShell Module logging etkinlestirilmeli."
        b.add("CHT-02-004", "PowerShell Module logging", test_ps_module)

        # 02.5 PowerShell Transcription
        def test_ps_transcript(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1059.001"
            r.attempted_methods = ["registry Transcription"]
            path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            enabled, ok = winapi.reg_dword(winapi._HKLM, path, "EnableTranscripting")
            out_dir, _ = winapi.reg_string(winapi._HKLM, path, "OutputDirectory")
            r.evidence = f"EnableTranscripting={enabled}(set={ok}); OutputDirectory={out_dir!r}"
            if ok and enabled == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — Transcription aktif"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "PowerShell Transcription etkinlestirilmeli."
        b.add("CHT-02-005", "PowerShell Transcription", test_ps_transcript)

        # 02.6 Windows Event Forwarding (WEF)
        def test_wef(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1562.002"
            r.attempted_methods = ["service Wecsvc", "registry WEF"]
            wecsvc = winapi.service_installed("Wecsvc")
            sub_mgr, _ = winapi.reg_string(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager", "")
            r.evidence = f"Wecsvc service={wecsvc}; SubscriptionManager set={bool(sub_mgr)}"
            if wecsvc and sub_mgr:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — WEF yapilandirilmis"
            elif wecsvc:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "WEF servisi var ama subscription yapilandirilmamis."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Windows Event Forwarding yapilandirilmamis — merkezi log toplama eksik."
        b.add("CHT-02-006", "Windows Event Forwarding (WEF)", test_wef)

        # 02.7 Event log boyutlari
        def test_log_sizes(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1070.001"
            r.attempted_methods = ["registry EventLog configs"]
            logs = {"Security": 0, "Application": 0, "System": 0, "PowerShellCore/Operational": 0}
            details = []
            for log_name in logs:
                path = rf"SYSTEM\CurrentControlSet\Services\EventLog\{log_name}"
                max_size, ok = winapi.reg_dword(winapi._HKLM, path, "MaxSize")
                if ok:
                    logs[log_name] = max_size
                    details.append(f"{log_name}={max_size // 1024}KB")
                else:
                    details.append(f"{log_name}=varsayilan")
            r.evidence = "; ".join(details)
            sec_size = logs.get("Security", 0)
            if sec_size > 0 and sec_size < 64 * 1024 * 1024:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = f"Security log boyutu {sec_size // (1024*1024)}MB — en az 1GB onerilir."
            else:
                r.result = schema.RESULT_PARTIAL
        b.add("CHT-02-007", "Event log boyutlari", test_log_sizes)

        return b.results()
