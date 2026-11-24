"""Module 06 — Uygulama Kontrolu (Application Control)."""
from __future__ import annotations
import os

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "06-AppControl"


class Module06:
    def id(self) -> str: return "06"
    def name(self) -> str: return "Uygulama Kontrolu"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 06.1 AppLocker
        def test_applocker(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping = schema.Mapping(cis="Application Whitelisting", attack="T1204")
            r.attempted_methods = ["service AppIDSvc", "registry AppLocker"]
            svc = winapi.service_installed("AppIDSvc")
            base = r"SOFTWARE\Policies\Microsoft\Windows\SrpV2"
            collections = ["Exe", "Msi", "Script", "Dll", "Appx"]
            configured = []
            for col in collections:
                if winapi.reg_key_exists(winapi._HKLM, base + "\\" + col):
                    rules = winapi.reg_subkeys(winapi._HKLM, base + "\\" + col)
                    if rules:
                        configured.append(f"{col}({len(rules)} kural)")
            reg_text = ""
            for col in collections:
                reg_text += winapi.reg_export_text(winapi._HKLM, base + "\\" + col) + "\n\n"
            ctx.save_poc(r, "applocker_registry.txt", reg_text, "AppLocker registry kurallari", "registry")
            r.evidence = f"AppIDSvc={svc}; Yapilandirilan koleksiyonlar: {', '.join(configured) if configured else 'yok'}"
            if svc and len(configured) >= 3:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "AppLocker"
                r.evidence += " — AppLocker aktif ve kapsamli"
            elif configured:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "AppLocker kismi; Exe/Script/Dll koleksiyonlari da yapilandirilmali."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "AppLocker yapilandirilmamis — uygulama kontrolu yok."
        b.add("CHT-06-001", "AppLocker politikasi", test_applocker)

        # 06.2 WDAC (Windows Defender Application Control)
        def test_wdac(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1204"
            r.attempted_methods = ["registry CodeIntegrity", "CiTool"]
            ci_path = r"SYSTEM\CurrentControlSet\Control\CI"
            umci, ok_umci = winapi.reg_dword(winapi._HKLM, ci_path, "UMCIAuditMode")
            enabled, ok_en = winapi.reg_dword(winapi._HKLM, ci_path, "HVCIEnabled")
            policy_path = os.path.join(winapi.system_root(), "System32", "CodeIntegrity", "SIPolicy.p7b")
            has_policy = winapi.file_exists(policy_path)
            r.evidence = f"UMCIAuditMode={umci}(set={ok_umci}); HVCIEnabled={enabled}(set={ok_en}); SIPolicy.p7b={has_policy}"
            if has_policy:
                r.result = schema.RESULT_BLOCKED if not (ok_umci and umci == 1) else schema.RESULT_PARTIAL
                r.evidence += " — WDAC politikasi mevcut"
                if ok_umci and umci == 1:
                    r.recommendation = "WDAC audit modunda; enforce moduna gecirilmeli."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "WDAC politikasi yok — imzasiz kod calistirilabilir."
        b.add("CHT-06-002", "WDAC (Device Guard Code Integrity)", test_wdac)

        # 06.3 SRP (Software Restriction Policies)
        def test_srp(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1204"
            r.attempted_methods = ["registry SRP"]
            base = r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
            default_level, ok = winapi.reg_dword(winapi._HKLM, base, "DefaultLevel")
            transparent, _ = winapi.reg_dword(winapi._HKLM, base, "TransparentEnabled")
            r.evidence = f"SRP DefaultLevel={default_level}(set={ok}); TransparentEnabled={transparent}"
            if ok and default_level == 0:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "SRP"
                r.evidence += " — varsayilan seviye Disallowed"
            elif ok:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "SRP yapilandirilmis ama Disallowed degil."
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — SRP yapilandirilmamis (AppLocker/WDAC tercih edilir)"
        b.add("CHT-06-003", "Software Restriction Policies (SRP)", test_srp)

        return b.results()
