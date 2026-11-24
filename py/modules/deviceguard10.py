"""Module 10 — Cihaz Korumasi (Device Guard)."""
from __future__ import annotations
import os

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "10-DeviceGuard"


class Module10:
    def id(self) -> str: return "10"
    def name(self) -> str: return "Cihaz Korumasi"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 10.1 Credential Guard
        def test_credguard(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1003.001"
            r.attempted_methods = ["registry DeviceGuard/Lsa"]
            lsa_cfg, lsa_ok = winapi.reg_dword(winapi._HKLM,
                r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags")
            dg_enable, dg_ok = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "EnableVirtualizationBasedSecurity")
            dg_cred, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "LsaCfgFlags")
            reg_text = winapi.reg_export_text(winapi._HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa")
            reg_text += "\n" + winapi.reg_export_text(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard")
            ctx.save_poc(r, "credential_guard_registry.txt", reg_text, "Credential Guard registry", "registry")
            r.evidence = f"Lsa LsaCfgFlags={lsa_cfg}(set={lsa_ok}); DG VBS={dg_enable}(set={dg_ok}); DG LsaCfgFlags={dg_cred}"
            if (lsa_ok and lsa_cfg >= 1) or (dg_cred >= 1):
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — Credential Guard aktif"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Credential Guard aktif degil — LSASS'tan hash dump riski."
        b.add("CHT-10-001", "Credential Guard", test_credguard)

        # 10.2 HVCI (Hypervisor-enforced Code Integrity)
        def test_hvci(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1014"
            r.attempted_methods = ["registry DeviceGuard HVCI"]
            hvci, ok = winapi.reg_dword(winapi._HKLM,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
            dg_hvci, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "HypervisorEnforcedCodeIntegrity")
            r.evidence = f"HVCI Enabled={hvci}(set={ok}); Policy HVCI={dg_hvci}"
            if (ok and hvci == 1) or dg_hvci == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — HVCI aktif"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "HVCI aktif degil — cekirdek seviyesinde kod butunlugu korumasiz."
        b.add("CHT-10-002", "HVCI (Hypervisor Code Integrity)", test_hvci)

        # 10.3 Secure Boot
        def test_secureboot(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1542"
            r.attempted_methods = ["registry SecureBoot", "bcdedit"]
            sb, ok = winapi.reg_dword(winapi._HKLM,
                r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
            r.evidence = f"UEFISecureBootEnabled={sb}(set={ok})"
            if ok and sb == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — Secure Boot aktif"
            elif ok and sb == 0:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Secure Boot KAPALI — bootkit/rootkit riski."
            else:
                res = winapi.run_cmd(8, "bcdedit", "/enum", "{current}")
                if "secureboot" in res.output.lower():
                    r.result = schema.RESULT_PARTIAL
                    r.evidence += f"; bcdedit: {res.output[:160]}"
                else:
                    r.result = schema.RESULT_PARTIAL
                    r.evidence += " — Secure Boot durumu belirlenemedi"
        b.add("CHT-10-003", "Secure Boot", test_secureboot)

        # 10.4 VBS (Virtualization-based Security)
        def test_vbs(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1014"
            r.attempted_methods = ["registry DeviceGuard VBS"]
            vbs_en, ok = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "EnableVirtualizationBasedSecurity")
            req_plat, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "RequirePlatformSecurityFeatures")
            reg_text = winapi.reg_export_text(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard")
            ctx.save_poc(r, "vbs_registry.txt", reg_text, "VBS/DeviceGuard registry", "registry")
            r.evidence = f"VBS EnableVirtualizationBasedSecurity={vbs_en}(set={ok}); RequirePlatformSecurity={req_plat}"
            if ok and vbs_en == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — VBS aktif"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "VBS aktif degil — Credential Guard ve HVCI calisamaz."
        b.add("CHT-10-004", "VBS (Virtualization-based Security)", test_vbs)

        # 10.5 Kernel DMA Protection
        def test_dma(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1200"
            r.attempted_methods = ["registry DmaGuard"]
            policy, ok = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\DmaGuard", "DeviceEnumerationPolicy")
            r.evidence = f"DmaGuard DeviceEnumerationPolicy={policy}(set={ok})"
            if ok and policy == 0:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — DMA korumasi aktif (block all)"
            elif ok:
                r.result = schema.RESULT_PARTIAL
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Kernel DMA korumasi yapilandirilmamis — Thunderbolt DMA atak riski."
        b.add("CHT-10-005", "Kernel DMA Protection", test_dma)

        return b.results()
