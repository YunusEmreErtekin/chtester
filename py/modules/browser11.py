"""Module 11 — Tarayici Politikalari (Browser)."""
from __future__ import annotations
import os, winreg

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "11-Browser"

CHROME_POL = r"SOFTWARE\Policies\Google\Chrome"
EDGE_POL = r"SOFTWARE\Policies\Microsoft\Edge"


class Module11:
    def id(self) -> str: return "11"
    def name(self) -> str: return "Tarayici Politikalari"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 11.1 Extension install restrictions
        def test_extension(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1176"
            r.attempted_methods = ["registry ExtensionInstallBlocklist/Sources"]
            chrome_bl = winapi.reg_key_exists(winapi._HKLM, CHROME_POL + r"\ExtensionInstallBlocklist")
            chrome_src = winapi.reg_key_exists(winapi._HKLM, CHROME_POL + r"\ExtensionInstallSources")
            edge_bl = winapi.reg_key_exists(winapi._HKLM, EDGE_POL + r"\ExtensionInstallBlocklist")
            edge_src = winapi.reg_key_exists(winapi._HKLM, EDGE_POL + r"\ExtensionInstallSources")
            reg_text = winapi.reg_export_text(winapi._HKLM, CHROME_POL + r"\ExtensionInstallBlocklist")
            reg_text += "\n" + winapi.reg_export_text(winapi._HKLM, EDGE_POL + r"\ExtensionInstallBlocklist")
            ctx.save_poc(r, "extension_policy.txt", reg_text, "Extension install policy registry", "registry")
            r.evidence = f"Chrome blocklist={chrome_bl} sources={chrome_src}; Edge blocklist={edge_bl} sources={edge_src}"
            if (chrome_bl or chrome_src) and (edge_bl or edge_src):
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
            elif chrome_bl or chrome_src or edge_bl or edge_src:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "Extension kisitlamasi her iki tarayicida da uygulanmali."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Extension kurulumu kisitlanmamis — zararli eklenti riski."
        b.add("CHT-11-001", "Tarayici extension kurulum kisitlamasi", test_extension)

        # 11.2 DevTools policy
        def test_devtools(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1185"
            r.attempted_methods = ["registry DeveloperToolsAvailability"]
            chrome_dt, c_ok = winapi.reg_dword(winapi._HKLM, CHROME_POL, "DeveloperToolsAvailability")
            edge_dt, e_ok = winapi.reg_dword(winapi._HKLM, EDGE_POL, "DeveloperToolsAvailability")
            r.evidence = f"Chrome DevTools={chrome_dt}(set={c_ok}); Edge DevTools={edge_dt}(set={e_ok})"
            blocked = (c_ok and chrome_dt == 2) and (e_ok and edge_dt == 2)
            if blocked:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
            elif c_ok or e_ok:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "DevTools her iki tarayicida da kisitlanmali (DeveloperToolsAvailability=2)."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "DevTools kisitlanmamis."
        b.add("CHT-11-002", "DevTools politikasi", test_devtools)

        # 11.3 Safe Browsing
        def test_safe_browsing(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1566"
            r.attempted_methods = ["registry SafeBrowsing"]
            chrome_sb, c_ok = winapi.reg_dword(winapi._HKLM, CHROME_POL, "SafeBrowsingProtectionLevel")
            edge_sb, e_ok = winapi.reg_dword(winapi._HKLM, EDGE_POL, "SmartScreenEnabled")
            r.evidence = f"Chrome SafeBrowsing={chrome_sb}(set={c_ok}); Edge SmartScreen={edge_sb}(set={e_ok})"
            if (c_ok and chrome_sb >= 1) and (e_ok and edge_sb == 1):
                r.result = schema.RESULT_BLOCKED
            elif c_ok or e_ok:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "Safe Browsing / SmartScreen her iki tarayicida zorlanmali."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Safe Browsing GPO ile zorlanmamis."
        b.add("CHT-11-003", "Safe Browsing / SmartScreen politikasi", test_safe_browsing)

        # 11.4 Password manager policy
        def test_pwd_manager(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1555.003"
            r.attempted_methods = ["registry PasswordManagerEnabled"]
            chrome_pm, c_ok = winapi.reg_dword(winapi._HKLM, CHROME_POL, "PasswordManagerEnabled")
            edge_pm, e_ok = winapi.reg_dword(winapi._HKLM, EDGE_POL, "PasswordManagerEnabled")
            r.evidence = f"Chrome PwdMgr={chrome_pm}(set={c_ok}); Edge PwdMgr={edge_pm}(set={e_ok})"
            both_off = (c_ok and chrome_pm == 0) and (e_ok and edge_pm == 0)
            if both_off:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
                r.evidence += " — tarayici parola yoneticisi kapali"
            elif c_ok or e_ok:
                r.result = schema.RESULT_PARTIAL
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Tarayici parola yoneticisi GPO ile kapatilmamis."
        b.add("CHT-11-004", "Tarayici parola yoneticisi politikasi", test_pwd_manager)

        # 11.5 Download restrictions
        def test_download(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1204.002"
            r.attempted_methods = ["registry DownloadRestrictions"]
            chrome_dl, c_ok = winapi.reg_dword(winapi._HKLM, CHROME_POL, "DownloadRestrictions")
            edge_dl, e_ok = winapi.reg_dword(winapi._HKLM, EDGE_POL, "DownloadRestrictions")
            r.evidence = f"Chrome DownloadRestrictions={chrome_dl}(set={c_ok}); Edge={edge_dl}(set={e_ok})"
            if (c_ok and chrome_dl >= 1) and (e_ok and edge_dl >= 1):
                r.result = schema.RESULT_BLOCKED
            elif c_ok or e_ok:
                r.result = schema.RESULT_PARTIAL
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Indirme kisitlamalari GPO ile ayarlanmamis."
        b.add("CHT-11-005", "Tarayici indirme kisitlamalari", test_download)

        return b.results()
