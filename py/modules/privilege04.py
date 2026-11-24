"""Module 04 — Ayricalik & UAC."""
from __future__ import annotations
import os, winreg

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "04-Privilege"


class Module04:
    def id(self) -> str: return "04"
    def name(self) -> str: return "Ayricalik & UAC"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 04.1 Local admin + UAC
        def test_admin_uac(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            admin = winapi.is_elevated()
            el, _ = winapi.reg_dword(winapi._HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
            ca, _ = winapi.reg_dword(winapi._HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
            r.attempted_methods = ["token elevation", "registry UAC policy"]
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"elevated={admin}; integrity={winapi.integrity_level()}; EnableLUA={el}; ConsentPromptBehaviorAdmin={ca}"
            if admin:
                r.result = schema.RESULT_ALLOWED
                r.risk_when_open = schema.RISK_CRITICAL
                r.recommendation = "Kullanici yukseltilmis token tasiyor — standart kullanici prensibi ihlali."
            elif el == 0:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "UAC kapali (EnableLUA=0)."
        b.add("CHT-04-001", "Local admin uyeligi + UAC seviyesi", test_admin_uac)

        # 04.3 UAC bypass
        def test_uac_bypass(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1548.002"
            r.attempted_methods = ["auto-elevate binary varligi"]
            present = []
            sysdir = os.path.join(winapi.system_root(), "System32")
            for b_name in ("fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe", "slui.exe"):
                if winapi.file_exists(os.path.join(sysdir, b_name)):
                    present.append(b_name)
            ca, _ = winapi.reg_dword(winapi._HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
            r.evidence = f"auto-elevate binary mevcut={','.join(present)}; ConsentPromptBehaviorAdmin={ca}"
            r.result = schema.RESULT_PARTIAL
            if ca in (0, 5):
                r.recommendation = "ConsentPromptBehaviorAdmin=2 onerilir; fodhelper-tarzi bypass yuzeyi mevcut."
        b.add("CHT-04-003", "UAC bypass yuzeyi (auto-elevate binary'ler)", test_uac_bypass)

        # 04.4 Token privileges
        def test_token_privs(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1134"
            r.attempted_methods = ["GetTokenInformation privileges"]
            dangerous = {
                "SeImpersonatePrivilege": "Potato (impersonation)",
                "SeAssignPrimaryTokenPrivilege": "Potato (primary token)",
                "SeDebugPrivilege": "process bellek/inject",
                "SeBackupPrivilege": "SAM/SYSTEM okuma",
                "SeRestorePrivilege": "korumali yazma",
                "SeLoadDriverPrivilege": "kernel driver yukleme",
                "SeTakeOwnershipPrivilege": "sahiplik ele gecirme",
            }
            hits = []
            for p in winapi.get_privileges():
                if p in dangerous:
                    hits.append(f"{p} ({dangerous[p]})")
            if not hits:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Tehlikeli privesc privilege'i yok"
                return
            r.result = schema.RESULT_ALLOWED
            r.evidence = f"Privesc yuzeyi: {'; '.join(hits)}"
            all_privs = winapi.get_privileges()
            ctx.save_poc(r, "token_privileges.txt", "\n".join(all_privs), "Tum token privilege listesi", "command_output")
            r.recommendation = "Bu privilege'ler standart kullanici token'inda olmamali."
        b.add("CHT-04-004", "Token privilege privesc yuzeyi", test_token_privs)

        # 04.5 AlwaysInstallElevated
        def test_aie(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1548.002"
            r.attempted_methods = ["registry HKLM+HKCU Installer"]
            hklm, _ = winapi.reg_dword(winapi._HKLM, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
            hkcu, _ = winapi.reg_dword(winapi._HKCU, r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
            r.evidence = f"HKLM={hklm}; HKCU={hkcu}"
            if hklm == 1 and hkcu == 1:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "AlwaysInstallElevated her iki hive'da ACIK — dogrudan SYSTEM privesc!"
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — privesc icin ikisi de 1 olmali (degil)"
        b.add("CHT-04-005", "AlwaysInstallElevated (HKLM + HKCU)", test_aie)

        # 04.6 Unquoted service path
        def test_unquoted(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1574.009"
            r.attempted_methods = ["Services\\*\\ImagePath analizi"]
            vuln = _find_unquoted()
            if not vuln:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Somurulabilir unquoted service path bulunamadi"
                return
            r.result = schema.RESULT_ALLOWED
            r.evidence = f"{len(vuln)} aday: {' | '.join(vuln)[:240]}"
            r.recommendation = "Service ImagePath'leri tirnak icine alinmali."
        b.add("CHT-04-006", "Unquoted service path + yazilabilir segment", test_unquoted)

        # 04.8 Writable PATH dirs
        def test_writable_path(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1574.007"
            r.attempted_methods = ["%PATH% segment yazma probe"]
            writable = []
            for p in os.environ.get("PATH", "").split(";"):
                if p and winapi.try_write_probe(p):
                    writable.append(p)
            if not writable:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "PATH dizinlerinin hicbiri yazilabilir degil"
                return
            r.result = schema.RESULT_ALLOWED
            r.evidence = f"{len(writable)} yazilabilir PATH dizini: {'; '.join(writable)}"
            r.recommendation = "Yazilabilir PATH dizinleri DLL/exe hijack yuzeyidir."
        b.add("CHT-04-008", "Yazilabilir PATH dizini (DLL hijack)", test_writable_path)

        # 04.9 Embedded credentials
        def test_embedded_cred(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1552.001"
            r.attempted_methods = ["unattend/sysprep dosyalari", "Winlogon AutoAdminLogon"]
            sr = winapi.system_root()
            hits = []
            for f in [os.path.join(sr, r"Panther\Unattend.xml"),
                      os.path.join(sr, r"Panther\Unattended.xml"),
                      os.path.join(sr, r"System32\Sysprep\unattend.xml"),
                      r"C:\unattend.xml"]:
                if winapi.file_exists(f):
                    hits.append(f"dosya:{f}")
            auto, _ = winapi.reg_string(winapi._HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
            defpwd, _ = winapi.reg_string(winapi._HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword")
            if auto == "1" or defpwd:
                hits.append(f"Winlogon AutoAdminLogon={auto} DefaultPassword-set={bool(defpwd)}")
            if not hits:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Bilinen konumlarda gomulu credential bulunamadi"
                return
            r.result = schema.RESULT_ALLOWED
            r.evidence = "; ".join(hits)
            r.recommendation = "Gomulu/autologon credential temizlenmeli."
        b.add("CHT-04-009", "Gomulu credential (unattend/sysprep/autologon)", test_embedded_cred)

        return b.results()


def _find_unquoted() -> list[str]:
    base = r"SYSTEM\CurrentControlSet\Services"
    subs = winapi.reg_subkeys(winapi._HKLM, base)
    vuln = []
    for s in subs:
        img, ok = winapi.reg_string(winapi._HKLM, base + "\\" + s, "ImagePath")
        if not ok or not img:
            continue
        t = img.strip()
        if t.startswith('"'):
            continue
        low = t.lower()
        idx = low.find(".exe")
        if idx < 0:
            continue
        head = t[:idx]
        if " " in head and not low.startswith("\\??\\"):
            vuln.append(f"{s}: {t[:80]}")
    return vuln
