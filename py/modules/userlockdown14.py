"""Module 14 — Kullanici Kisitlama / Kilitleme."""
from __future__ import annotations
import winreg

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "14-UserLockdown"
POL_EXPLORER = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
POL_SYSTEM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def _pol_dword(subkey: str, name: str) -> tuple[int, bool]:
    v, ok = winapi.reg_dword(winapi._HKCU, subkey, name)
    if ok:
        lm, lm_ok = winapi.reg_dword(winapi._HKLM, subkey, name)
        if lm_ok and lm > v:
            return lm, True
        return v, True
    return winapi.reg_dword(winapi._HKLM, subkey, name)


class Module14:
    def id(self) -> str: return "14"
    def name(self) -> str: return "Kullanici Kisitlama / Kilitleme"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 14.1 Denetim Masasi
        def test_cp(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.attempted_methods = ["registry NoControlPanel / SettingsPageVisibility"]
            ncp, _ = _pol_dword(POL_EXPLORER, "NoControlPanel")
            r.evidence = f"NoControlPanel={ncp}"
            if ncp == 1:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Denetim Masasi/Ayarlar tam erisim acik; SettingsPageVisibility ile kisitlanmali."
        b.add("CHT-14-001", "Denetim Masasi / Ayarlar erisimi kisitlamasi", test_cp)

        # 14.2 Task Manager
        def test_taskmgr(r: schema.Result):
            r.risk_when_open = schema.RISK_LOW
            r.attempted_methods = ["registry DisableTaskMgr"]
            v, _ = _pol_dword(POL_SYSTEM, "DisableTaskMgr")
            r.evidence = f"DisableTaskMgr={v}"
            r.result = schema.RESULT_BLOCKED if v == 1 else schema.RESULT_ALLOWED
            if v != 1:
                r.recommendation = "Gorev Yoneticisi acik."
        b.add("CHT-14-002", "Gorev Yoneticisi kisitlamasi", test_taskmgr)

        # 14.3 CMD
        def test_cmd(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1059.003"
            r.attempted_methods = ["registry DisableCMD"]
            v, ok = _pol_dword(POL_SYSTEM, "DisableCMD")
            r.evidence = f"DisableCMD={v}"
            if ok and v in (1, 2):
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
                if v == 2:
                    r.result = schema.RESULT_PARTIAL
                    r.evidence += " — interaktif cmd kapali ama .bat/.cmd script acik"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "cmd.exe kisitlanmamis."
        b.add("CHT-14-003", "Komut Istemi kisitlamasi (DisableCMD)", test_cmd)

        # 14.7 Ekran kilidi
        def test_screenlock(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1078"
            r.attempted_methods = ["registry InactivityTimeoutSecs / ScreenSaverIsSecure"]
            inact, _ = _pol_dword(POL_SYSTEM, "InactivityTimeoutSecs")
            pol_desk = r"SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
            sec_cu, _ = winapi.reg_string(winapi._HKCU, pol_desk, "ScreenSaverIsSecure")
            sec_lm, _ = winapi.reg_string(winapi._HKLM, pol_desk, "ScreenSaverIsSecure")
            secure = sec_cu == "1" or sec_lm == "1"
            r.evidence = f"InactivityTimeoutSecs={inact}; ScreenSaverIsSecure={secure}"
            if inact > 0 or secure:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Otomatik ekran kilidi zorlanmamis — fiziksel erisim riski."
        b.add("CHT-14-007", "Otomatik ekran kilidi", test_screenlock)

        # 14.11 RDP yonlendirme
        def test_rdp_redir(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1021.001"
            r.attempted_methods = ["registry Terminal Services fDisable*"]
            ts = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            cdm, _ = _pol_dword(ts, "fDisableCdm")
            clip, _ = _pol_dword(ts, "fDisableClip")
            r.evidence = f"fDisableCdm(surucu)={cdm}; fDisableClip(pano)={clip}"
            if cdm == 1 and clip == 1:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "RDP surucu/pano yonlendirme kisitlanmamis."
        b.add("CHT-14-011", "RDP oturum yonlendirme kisitlari", test_rdp_redir)

        return b.results()
