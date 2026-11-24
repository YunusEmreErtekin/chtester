"""Module 05 — Depolama & Sifreleme (Storage & Encryption)."""
from __future__ import annotations
import os

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "05-Storage"


class Module05:
    def id(self) -> str: return "05"
    def name(self) -> str: return "Depolama & Sifreleme"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 05.1 BitLocker
        def test_bitlocker(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping = schema.Mapping(cis="BitLocker Drive Encryption", attack="T1005")
            r.attempted_methods = ["manage-bde -status", "registry BitLocker"]
            res = winapi.run_cmd(10, "manage-bde", "-status")
            ctx.save_poc(r, "bitlocker_status.txt", res.output, "BitLocker durum ciktisi", "command_output")
            if res.exit_code != 0:
                fve, _ = winapi.reg_dword(winapi._HKLM,
                    r"SOFTWARE\Policies\Microsoft\FVE", "UseAdvancedStartup")
                r.evidence = f"manage-bde calistirilamadi (exit={res.exit_code}); FVE policy set={fve}"
                r.result = schema.RESULT_PARTIAL
                return
            output_lower = res.output.lower()
            if "fully encrypted" in output_lower or "tamamen sifreli" in output_lower:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "BitLocker: disk tamamen sifreli"
            elif "protection on" in output_lower or "koruma acik" in output_lower:
                r.result = schema.RESULT_PARTIAL
                r.evidence = "BitLocker aktif ama tam durum belirsiz"
            elif "protection off" in output_lower or "koruma kapali" in output_lower:
                r.result = schema.RESULT_ALLOWED
                r.evidence = "BitLocker: koruma KAPALI veya sifrelenmemis"
                r.recommendation = "BitLocker etkinlestirilmeli; cihaz kaybi durumunda veri korumasiz."
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence = f"BitLocker durumu belirsiz: {res.output[:200]}"
        b.add("CHT-05-001", "BitLocker disk sifreleme durumu", test_bitlocker)

        # 05.2 USB storage policy
        def test_usb_storage(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1052.001"
            r.attempted_methods = ["registry USBSTOR"]
            start_val, ok = winapi.reg_dword(winapi._HKLM,
                r"SYSTEM\CurrentControlSet\Services\USBSTOR", "Start")
            deny_write, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}", "Deny_Write")
            deny_read, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}", "Deny_Read")
            deny_all, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}", "Deny_Execute")
            reg_text = winapi.reg_export_text(winapi._HKLM, r"SYSTEM\CurrentControlSet\Services\USBSTOR")
            ctx.save_poc(r, "usbstor_registry.txt", reg_text, "USBSTOR registry", "registry")
            r.evidence = f"USBSTOR Start={start_val}(set={ok}); DenyWrite={deny_write}; DenyRead={deny_read}; DenyExec={deny_all}"
            if start_val == 4:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
                r.evidence += " — USB storage devre disi"
            elif deny_write == 1 and deny_read == 1:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
                r.evidence += " — read/write kisitli"
            elif deny_write == 1:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — sadece yazma kisitli"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "USB depolama kisitlanmamis — veri sizintisi riski."
        b.add("CHT-05-002", "USB storage politikasi", test_usb_storage)

        # 05.3 AutoPlay/AutoRun
        def test_autorun(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1091"
            r.attempted_methods = ["registry NoDriveTypeAutoRun"]
            val_m, ok_m = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
            val_u, ok_u = winapi.reg_dword(winapi._HKCU,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
            r.evidence = f"HKLM NoDriveTypeAutoRun={val_m}(set={ok_m}); HKCU={val_u}(set={ok_u})"
            if (ok_m and val_m == 255) or (ok_u and val_u == 255):
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — AutoRun tum suruculer icin kapali"
            elif ok_m or ok_u:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "NoDriveTypeAutoRun=0xFF ile tum suruculer icin kapatilmali."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "AutoRun kisitlanmamis — USB-based malware riski."
        b.add("CHT-05-003", "AutoPlay / AutoRun politikasi", test_autorun)

        # 05.4 Removable media GPO
        def test_removable_media(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1052.001"
            r.attempted_methods = ["registry RemovableStorageDevices"]
            base = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
            deny_all_w, _ = winapi.reg_dword(winapi._HKLM, base, "Deny_All")
            cdrom_w, _ = winapi.reg_dword(winapi._HKLM,
                base + r"\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}", "Deny_Write")
            floppy_w, _ = winapi.reg_dword(winapi._HKLM,
                base + r"\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}", "Deny_Write")
            r.evidence = f"Deny_All={deny_all_w}; CD/DVD DenyWrite={cdrom_w}; Floppy DenyWrite={floppy_w}"
            if deny_all_w == 1:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — tum removable media kisitli"
            elif cdrom_w == 1 or floppy_w == 1:
                r.result = schema.RESULT_PARTIAL
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Removable media kisitlanmamis."
        b.add("CHT-05-004", "Removable media GPO kisitlamalari", test_removable_media)

        return b.results()
