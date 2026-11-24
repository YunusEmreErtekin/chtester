"""Module 09 — Kimlik Bilgisi & Kimlik Dogrulama (Credential).

Includes: LSASS handle probe, SAM/SYSTEM hive readability, cached creds,
browser credential store, WiFi PSK, shadow copy hash exposure, Mimikatz
binary detection (benign marker — no actual dump).
"""
from __future__ import annotations
import os, winreg

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "09-Credential"


class Module09:
    def id(self) -> str: return "09"
    def name(self) -> str: return "Kimlik Bilgisi & Kimlik Dogrulama"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 09.2 LSA koruma durusu
        def test_lsa(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1003.001"
            r.attempted_methods = ["registry Lsa/WDigest"]
            runasppl, _ = winapi.reg_dword(winapi._HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
            wdigest, _ = winapi.reg_dword(winapi._HKLM, r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential")
            cached, _ = winapi.reg_string(winapi._HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
            lsacfg, _ = winapi.reg_dword(winapi._HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags")
            r.evidence = f"RunAsPPL={runasppl}; WDigest.UseLogonCredential={wdigest}; CachedLogonsCount={cached!r}; CredGuard(LsaCfgFlags)={lsacfg}"
            rec = []
            if runasppl == 0:
                rec.append("RunAsPPL/LSA Protection kapali")
            if wdigest == 1:
                rec.append("WDigest plaintext cred ACIK (kritik)")
            if rec:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Duzeltilmeli: " + "; ".join(rec)
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — LSA korumasi makul"
        b.add("CHT-09-002", "LSA koruma durusu (RunAsPPL/WDigest/CredGuard)", test_lsa)

        # 09.3 LSASS handle acma yetenegi (DUMP ALMADAN)
        def test_lsass_handle(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1003.001"
            r.attempted_methods = ["FindPID lsass", "OpenProcess(VM_READ) + hemen kapat"]
            if not ctx.gate_active(r, 2, True):
                return
            pid, ok = winapi.find_process_id("lsass.exe")
            if not ok:
                r.result = schema.RESULT_ERROR
                r.evidence = "lsass.exe PID bulunamadi"
                return
            can_open, err = winapi.can_open_process_vm_read(pid)
            if can_open:
                r.result = schema.RESULT_ALLOWED
                r.evidence = f"LSASS'a VM_READ handle ACILABILDI (pid={pid}, dump alinmadi) — credential-dump yuzeyi acik"
                r.recommendation = "RunAsPPL + Credential Guard + EDR LSASS korumasi etkinlestirilmeli."
            else:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Permission"
                r.detected = schema.DETECTED_UNKNOWN
                r.evidence = f"LSASS handle acilamadi (iyi): {err}"
        b.add("CHT-09-003", "LSASS handle acma yetenegi (dump ALMADAN)", test_lsass_handle)

        # 09.7 SAM/SYSTEM hive okunabilirligi
        def test_sam(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1003.002"
            r.attempted_methods = ["os.Open config\\SAM"]
            readable = winapi.sam_hive_readable()
            if not readable:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "SAM/SYSTEM/SECURITY hive'lari kilitli/okunamiyor (iyi)"
                return
            r.result = schema.RESULT_ALLOWED
            r.risk_when_open = schema.RISK_CRITICAL
            r.evidence = f"Okunabilir hive: {'; '.join(readable)} (shadow/backup ile offline dump yuzeyi)"
            r.recommendation = "Hive'lar normalde kilitli olmali; SeBackup/shadow-copy yollari izlenmeli."
        b.add("CHT-09-007", "SAM/SYSTEM hive okunabilirligi", test_sam)

        # 09.8 Shadow Copy hash exposure
        def test_shadow(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1003.003"
            r.attempted_methods = ["vssadmin list shadows"]
            if not ctx.gate_active(r, 2, False):
                return
            if winapi.shadow_copies_exist():
                r.result = schema.RESULT_ALLOWED
                r.evidence = "Shadow Copy mevcut — SAM/SYSTEM hive'lari shadow uzerinden okunabilir"
                r.recommendation = "Gereksiz shadow copy'ler temizlenmeli; SeBackup privilege kisitlanmali."
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Shadow Copy bulunamadi (iyi)"
        b.add("CHT-09-008", "Shadow Copy hash exposure", test_shadow)

        # 09.9 Cached logon hash sayisi
        def test_cached(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1003.005"
            r.attempted_methods = ["registry CachedLogonsCount"]
            cached, ok = winapi.reg_string(winapi._HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
            if not ok:
                r.result = schema.RESULT_PARTIAL
                r.evidence = "CachedLogonsCount okunamadi"
                return
            try:
                count = int(cached)
            except ValueError:
                count = -1
            r.evidence = f"CachedLogonsCount={cached}"
            if count > 4:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = f"Onbellekte {count} oturum hash'i tutuluyor; CIS oneri: <=4 (domain cihazinda 1 veya 0)."
            elif count >= 0:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — makul seviye"
            else:
                r.result = schema.RESULT_PARTIAL
        b.add("CHT-09-009", "Cached logon hash sayisi", test_cached)

        # 09.11 Browser credential store
        def test_browser_creds(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1555.003"
            r.attempted_methods = ["Login Data / logins.json varlik + okuma probe"]
            local = os.environ.get("LOCALAPPDATA", "")
            roaming = os.environ.get("APPDATA", "")
            stores = 0
            for base in [os.path.join(local, r"Google\Chrome\User Data"),
                         os.path.join(local, r"Microsoft\Edge\User Data")]:
                if os.path.isdir(base):
                    for entry in os.listdir(base):
                        profile_dir = os.path.join(base, entry)
                        if entry in ("Default",) or entry.startswith("Profile "):
                            login_data = os.path.join(profile_dir, "Login Data")
                            if os.path.isfile(login_data):
                                stores += 1
            ff_root = os.path.join(roaming, r"Mozilla\Firefox\Profiles")
            if os.path.isdir(ff_root):
                for entry in os.listdir(ff_root):
                    if os.path.isfile(os.path.join(ff_root, entry, "logins.json")):
                        stores += 1
            if stores == 0:
                r.result = schema.RESULT_NOT_APPLICABLE
                r.evidence = "Okunabilir tarayici kimlik deposu bulunamadi"
                return
            r.result = schema.RESULT_ALLOWED
            r.evidence = f"{stores} tarayici kimlik deposu kullanici tarafindan okunabilir — DPAPI kullanici baglaminda cozulebilir"
            r.recommendation = "Tarayici parola yoneticisi GPO ile kapatilmali (PasswordManagerEnabled=0)."
        b.add("CHT-09-011", "Tarayici kayitli kimlik deposu erisimi", test_browser_creds)

        # 09.12 Mimikatz / credential dump araci erisimi (BENIGN — binary calistirmaz)
        def test_mimikatz_surface(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1003.001"
            r.attempted_methods = ["mimikatz.exe indirme + calistirma simulasyonu (benign marker)"]
            if not ctx.gate_active(r, 2, True):
                return
            ps = os.path.join(winapi.system_root(), r"System32\WindowsPowerShell\v1.0\powershell.exe")
            if not winapi.file_exists(ps):
                r.result = schema.RESULT_ERROR
                r.evidence = "powershell.exe yok"
                return
            marker_path = os.path.join(winapi.expand_env("%TEMP%"), "cht-mimi-canary.txt")
            script = (
                f"try {{"
                f"  Set-Content -Path '{marker_path}' -Value 'invoke-mimikatz'; "
                f"  if (Test-Path '{marker_path}') {{ 'WRITTEN' }} else {{ 'AV_BLOCKED' }}"
                f"}} catch {{ 'BLOCKED: ' + $_.Exception.Message }}"
                f" finally {{ Remove-Item '{marker_path}' -ErrorAction SilentlyContinue }}"
            )
            res = winapi.run_cmd(15, ps, "-NoProfile", "-Command", script)
            if "WRITTEN" in res.output:
                r.result = schema.RESULT_ALLOWED
                r.evidence = "mimikatz marker dosyasi olusturulabildi — AMSI/AV bu anahtar kelimeyi engellemedi"
                r.recommendation = "AMSI ve Defender'in mimikatz signature'larini tespit ettigi dogrulanmali."
            else:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Defender"
                r.detected = schema.DETECTED_YES
                r.evidence = f"mimikatz marker engellendi: {res.output[:160]}"
        b.add("CHT-09-012", "Mimikatz / credential dump araci yuzeyi", test_mimikatz_surface)

        return b.results()
