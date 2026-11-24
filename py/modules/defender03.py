"""Module 03 — Defender / AV / EDR."""
from __future__ import annotations
import os, time
import winreg

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "03-Defender"

ASR_RULES = [
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Abuse of vulnerable signed drivers"),
    ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Adobe Reader child process"),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Office child process"),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Credential stealing from LSASS"),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Executable email/webmail content"),
    ("01443614-cd74-433a-b99e-2ecdc07bfc25", "Executable unless prevalence/age/trusted"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Obfuscated scripts"),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "JS/VBS launching downloaded content"),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Office creating executable content"),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Office code injection"),
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Office comm app child process"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Persistence via WMI event subscription"),
    ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Process creation from PSExec/WMI"),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Untrusted/unsigned processes from USB"),
    ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Win32 API from Office macro"),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", "Advanced ransomware protection"),
]

DEF_ROOT = r"SOFTWARE\Microsoft\Windows Defender"
POL_ROOT = r"SOFTWARE\Policies\Microsoft\Windows Defender"


class Module03:
    def id(self) -> str: return "03"
    def name(self) -> str: return "Defender / AV / EDR"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 03.1 RTP / Tamper / Cloud / PUA / NP / CFA
        def test_rtp(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1562.001"
            r.attempted_methods = ["registry Defender"]
            dis_rtp, _ = winapi.reg_dword(winapi._HKLM, DEF_ROOT + r"\Real-Time Protection", "DisableRealtimeMonitoring")
            tamper, t_ok = winapi.reg_dword(winapi._HKLM, DEF_ROOT + r"\Features", "TamperProtection")
            pua, _ = winapi.reg_dword(winapi._HKLM, DEF_ROOT, "PUAProtection")
            np, _ = winapi.reg_dword(winapi._HKLM, DEF_ROOT + r"\Windows Defender Exploit Guard\Network Protection", "EnableNetworkProtection")
            cfa, _ = winapi.reg_dword(winapi._HKLM, DEF_ROOT + r"\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess")
            tamper_label = "okunamadi(korumali olabilir)"
            if t_ok:
                tamper_label = "Acik(5)" if tamper == 5 else str(tamper)
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"RTP-disabled={dis_rtp}; Tamper={tamper_label}; PUA={pua}; NP={np}; CFA={cfa}"
            reg_text = winapi.reg_export_text(winapi._HKLM, DEF_ROOT + r"\Real-Time Protection")
            reg_text += "\n" + winapi.reg_export_text(winapi._HKLM, DEF_ROOT + r"\Features")
            ctx.save_poc(r, "defender_registry.txt", reg_text, "Defender registry degerleri", "registry")
            if dis_rtp == 1:
                r.result = schema.RESULT_ALLOWED
                r.risk_when_open = schema.RISK_CRITICAL
                r.recommendation = "Real-time protection KAPALI — kritik."
            elif tamper == 5:
                r.recommendation = "Tamper Protection acik (iyi). NP ve CFA da Block'a alinmali."
            else:
                r.recommendation = "Tamper Protection acik degil gorunuyor — etkinlestirilmeli."
        b.add("CHT-03-001", "Defender koruma durusu (RTP/Tamper/Cloud/PUA/NP/CFA)", test_rtp)

        # 03.2 ASR rules
        def test_asr(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping = schema.Mapping(asr_id="all-16", attack="T1562.001")
            r.attempted_methods = ["registry ASR\\Rules"]
            merged: dict[str, str] = {}
            for base in [POL_ROOT + r"\Windows Defender Exploit Guard\ASR\Rules",
                         DEF_ROOT + r"\Windows Defender Exploit Guard\ASR\Rules"]:
                vals = winapi.reg_string_values(winapi._HKLM, base)
                for k, v in vals.items():
                    merged[k.lower()] = v
            block = audit = warn = off = unset = 0
            not_configured = []
            for guid, name in ASR_RULES:
                st = merged.get(guid.lower())
                if st is None:
                    unset += 1
                    not_configured.append(name)
                elif st == "1":
                    block += 1
                elif st == "2":
                    audit += 1
                elif st == "6":
                    warn += 1
                else:
                    off += 1
            r.evidence = f"toplam={len(ASR_RULES)}; Block={block} Audit={audit} Warn={warn} Off={off} Yapilandirilmamis={unset}"
            if block >= len(ASR_RULES) - 2:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "ASR"
            elif block > 0:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = f"Eksik ASR kurallari Block'a alinmali: {', '.join(not_configured)[:200]}"
            else:
                r.result = schema.RESULT_ALLOWED
                r.risk_when_open = schema.RISK_HIGH
                r.recommendation = "Hicbir ASR kurali Block degil — 16 kural Block'a alinmali."
        b.add("CHT-03-002", "ASR kurallari durumu (per-GUID)", test_asr)

        # 03.4 Defender kapatma denemesi
        def test_disable_defender(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1562.001"
            r.attempted_methods = ["Set-MpPreference -DisableRealtimeMonitoring $true (+ geri al)"]
            if not ctx.gate_active(r, 2, False):
                return
            ps = os.path.join(winapi.system_root(), r"System32\WindowsPowerShell\v1.0\powershell.exe")
            if not winapi.file_exists(ps):
                r.result = schema.RESULT_ERROR
                r.evidence = "powershell.exe yok"
                return
            res = winapi.run_cmd(15, ps, "-NoProfile", "-Command",
                "try { Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop; 'CHANGED' } catch { 'BLOCKED: ' + $_.Exception.Message } finally { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue }")
            if "CHANGED" in res.output:
                r.result = schema.RESULT_ALLOWED
                r.risk_when_open = schema.RISK_CRITICAL
                r.evidence = "Defender RTP kapatilabildi (geri alindi) — Tamper Protection etkisiz!"
                r.recommendation = "Tamper Protection acilmali."
            else:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Defender"
                r.detected = schema.DETECTED_YES
                r.evidence = f"Kapatma engellendi: {res.output[:160]}"
        b.add("CHT-03-004", "Defender kapatma denemesi (Set-MpPreference)", test_disable_defender)

        # 03.5 Exclusion ekleme denemesi
        def test_exclusion(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1562.001"
            r.attempted_methods = ["Add-MpPreference -ExclusionPath (+ geri al)"]
            if not ctx.gate_active(r, 2, False):
                return
            ps = os.path.join(winapi.system_root(), r"System32\WindowsPowerShell\v1.0\powershell.exe")
            if not winapi.file_exists(ps):
                r.result = schema.RESULT_ERROR
                r.evidence = "powershell.exe yok"
                return
            excl = r"C:\cht-test-exclusion-canary"
            res = winapi.run_cmd(15, ps, "-NoProfile", "-Command",
                f"try {{ Add-MpPreference -ExclusionPath '{excl}' -ErrorAction Stop; 'ADDED' }} catch {{ 'BLOCKED: ' + $_.Exception.Message }} finally {{ Remove-MpPreference -ExclusionPath '{excl}' -ErrorAction SilentlyContinue }}")
            if "ADDED" in res.output:
                r.result = schema.RESULT_ALLOWED
                r.evidence = "Exclusion eklenebildi (geri alindi) — kullanici exclusion ekleyebiliyor!"
                r.recommendation = "Exclusion degisikligi standart kullaniciya kapatilmali."
            else:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Defender"
                r.evidence = f"Exclusion ekleme engellendi: {res.output[:160]}"
        b.add("CHT-03-005", "Defender exclusion ekleme denemesi", test_exclusion)

        # 03.6 AMSI
        def test_amsi(r: schema.Result):
            r.risk_when_open = schema.RISK_INFO
            r.attempted_methods = ["registry AMSI\\Providers", "amsi.dll varlik"]
            providers = winapi.reg_subkeys(winapi._HKLM, r"SOFTWARE\Microsoft\AMSI\Providers")
            amsi_dll = winapi.file_exists(os.path.join(winapi.system_root(), "System32", "amsi.dll"))
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"amsi.dll={amsi_dll}; kayitli provider={len(providers)}"
            if len(providers) == 0:
                r.risk_when_open = schema.RISK_MEDIUM
                r.recommendation = "Kayitli AMSI provider yok — script tarama zayif olabilir."
        b.add("CHT-03-006", "AMSI provider envanteri", test_amsi)

        # 03.11 Exclusion listesi okunabilir mi
        def test_exclusion_read(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1518.001"
            r.attempted_methods = ["registry Defender\\Exclusions"]
            paths = winapi.reg_value_names(winapi._HKLM, DEF_ROOT + r"\Exclusions\Paths")
            procs = winapi.reg_value_names(winapi._HKLM, DEF_ROOT + r"\Exclusions\Processes")
            exts = winapi.reg_value_names(winapi._HKLM, DEF_ROOT + r"\Exclusions\Extensions")
            if not paths and not procs and not exts:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Exclusion listesi standart kullaniciya okunamiyor (iyi)"
                return
            r.result = schema.RESULT_ALLOWED
            r.evidence = f"OKUNABILIR — path={len(paths)} process={len(procs)} ext={len(exts)}"
            r.recommendation = "Exclusion'lar standart kullanici tarafindan okunabiliyor; ACL gozden gecirilmeli."
        b.add("CHT-03-011", "Mevcut exclusion listesi okunabilirligi", test_exclusion_read)

        # 03.10 EICAR test
        def test_eicar(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1562.001"
            r.attempted_methods = ["EICAR runtime uretimi", "Temp'e yaz", "AV tepkisi gozlemle"]
            if not ctx.gate_active(r, 2, True):
                return
            parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}", "$EICAR",
                     "-STANDARD-ANTIVIRUS-TEST-FILE!", "$H+H*"]
            eicar = "".join(parts)
            path = os.path.join(winapi.expand_env("%TEMP%"), "cht-eicar.com")
            try:
                with open(path, "w") as f:
                    f.write(eicar)
                exists = os.path.isfile(path)
            except OSError as e:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Defender"
                r.detected = schema.DETECTED_YES
                r.evidence = f"EICAR yazilamadi — AV on-access engelledi: {e}"
                return
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass
            if not exists:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Defender"
                r.detected = schema.DETECTED_YES
                r.evidence = "EICAR yazildi ama aninda kaldirildi/karantina — AV tespit etti"
            else:
                r.result = schema.RESULT_ALLOWED
                r.detected = schema.DETECTED_NO
                r.risk_when_open = schema.RISK_HIGH
                r.evidence = "EICAR Temp'te kaldi, AV tepki vermedi — malware tespiti ZAYIF/kapali"
                r.recommendation = "Real-time protection ve on-access tarama dogrulanmali."
        b.add("CHT-03-010", "EICAR test dosyasi tespiti", test_eicar)

        return b.results()
