"""Module 08 — Yama Yonetimi (Patch Management)."""
from __future__ import annotations
import os
from datetime import datetime, timezone

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "08-Patch"


class Module08:
    def id(self) -> str: return "08"
    def name(self) -> str: return "Yama Yonetimi"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 08.1 Son guncelleme tarihi
        def test_last_update(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping = schema.Mapping(cis="Patch Management", attack="T1190")
            r.attempted_methods = ["wmic qfe list brief", "registry AU"]
            res = winapi.run_cmd(15, "wmic", "qfe", "list", "brief", "/format:table")
            ctx.save_poc(r, "installed_hotfixes.txt", res.output, "Yuklu hotfix listesi", "command_output")
            if res.exit_code != 0 or not res.output.strip():
                r.result = schema.RESULT_PARTIAL
                r.evidence = "Hotfix listesi alinamadi"
                return
            dates = []
            for line in res.output.splitlines():
                parts = line.split()
                for p in parts:
                    for fmt in ("%m/%d/%Y", "%d.%m.%Y", "%Y-%m-%d"):
                        try:
                            dates.append(datetime.strptime(p, fmt))
                            break
                        except ValueError:
                            continue
            if not dates:
                r.result = schema.RESULT_PARTIAL
                r.evidence = "Hotfix tarihleri ayriştirilamadi"
                return
            latest = max(dates)
            days_ago = (datetime.now() - latest).days
            count = len(set(dates))
            r.evidence = f"Son hotfix: {latest.strftime('%Y-%m-%d')} ({days_ago} gun once); toplam {count} farkli tarih"
            if days_ago > 90:
                r.result = schema.RESULT_ALLOWED
                r.risk_when_open = schema.RISK_CRITICAL
                r.recommendation = f"Son yama {days_ago} gun once — 90+ gun yamamisiz cihaz kritik risk."
            elif days_ago > 30:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = f"Son yama {days_ago} gun once; aylik yama dongusu gecmis olabilir."
            else:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — guncel"
        b.add("CHT-08-001", "Son guncelleme tarihi", test_last_update)

        # 08.2 Windows Update ayarlari
        def test_wu_settings(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1190"
            r.attempted_methods = ["registry WindowsUpdate\\AU"]
            path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            au_opt, ok = winapi.reg_dword(winapi._HKLM, path, "AUOptions")
            no_auto, _ = winapi.reg_dword(winapi._HKLM, path, "NoAutoUpdate")
            reg_text = winapi.reg_export_text(winapi._HKLM, path)
            reg_text += "\n" + winapi.reg_export_text(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")
            ctx.save_poc(r, "wu_registry.txt", reg_text, "Windows Update registry", "registry")
            au_label = {1: "Devre disi", 2: "Bildirim", 3: "Otomatik indir", 4: "Otomatik kur"}.get(au_opt, "Bilinmiyor")
            r.evidence = f"AUOptions={au_opt}({au_label})(set={ok}); NoAutoUpdate={no_auto}"
            if no_auto == 1:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Otomatik guncelleme KAPALI — kritik."
            elif au_opt == 4:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — otomatik kurulum"
            elif ok:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "Windows Update otomatik kuruluma (AUOptions=4) ayarlanmali."
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — GPO ile yapilandirilmamis"
        b.add("CHT-08-002", "Windows Update ayarlari (GPO)", test_wu_settings)

        # 08.3 WSUS endpoint
        def test_wsus(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1557"
            r.attempted_methods = ["registry WUServer"]
            wu_server, ok = winapi.reg_string(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer")
            wu_status, _ = winapi.reg_string(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUStatusServer")
            use_wu, _ = winapi.reg_dword(winapi._HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "UseWUServer")
            r.evidence = f"WUServer={wu_server!r}(set={ok}); WUStatusServer={wu_status!r}; UseWUServer={use_wu}"
            if ok and wu_server:
                if wu_server.startswith("http://"):
                    r.result = schema.RESULT_ALLOWED
                    r.recommendation = "WSUS HTTP uzerinden — MITM riski; HTTPS kullanilmali."
                else:
                    r.result = schema.RESULT_BLOCKED
                    r.evidence += " — WSUS HTTPS ile yapilandirilmis"
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — WSUS yapilandirilmamis (dogrudan WU)"
        b.add("CHT-08-003", "WSUS yapilandirmasi", test_wsus)

        return b.results()
