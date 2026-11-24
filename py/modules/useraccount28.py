"""Module 28 — Kullanici Hesap Yonetimi Kisitliligi.

Testler:
- Kullanici olusturma/silme yetenegi
- Gruba ekleme/cikarma yetenegi (Administrators, Remote Desktop Users vs.)
- Mevcut kullanici/grup envanteri
- Parola politikasi
- Hesap kilitleme politikasi
- Local admin grubunda kimler var
"""
from __future__ import annotations
import os

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "28-UserAccount"


class Module28:
    def id(self) -> str: return "28"
    def name(self) -> str: return "Kullanici Hesap Yonetimi Kisitliligi"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 28.1 Local admin grubu uyeleri
        def test_admin_members(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1078.003"
            r.attempted_methods = ["net localgroup Administrators"]
            members = winapi.group_members("Administrators")
            if not members:
                alt_members = winapi.group_members("Yoneticiler")
                if alt_members:
                    members = alt_members
            r.evidence = f"Administrators grubu uyeleri ({len(members)}): {', '.join(members) if members else 'okunamadi'}"
            if len(members) > 2:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = f"Administrators grubunda {len(members)} uye var; en az yetki prensibi icin yalniz gerekli hesaplar tutulmali."
            elif members:
                r.result = schema.RESULT_BLOCKED
                r.evidence += " — makul sayida admin"
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence += " — grup okunamadi (dil farki olabilir)"
        b.add("CHT-28-001", "Local admin grubu uyeleri", test_admin_members)

        # 28.2–28.4 Kullanici olusturma / silme / gruba ekleme (tek test kullanicisi)
        _acct_test_user = "cht-test-usr"
        _acct_test_pass = "CHTt3st!Pwd#2024"
        _acct_created = False

        def test_create_user(r: schema.Result):
            nonlocal _acct_created
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1136.001"
            r.attempted_methods = ["net user cht-test-usr /add"]
            if not ctx.gate_active(r, 2, False):
                return
            res = winapi.try_create_user(_acct_test_user, _acct_test_pass)
            if res.exit_code == 0:
                _acct_created = True
                r.result = schema.RESULT_ALLOWED
                r.evidence = f"Kullanici '{_acct_test_user}' OLUSTURULABILDI — kullanici olusturma kisitli degil!"
                r.recommendation = "Standart kullanicinin hesap olusturma yetkisi olmamali."
            else:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Permission"
                r.evidence = f"Kullanici olusturulamadi (iyi): {res.output[:160]}"
        b.add("CHT-28-002", "Kullanici olusturma yetenegi", test_create_user)

        def test_group_add(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1098"
            r.attempted_methods = ["net localgroup Administrators cht-test-usr /add"]
            if not ctx.gate_active(r, 2, False):
                return
            if not _acct_created:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Permission"
                r.evidence = "Test kullanicisi olusturulamadi — gruba ekleme testi yapilamadi (iyi)"
                return
            add_res = winapi.try_add_to_group(_acct_test_user, "Administrators")
            if add_res.exit_code != 0:
                add_res = winapi.try_add_to_group(_acct_test_user, "Yoneticiler")
            if add_res.exit_code == 0:
                winapi.try_remove_from_group(_acct_test_user, "Administrators")
                winapi.try_remove_from_group(_acct_test_user, "Yoneticiler")
                r.result = schema.RESULT_ALLOWED
                r.evidence = "Kullanici Administrators grubuna EKLENABILDI (geri alindi) — privesc yuzeyi!"
                r.recommendation = "Standart kullanicinin gruba ekleme yetkisi olmamali."
            else:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Permission"
                r.evidence = f"Gruba ekleme engellendi (iyi): {add_res.output[:160]}"
        b.add("CHT-28-004", "Administrators grubuna ekleme yetenegi", test_group_add)

        def test_delete_user(r: schema.Result):
            r.risk_when_open = schema.RISK_CRITICAL
            r.mapping.attack = "T1531"
            r.attempted_methods = ["net user cht-test-usr /delete"]
            if not ctx.gate_active(r, 2, False):
                return
            if not _acct_created:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "Permission"
                r.evidence = "Kullanici olusturulamadigi icin silme testi yapilamadi (iyi — yetki kisitli)"
                return
            del_res = winapi.try_delete_user(_acct_test_user)
            if del_res.exit_code == 0:
                r.result = schema.RESULT_ALLOWED
                r.evidence = "Kullanici olusturulup SILINEBILDI — tam hesap yonetimi yetkisi var"
                r.recommendation = "Standart kullanicinin hesap silme yetkisi olmamali."
            else:
                r.result = schema.RESULT_PARTIAL
                r.evidence = "Kullanici olusturulabildi ama silinemedi"
                winapi.try_delete_user(_acct_test_user)
        b.add("CHT-28-003", "Kullanici silme yetenegi", test_delete_user)

        # 28.5 Mevcut kullanici envanteri
        def test_user_inventory(r: schema.Result):
            r.risk_when_open = schema.RISK_INFO
            r.attempted_methods = ["net user"]
            users = winapi.list_local_users()
            r.evidence = f"Yerel kullanicilar ({len(users)}): {', '.join(users) if users else 'okunamadi'}"
            r.result = schema.RESULT_PARTIAL
            default_suspicious = ["Guest", "DefaultAccount", "WDAGUtilityAccount"]
            enabled_suspect = [u for u in users if u in default_suspicious]
            if enabled_suspect:
                r.recommendation = f"Varsayilan hesaplar ({', '.join(enabled_suspect)}) devre disi birakilmali."
        b.add("CHT-28-005", "Mevcut kullanici envanteri", test_user_inventory)

        # 28.6 Mevcut grup envanteri
        def test_group_inventory(r: schema.Result):
            r.risk_when_open = schema.RISK_INFO
            r.attempted_methods = ["net localgroup"]
            groups = winapi.list_local_groups()
            r.evidence = f"Yerel gruplar ({len(groups)}): {', '.join(groups[:20]) if groups else 'okunamadi'}"
            r.result = schema.RESULT_PARTIAL
            sensitive = ["Administrators", "Remote Desktop Users", "Yoneticiler", "Uzak Masaustu Kullanicilari"]
            for g in groups:
                if g in sensitive:
                    members = winapi.group_members(g)
                    if members:
                        r.evidence += f"; {g} uyeleri: {', '.join(members)}"
        b.add("CHT-28-006", "Mevcut grup envanteri + hassas grup uyeleri", test_group_inventory)

        # 28.7 Parola politikasi
        def test_pwd_policy(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping = schema.Mapping(cis="Password Policy", attack="T1110")
            r.attempted_methods = ["net accounts"]
            res = winapi.run_cmd(10, "net", "accounts")
            r.evidence = res.output[:300] if res.output else "net accounts ciktisi alinamadi"
            if "0" in res.output and ("Minimum password length" in res.output or "Minimum parola" in res.output):
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Parola politikasi gozden gecirilmeli; minimum uzunluk 14+ karakter olmali."
            else:
                r.result = schema.RESULT_PARTIAL
        b.add("CHT-28-007", "Parola politikasi (net accounts)", test_pwd_policy)

        # 28.8 Hesap kilitleme politikasi
        def test_lockout(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping = schema.Mapping(cis="Account Lockout", attack="T1110")
            r.attempted_methods = ["net accounts"]
            res = winapi.run_cmd(10, "net", "accounts")
            r.evidence = res.output[:300] if res.output else "net accounts ciktisi alinamadi"
            if "Never" in res.output or "Hicbir zaman" in res.output:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Hesap kilitleme esigi ayarlanmamis — sinirsiz brute-force mumkun."
            else:
                r.result = schema.RESULT_PARTIAL
        b.add("CHT-28-008", "Hesap kilitleme politikasi", test_lockout)

        # 28.9 Remote Desktop Users grubu
        def test_rdp_users(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1021.001"
            r.attempted_methods = ["net localgroup 'Remote Desktop Users'"]
            members = winapi.group_members("Remote Desktop Users")
            if not members:
                members = winapi.group_members("Uzak Masaustu Kullanicilari")
            if not members:
                r.result = schema.RESULT_BLOCKED
                r.evidence = "Remote Desktop Users grubunda uye yok (iyi)"
                return
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"Remote Desktop Users uyeleri: {', '.join(members)}"
            r.recommendation = "RDP erisimi gerektirmeyen kullanicilar gruptan cikarilmali."
        b.add("CHT-28-009", "Remote Desktop Users grubu", test_rdp_users)

        return b.results()
