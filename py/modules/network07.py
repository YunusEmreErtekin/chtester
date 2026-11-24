"""Module 07 — Ag Kontrolleri (Network)."""
from __future__ import annotations
import os, socket, winreg

from .. import schema
from ..harness import Builder, RunContext
from .. import winapi

CAT = "07-Network"
FW_BASE = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"


class Module07:
    def id(self) -> str: return "07"
    def name(self) -> str: return "Ag Kontrolleri"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 07.1 Firewall
        def test_fw(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.attempted_methods = ["registry FirewallPolicy"]
            profiles = {"DomainProfile": "Domain", "StandardProfile": "Private", "PublicProfile": "Public"}
            states = []
            all_on = True
            for key, label in profiles.items():
                en, _ = winapi.reg_dword(winapi._HKLM, FW_BASE + "\\" + key, "EnableFirewall")
                out_act, _ = winapi.reg_dword(winapi._HKLM, FW_BASE + "\\" + key, "DefaultOutboundAction")
                if en != 1:
                    all_on = False
                states.append(f"{label}:on={en},out={out_act}")
            r.evidence = " ".join(states)
            if all_on:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Tum profillerde firewall etkin olmali."
        b.add("CHT-07-001", "Firewall profil-bazli (Domain/Private/Public)", test_fw)

        # 07.4 Proxy
        def test_proxy(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1090"
            r.attempted_methods = ["registry Internet Settings"]
            enable, _ = winapi.reg_dword(winapi._HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable")
            server, _ = winapi.reg_string(winapi._HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer")
            r.result = schema.RESULT_PARTIAL
            r.evidence = f"ProxyEnable={enable}; ProxyServer={server!r}"
            r.recommendation = "Proxy ayarlari GPO ile kilitlenmeli."
        b.add("CHT-07-004", "Proxy ayari / bypass yuzeyi", test_proxy)

        # 07.7 Egress sweep
        def test_egress(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1048"
            r.attempted_methods = ["yaygin portlara TCP baglanti denemesi"]
            if not ctx.gate_active(r, 2, True):
                return
            targets = [
                ("443/HTTPS", "1.1.1.1", 443), ("80/HTTP", "1.1.1.1", 80),
                ("53/DNS-TCP", "1.1.1.1", 53), ("22/SSH", "github.com", 22),
                ("3389/RDP", "1.1.1.1", 3389), ("445/SMB", "1.1.1.1", 445),
                ("21/FTP", "1.1.1.1", 21), ("8443/alt", "1.1.1.1", 8443),
            ]
            opened = []
            blocked = []
            for label, host, port in targets:
                try:
                    s = socket.create_connection((host, port), timeout=2)
                    s.close()
                    opened.append(label)
                except Exception:
                    blocked.append(label)
            r.evidence = f"acik cikis: [{' '.join(opened)}]; engelli: [{' '.join(blocked)}]"
            if not opened:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
            elif len(opened) <= 2:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "Yalniz standart portlar acik; makul."
            else:
                r.result = schema.RESULT_ALLOWED
                r.risk_when_open = schema.RISK_HIGH
                r.recommendation = "Cok sayida cikis portu acik — egress filtreleme degerlendirilmeli."
        b.add("CHT-07-007", "Egress cok-portlu sweep", test_egress)

        # 07.13 DoH bypass
        def test_doh(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1572"
            r.attempted_methods = ["registry Edge/Chrome DnsOverHttpsMode"]
            edge, edge_ok = winapi.reg_string(winapi._HKLM, r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode")
            chrome, chrome_ok = winapi.reg_string(winapi._HKLM, r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode")
            edge_off = edge_ok and edge.lower() == "off"
            chrome_off = chrome_ok and chrome.lower() == "off"
            r.evidence = f"Edge DnsOverHttpsMode={edge!r}(set={edge_ok}) Chrome={chrome!r}(set={chrome_ok})"
            if edge_off and chrome_off:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "GPO"
                r.evidence += " — tarayici DoH politika ile kapatilmis"
            else:
                r.result = schema.RESULT_ALLOWED
                r.evidence += " — tarayici DoH 'off'a zorlanmamis"
                r.recommendation = "Edge/Chrome DnsOverHttpsMode=off ile zorlanmali; DoH uç noktalari engellenmeli."
        b.add("CHT-07-013", "DoH / DNS filtreleme baypas yuzeyi", test_doh)

        return b.results()
