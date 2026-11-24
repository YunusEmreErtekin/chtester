"""Module 27 — Zararli / Kumar / Yasadisi Site Erisim Kontrolu.

DNS resolution + HTTP(S) connect probe ile bilinen zararli / kumar /
yetiskin / dosya paylasim / anonymizer sitelerine erisim test edilir.
Gercek icerik indirilmez — yalniz DNS cozumleme + TCP 443 handshake.
"""
from __future__ import annotations
import socket
import ssl

from .. import schema
from ..harness import Builder, RunContext

CAT = "27-MaliciousSite"

GAMBLING_SITES = [
    "www.bet365.com",
    "www.bwin.com",
    "www.betfair.com",
    "www.williamhill.com",
    "www.888casino.com",
    "www.pokerstars.com",
    "www.unibet.com",
    "www.betway.com",
    "www.1xbet.com",
    "www.iddaa.com",
    "www.nesine.com",
    "www.bilyoner.com",
    "www.misli.com",
    "www.tuttur.com",
    "www.banko6.com",
]

MALICIOUS_TEST_SITES = [
    "www.internetbadguys.com",
    "urlhaus.abuse.ch",
]

ADULT_SITES = [
    "www.pornhub.com",
    "www.xvideos.com",
]

ANONYMIZER_SITES = [
    "www.torproject.org",
    "www.hidemyass.com",
    "www.hotspotshield.com",
]

FILE_SHARING_SITES = [
    "www.4shared.com",
    "www.mediafire.com",
    "mega.nz",
]


class Module27:
    def id(self) -> str: return "27"
    def name(self) -> str: return "Zararli / Kumar / Yasadisi Site Erisim Kontrolu"

    def run(self, ctx: RunContext) -> list[schema.Result]:
        b = Builder(ctx, CAT)

        # 27.1 Kumar siteleri (15+)
        def test_gambling(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.attempted_methods = ["DNS resolve + TCP 443 connect probe"]
            if not ctx.gate_active(r, 2, True):
                return
            reachable, blocked = _probe_sites(GAMBLING_SITES)
            r.evidence = f"Erisilebilir kumar sitesi: {len(reachable)}/{len(GAMBLING_SITES)} — {', '.join(reachable) if reachable else 'yok'}"
            if len(blocked) > 0:
                r.evidence += f"; Engellenen: {', '.join(blocked)}"
            if not reachable:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "DNS/Proxy"
                r.evidence += " — tum kumar siteleri engelli (iyi)"
            elif len(reachable) <= 3:
                r.result = schema.RESULT_PARTIAL
                r.recommendation = "Bazi kumar sitelerine erisilebiliyor; URL filtre genisletilmeli."
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = f"{len(reachable)} kumar sitesine erisilebiliyor — URL/DNS filtreleme uygulanmali."
        b.add("CHT-27-001", "Kumar sitelerine erisim kontrolu (15+ site)", test_gambling)

        # 27.2 Bilinen zararli test siteleri
        def test_malicious(r: schema.Result):
            r.risk_when_open = schema.RISK_HIGH
            r.mapping.attack = "T1071"
            r.attempted_methods = ["DNS resolve + TCP 443 connect probe"]
            if not ctx.gate_active(r, 2, True):
                return
            reachable, blocked = _probe_sites(MALICIOUS_TEST_SITES)
            r.evidence = f"Erisilebilir zararli test sitesi: {len(reachable)}/{len(MALICIOUS_TEST_SITES)}"
            if reachable:
                r.evidence += f" — {', '.join(reachable)}"
            if not reachable:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "DNS/Proxy"
            else:
                r.result = schema.RESULT_ALLOWED
                r.recommendation = "Bilinen zararli test sitelerine erisilebiliyor — web filtreleme degerlendirilmeli."
        b.add("CHT-27-002", "Bilinen zararli test sitelerine erisim", test_malicious)

        # 27.3 Yetiskin icerik siteleri
        def test_adult(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.attempted_methods = ["DNS resolve + TCP 443 connect probe"]
            if not ctx.gate_active(r, 2, True):
                return
            reachable, _ = _probe_sites(ADULT_SITES)
            if not reachable:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "DNS/Proxy"
                r.evidence = "Yetiskin icerik siteleri engelli (iyi)"
            else:
                r.result = schema.RESULT_ALLOWED
                r.evidence = f"Erisilebilir: {', '.join(reachable)}"
                r.recommendation = "Yetiskin icerik siteleri URL filtre ile engellenmeli."
        b.add("CHT-27-003", "Yetiskin icerik sitelerine erisim", test_adult)

        # 27.4 Anonymizer / VPN siteleri
        def test_anon(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1090.003"
            r.attempted_methods = ["DNS resolve + TCP 443 connect probe"]
            if not ctx.gate_active(r, 2, True):
                return
            reachable, _ = _probe_sites(ANONYMIZER_SITES)
            if not reachable:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "DNS/Proxy"
                r.evidence = "Anonymizer/VPN siteleri engelli (iyi)"
            else:
                r.result = schema.RESULT_ALLOWED
                r.evidence = f"Erisilebilir: {', '.join(reachable)}"
                r.recommendation = "Anonymizer/VPN indirme siteleri engellenmeli."
        b.add("CHT-27-004", "Anonymizer / VPN sitelerine erisim", test_anon)

        # 27.5 Dosya paylasim siteleri
        def test_fileshare(r: schema.Result):
            r.risk_when_open = schema.RISK_MEDIUM
            r.mapping.attack = "T1567"
            r.attempted_methods = ["DNS resolve + TCP 443 connect probe"]
            if not ctx.gate_active(r, 2, True):
                return
            reachable, _ = _probe_sites(FILE_SHARING_SITES)
            if not reachable:
                r.result = schema.RESULT_BLOCKED
                r.blocking_mechanism = "DNS/Proxy"
                r.evidence = "Dosya paylasim siteleri engelli (iyi)"
            else:
                r.result = schema.RESULT_ALLOWED
                r.evidence = f"Erisilebilir: {', '.join(reachable)}"
                r.recommendation = "Dosya paylasim siteleri URL filtre ile engellenmeli; DLP ile veri cikisi izlenmeli."
        b.add("CHT-27-005", "Dosya paylasim sitelerine erisim", test_fileshare)

        return b.results()


def _probe_sites(sites: list[str]) -> tuple[list[str], list[str]]:
    reachable = []
    blocked = []
    for site in sites:
        try:
            socket.getaddrinfo(site, 443, socket.AF_INET, socket.SOCK_STREAM)
            s = socket.create_connection((site, 443), timeout=3)
            s.close()
            reachable.append(site)
        except Exception:
            blocked.append(site)
    return reachable, blocked
