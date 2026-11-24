"""CHtester — Windows Endpoint Hardening Assessment (Python edition).

Usage:
    python -m py.main [options]

Options:
    --passive-only       Yalniz pasif testler (varsayilan)
    --enable-active      Aktif testleri etkinlestir
    --enable-noisy       Gurultulu (N) testleri etkinlestir
    --out DIR            Cikti dizini (varsayilan: Results/)
    --open               Raporu bitince ac
    --budget SEC         Toplam calisma butcesi (sn)
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

from . import schema
from .harness import ConsoleLogger, RunContext, Runner
from .report.html_report import generate as generate_html
from . import winapi

from .modules.exec01 import Module01
from .modules.defender03 import Module03
from .modules.privilege04 import Module04
from .modules.network07 import Module07
from .modules.credential09 import Module09
from .modules.userlockdown14 import Module14
from .modules.malsite27 import Module27
from .modules.useraccount28 import Module28


def main():
    parser = argparse.ArgumentParser(description="CHtester — Windows Endpoint Hardening Assessment")
    parser.add_argument("--passive-only", action="store_true", default=True, help="Yalniz pasif testler")
    parser.add_argument("--enable-active", action="store_true", help="Aktif testleri etkinlestir")
    parser.add_argument("--enable-noisy", action="store_true", help="Gurultulu testleri etkinlestir")
    parser.add_argument("--out", default="Results", help="Cikti dizini")
    parser.add_argument("--open", action="store_true", help="Raporu bitince ac")
    parser.add_argument("--budget", type=int, default=0, help="Toplam calisma butcesi (sn)")
    args = parser.parse_args()

    log = ConsoleLogger()
    started = datetime.now(timezone.utc)

    log.logf("CHtester Python Edition v%s baslatiliyor...", schema.TOOL_VERSION)

    # Environment discovery
    env = winapi.discover()
    log.logf("DeviceId=%s Tier=%d (%s)", env.device_id, env.tier, env.tier_reason)
    log.logf("OS=%s Arch=%s Domain=%s EDR=%s", env.os_build, env.arch, env.domain_join, env.edr_detected)

    # Output directory
    hostname_safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in env.hostname)
    run_name = f"{hostname_safe}_{started.strftime('%Y%m%d_%H%M%S')}"
    out_dir = os.path.join(args.out, run_name)
    os.makedirs(out_dir, exist_ok=True)
    log.logf("Cikti dizini: %s", out_dir)

    # Flags
    passive_only = args.passive_only and not args.enable_active
    flags = schema.RunFlags(
        passive_only=passive_only,
        enable_noisy=args.enable_noisy,
    )

    # Context
    ctx = RunContext(
        profile=schema.PROFILE_AUDIT,
        tier=env.tier,
        device_id=env.device_id,
        flags=flags,
        log=log,
        budget=args.budget,
    )

    # Modules
    runner = Runner(ctx,
        Module01(),
        Module03(),
        Module04(),
        Module07(),
        Module09(),
        Module14(),
        Module27(),
        Module28(),
    )

    results = runner.run()

    # Report
    report = schema.Report(
        tier=env.tier,
        tier_reason=env.tier_reason,
        profile=schema.PROFILE_AUDIT,
        bootstrap_vector="chtester.py (primary)",
        os_build=env.os_build,
        arch=env.arch,
        domain_join=env.domain_join,
        intune_managed=env.intune_managed,
        edr_detected=env.edr_detected,
        device_id=env.device_id,
        hostname=env.hostname,
        started_at=started.isoformat(),
        finished_at=datetime.now(timezone.utc).isoformat(),
        flags=flags,
        results=results,
    )

    # Write JSON
    json_path = os.path.join(out_dir, "results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
    log.logf("JSON rapor: %s", json_path)

    # Write HTML
    html_path = os.path.join(out_dir, "report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html(report))
    log.logf("HTML rapor: %s", html_path)

    # Summary
    allowed = sum(1 for r in results if r.result == schema.RESULT_ALLOWED)
    blocked = sum(1 for r in results if r.result == schema.RESULT_BLOCKED)
    partial = sum(1 for r in results if r.result == schema.RESULT_PARTIAL)
    total = len(results)

    log.logf("")
    log.logf("=" * 60)
    log.logf("OZET: %d vektor | Izin=%d Engel=%d Kismi=%d", total, allowed, blocked, partial)
    log.logf("=" * 60)

    if args.open:
        subprocess.Popen(["cmd", "/c", "start", "", html_path], creationflags=subprocess.CREATE_NO_WINDOW)

    return 0


if __name__ == "__main__":
    sys.exit(main())
