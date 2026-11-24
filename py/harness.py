"""Test harness — mirrors the Go harness package."""
from __future__ import annotations
import os, time, random, shutil, traceback
from typing import Protocol, Any, Optional
from datetime import datetime, timezone

from . import schema


class Logger(Protocol):
    def logf(self, fmt: str, *args: Any) -> None: ...


class ConsoleLogger:
    def logf(self, fmt: str, *args: Any) -> None:
        msg = fmt % args if args else fmt
        print(f"[chtester] {msg}")


class Module(Protocol):
    def id(self) -> str: ...
    def name(self) -> str: ...
    def run(self, ctx: "RunContext") -> list[schema.Result]: ...


class RunContext:
    def __init__(self, profile: str, tier: int, device_id: str,
                 flags: schema.RunFlags, log: Logger,
                 seed: int = 0, budget: float = 0,
                 poc_dir: str = ""):
        self.profile = profile
        self.tier = tier
        self.device_id = device_id
        self.flags = flags
        self.log = log
        self.rng = random.Random(seed or int(time.time()))
        self.budget = budget
        self.started_at = time.monotonic()
        self._used_ids: set[str] = set()
        self._stealth = profile == schema.PROFILE_STEALTH
        self.poc_dir = poc_dir
        if poc_dir:
            os.makedirs(poc_dir, exist_ok=True)

    def active_allowed(self) -> bool:
        return not self.flags.passive_only and not self.flags.what_if

    def noisy_allowed(self) -> bool:
        return self.flags.enable_noisy and self.active_allowed()

    def tier_ok(self, required: int) -> bool:
        return self.tier >= required

    def gate_active(self, r: schema.Result, tier_req: int, noisy: bool) -> bool:
        r.tier_required = tier_req
        if not self.tier_ok(tier_req):
            r.result = schema.RESULT_NOT_APPLICABLE
            r.skip_reason = schema.SKIP_TIER
            r.evidence = f"Bu vektor Tier >= {tier_req} ister; mevcut Tier yetersiz"
            return False
        if self.flags.what_if:
            r.result = schema.RESULT_NOT_APPLICABLE
            r.skip_reason = schema.SKIP_WHAT_IF
            r.evidence = "WhatIf: bu aktif vektor calistirilacakti"
            return False
        if noisy:
            if not self.noisy_allowed():
                r.result = schema.RESULT_NOT_APPLICABLE
                r.skip_reason = schema.SKIP_NOISE_GATE
                r.evidence = "Gurultulu [N] vektor; -EnableNoisy + gecerli scope gerekir"
                return False
            return True
        if not self.active_allowed():
            r.result = schema.RESULT_NOT_APPLICABLE
            r.skip_reason = schema.SKIP_PASSIVE_ONLY
            r.evidence = "Pasif mod; aktif test icin -PassiveOnly=false"
            return False
        return True

    def save_poc(self, r: schema.Result, filename: str, content: str,
                 description: str = "", artifact_type: str = "command_output") -> Optional[str]:
        if not self.poc_dir:
            return None
        safe_id = r.test_id.replace("/", "_").replace("\\", "_")
        dir_path = os.path.join(self.poc_dir, safe_id)
        os.makedirs(dir_path, exist_ok=True)
        path = os.path.join(dir_path, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError:
            return None
        rel = os.path.relpath(path, os.path.dirname(self.poc_dir))
        r.poc_artifacts.append(schema.PocArtifact(
            filename=rel, description=description, artifact_type=artifact_type))
        return rel

    def save_poc_binary(self, r: schema.Result, src_path: str, filename: str,
                        description: str = "", artifact_type: str = "file_copy") -> Optional[str]:
        if not self.poc_dir:
            return None
        safe_id = r.test_id.replace("/", "_").replace("\\", "_")
        dir_path = os.path.join(self.poc_dir, safe_id)
        os.makedirs(dir_path, exist_ok=True)
        dst = os.path.join(dir_path, filename)
        try:
            shutil.copy2(src_path, dst)
        except OSError:
            return None
        rel = os.path.relpath(dst, os.path.dirname(self.poc_dir))
        r.poc_artifacts.append(schema.PocArtifact(
            filename=rel, description=description, artifact_type=artifact_type))
        return rel

    def budget_exhausted(self) -> bool:
        if self.budget <= 0:
            return False
        return (time.monotonic() - self.started_at) >= self.budget

    def pace(self) -> None:
        if self._stealth:
            time.sleep(self.rng.uniform(0.8, 3.5))

    def new_result(self, test_id: str, category: str, name: str) -> schema.Result:
        if test_id in self._used_ids:
            self.log.logf("UYARI: tekrar eden Test-ID %s", test_id)
        self._used_ids.add(test_id)
        return schema.Result(
            test_id=test_id,
            category=category,
            name=name,
            device_id=self.device_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def finalize(self, r: schema.Result, start: float) -> None:
        r.duration_ms = int((time.monotonic() - start) * 1000)
        r.risk_score = risk_score(r)
        if self._stealth:
            if "no-marker" not in r.evasion_applied:
                r.evasion_applied.append("no-marker")
            if "timing" not in r.evasion_applied:
                r.evasion_applied.append("timing")


def risk_score(r: schema.Result) -> int:
    base = {
        schema.RISK_CRITICAL: 100, schema.RISK_HIGH: 80,
        schema.RISK_MEDIUM: 55, schema.RISK_LOW: 30, schema.RISK_INFO: 10,
    }.get(r.risk_when_open, 10)
    openness = {
        schema.RESULT_ALLOWED: 1.0,
        schema.RESULT_PARTIAL: 0.5,
    }.get(r.result, 0.0)
    det_mult = {
        schema.DETECTED_NO: 1.0,
        schema.DETECTED_YES: 0.6,
    }.get(r.detected, 0.85)
    return max(0, min(100, int(base * openness * det_mult + 0.5)))


class Builder:
    def __init__(self, ctx: RunContext, category: str):
        self.ctx = ctx
        self.cat = category
        self.out: list[schema.Result] = []

    def add(self, test_id: str, name: str, fn) -> None:
        start = time.monotonic()
        r = self.ctx.new_result(test_id, self.cat, name)
        try:
            fn(r)
        except Exception as exc:
            r.result = schema.RESULT_ERROR
            r.evidence = f"vektor hatasi (kurtarildi): {exc}"
            self.ctx.log.logf("[%s] vektor HATA kurtarildi: %s", test_id, traceback.format_exc())
        self.ctx.finalize(r, start)
        if r.result in (schema.RESULT_ALLOWED, schema.RESULT_PARTIAL) and r.evidence:
            self.ctx.save_poc(r, "evidence.txt", r.evidence, "Test kaniti", "evidence")
        self.out.append(r)
        self.ctx.pace()

    def results(self) -> list[schema.Result]:
        return self.out


class Runner:
    def __init__(self, ctx: RunContext, *modules: Module):
        self.ctx = ctx
        self.modules = list(modules)

    def run(self) -> list[schema.Result]:
        all_results: list[schema.Result] = []
        for m in self.modules:
            if self.ctx.budget_exhausted():
                self.ctx.log.logf("[%s] butce doldu, atlaniyor", m.id())
                r = self.ctx.new_result(f"CHT-{m.id()}-000", f"{m.id()}-{m.name()}", "Modul atlandi (butce)")
                r.result = schema.RESULT_ERROR
                r.skip_reason = schema.SKIP_BUDGET
                r.evidence = "Toplam calisma butcesi asildi"
                all_results.append(r)
                continue
            self.ctx.log.logf("[%s] %s calisiyor...", m.id(), m.name())
            try:
                res = m.run(self.ctx)
            except Exception as exc:
                self.ctx.log.logf("[%s] PANIK kurtarildi: %s", m.id(), exc)
                r = self.ctx.new_result(f"CHT-{m.id()}-PANIC", f"{m.id()}-{m.name()}", "Modul panigi (kurtarildi)")
                r.result = schema.RESULT_ERROR
                r.evidence = f"panik: {exc}"
                res = [r]
            self.ctx.log.logf("[%s] %d vektor sonucu", m.id(), len(res))
            all_results.extend(res)
        all_results.sort(key=lambda r: r.test_id)
        return all_results
