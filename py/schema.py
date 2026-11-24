"""Result schema — mirrors the Go schema package."""
from __future__ import annotations
import dataclasses as dc
from typing import Optional

SCHEMA_VERSION = "1.0.0"
CATALOG_VERSION = "2.0.0-py"
TOOL_VERSION = "2.0.0-py"

PROFILE_AUDIT = "Audit"
PROFILE_STEALTH = "Stealth"

RESULT_ALLOWED = "Allowed"
RESULT_BLOCKED = "Blocked"
RESULT_PARTIAL = "Partial"
RESULT_ERROR = "Error"
RESULT_NOT_APPLICABLE = "NotApplicable"

RISK_CRITICAL = "Critical"
RISK_HIGH = "High"
RISK_MEDIUM = "Medium"
RISK_LOW = "Low"
RISK_INFO = "Info"

DETECTED_YES = "Yes"
DETECTED_NO = "No"
DETECTED_UNKNOWN = "Unknown"

SKIP_PASSIVE_ONLY = "PassiveOnly"
SKIP_NOISE_GATE = "NoiseGateClosed"
SKIP_TIER = "TierInsufficient"
SKIP_WHAT_IF = "WhatIf"
SKIP_BUDGET = "BudgetExhausted"
SKIP_NOT_APPLICABLE = "NotApplicableOS"
SKIP_NOT_IMPLEMENTED = "NotImplemented"
SKIP_TIMEOUT = "Timeout"

BLOCK_NONE = ""
BLOCK_UNKNOWN = "Unknown"

TELEMETRY_NONE = "None"


@dc.dataclass
class Mapping:
    cis: str = ""
    asr_id: str = ""
    attack: str = ""


@dc.dataclass
class RunFlags:
    passive_only: bool = True
    enable_noisy: bool = False
    skip_destructive: bool = False
    what_if: bool = False


@dc.dataclass
class Result:
    test_id: str = ""
    category: str = ""
    name: str = ""
    attempted_methods: list[str] = dc.field(default_factory=list)
    result: str = RESULT_NOT_APPLICABLE
    blocking_mechanism: str = BLOCK_NONE
    detected: str = DETECTED_UNKNOWN
    detection_evidence: list[str] = dc.field(default_factory=list)
    telemetry_weight: str = TELEMETRY_NONE
    evasion_applied: list[str] = dc.field(default_factory=list)
    risk_when_open: str = RISK_INFO
    risk_score: int = 0
    evidence: str = ""
    recommendation: str = ""
    skip_reason: str = ""
    tier_required: int = 0
    mapping: Mapping = dc.field(default_factory=Mapping)
    device_id: str = ""
    timestamp: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict:
        d = dc.asdict(self)
        d["mapping"] = dc.asdict(self.mapping)
        return d


@dc.dataclass
class Report:
    schema_version: str = SCHEMA_VERSION
    catalog_version: str = CATALOG_VERSION
    tool_version: str = TOOL_VERSION
    tier: int = 0
    tier_reason: str = ""
    profile: str = PROFILE_AUDIT
    bootstrap_vector: str = ""
    os_build: str = ""
    arch: str = ""
    domain_join: str = ""
    intune_managed: bool = False
    edr_detected: str = ""
    device_id: str = ""
    hostname: str = ""
    started_at: str = ""
    finished_at: str = ""
    flags: RunFlags = dc.field(default_factory=RunFlags)
    results: list[Result] = dc.field(default_factory=list)

    def to_dict(self) -> dict:
        d = dc.asdict(self)
        d["flags"] = dc.asdict(self.flags)
        d["results"] = [r.to_dict() for r in self.results]
        return d
