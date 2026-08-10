"""Core data model shared by every check, the engine, and all report formats."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum


class Severity(IntEnum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class Finding:
    check_id: str
    title: str
    service: str
    severity: Severity
    status: Status
    resource_id: str
    region: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    error_code: str | None = None
    account_id: str | None = None
    cis_benchmarks: list[str] = field(default_factory=list)
    cis_benchmark_version: str = "3.0.0"
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["severity"] = self.severity.name
        d["status"] = self.status.value
        d["scanned_at"] = self.scanned_at.isoformat()
        return d


@dataclass
class CheckMeta:
    check_id: str
    title: str
    service: str
    severity: Severity
    description: str
    remediation: str
    references: list[str]
    required_actions: list[str]
    scope: str  # "account" | "region"
    cis_benchmarks: list[str]  # CIS AWS Foundations Benchmark v3.0.0 control IDs, or [] if no clean match

    def __post_init__(self):
        if self.scope not in ("account", "region"):
            raise ValueError(f"{self.check_id}: scope must be 'account' or 'region', got {self.scope!r}")
