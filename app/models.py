from enum import Enum
from dataclasses import dataclass, field


class Severity(str, Enum):
    CRITICAL = "kritik"
    HIGH = "yuqori"
    MEDIUM = "o'rta"
    LOW = "past"
    INFO = "ma'lumot"

    @property
    def score(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]


SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: str
    recommendation: str = ""


@dataclass
class ScanResult:
    domain: str
    url: str
    findings: list[Finding] = field(default_factory=list)
    scan_duration_ms: int = 0
    error: str | None = None
    target_type: str = "domain"
    raw_input: str = ""

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        total = sum(f.severity.score for f in self.findings)
        max_possible = len(self.findings) * Severity.CRITICAL.score
        return round((total / max_possible) * 100, 1)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 80:
            return "Juda yuqori xavf"
        if score >= 60:
            return "Yuqori xavf"
        if score >= 40:
            return "O'rta xavf"
        if score >= 20:
            return "Past xavf"
        return "Minimal xavf"

    def by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {s.value: [] for s in SEVERITY_ORDER}
        for f in self.findings:
            grouped[f.severity.value].append(f)
        return grouped
