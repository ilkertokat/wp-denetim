"""Bulgu ve rapor veri yapıları, puanlama."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return {0: "Bilgi", 1: "Düşük", 2: "Orta", 3: "Yüksek"}[self.value]

    @property
    def penalty(self) -> int:
        return {0: 0, 1: 4, 2: 10, 3: 22}[self.value]


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    detail: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class Report:
    url: str
    is_wordpress: bool = False
    wp_version: str | None = None
    plugins: dict[str, str | None] = field(default_factory=dict)
    theme: str | None = None
    findings: list[Finding] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def score(self) -> int:
        """100'den başlar, her bulgu önem derecesine göre puan düşürür."""
        return max(0, 100 - sum(f.severity.penalty for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -f.severity)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "score": self.score, "grade": self.grade,
            "is_wordpress": self.is_wordpress, "wp_version": self.wp_version,
            "theme": self.theme, "plugins": self.plugins, "passed": self.passed,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
