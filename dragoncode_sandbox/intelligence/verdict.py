from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ThreatLevel(str, Enum):
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
    CRITICAL = "Critical"


@dataclass(slots=True)
class Verdict:
    score: int
    level: ThreatLevel
    confidence: float
    behavior_tags: list[str]
    explanation: list[str]


class VerdictEngine:
    def __init__(self) -> None:
        self._static_weight = 0.3
        self._dynamic_weight = 0.5
        self._network_weight = 0.2

    def calculate(
        self,
        static_score: int,
        dynamic_score: int,
        network_score: int,
        tags: list[str],
    ) -> Verdict:
        raw_score = (
            (static_score * self._static_weight)
            + (dynamic_score * self._dynamic_weight)
            + (network_score * self._network_weight)
        )
        final_score = int(min(raw_score, 100.0))

        if 0 <= final_score <= 20:
            level = ThreatLevel.BENIGN
        elif 21 <= final_score <= 50:
            level = ThreatLevel.SUSPICIOUS
        elif 51 <= final_score <= 85:
            level = ThreatLevel.MALICIOUS
        else:
            level = ThreatLevel.CRITICAL

        explanation: list[str] = []
        if static_score > 50:
            explanation.append(
                f"Static analysis detected anomalies (Score: {static_score})"
            )
        if dynamic_score > 50:
            explanation.append(
                f"Dynamic behavior is highly suspicious (Score: {dynamic_score})"
            )
        if network_score > 50:
            explanation.append(
                f"Network traffic indicates C2 activity (Score: {network_score})"
            )

        return Verdict(
            score=final_score,
            level=level,
            confidence=0.9,
            behavior_tags=list(tags),
            explanation=explanation,
        )
