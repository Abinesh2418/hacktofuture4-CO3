"""Score calculation engine for red/blue team findings and fixes."""

from __future__ import annotations

from typing import Dict, List

# Points awarded per severity level
SEVERITY_POINTS: Dict[str, int] = {
    "critical": 100,
    "high": 50,
    "medium": 25,
    "low": 10,
}

# Multipliers – defense is harder so blue gets a bonus
RED_MULTIPLIER: float = 1.0
BLUE_MULTIPLIER: float = 1.2


def calc_red_points(findings: List[dict]) -> int:
    """Calculate total red-team points from a list of findings.

    Each finding dict should have a ``severity`` key (critical/high/medium/low).
    """
    total: float = 0.0
    for finding in findings:
        severity = finding.get("severity", "low").lower()
        base = SEVERITY_POINTS.get(severity, SEVERITY_POINTS["low"])
        total += base * RED_MULTIPLIER
    return int(total)


def calc_blue_points(fixes: List[dict]) -> int:
    """Calculate total blue-team points from a list of fixes.

    Each fix dict should have a ``severity`` key (critical/high/medium/low).
    """
    total: float = 0.0
    for fix in fixes:
        severity = fix.get("severity", "low").lower()
        base = SEVERITY_POINTS.get(severity, SEVERITY_POINTS["low"])
        total += base * BLUE_MULTIPLIER
    return int(total)
