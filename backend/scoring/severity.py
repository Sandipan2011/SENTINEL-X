SEVERITY_WEIGHTS = {
    "INFO": 0.10,
    "LOW": 0.30,
    "MEDIUM": 0.55,
    "HIGH": 0.80,
    "CRITICAL": 1.00,
}


def severity_weight(severity: str) -> float:
    """
    Convert severity into a normalized numerical weight.
    """

    return SEVERITY_WEIGHTS.get(
        severity.upper(),
        0.0,
    )


def calculate_risk_score(
    confidence: float,
    severity: str,
) -> float:
    """
    Calculate a normalized 0-100 risk score.
    """

    confidence = max(
        0.0,
        min(1.0, confidence),
    )

    weight = severity_weight(
        severity
    )

    score = (
        confidence
        * weight
        * 100
    )

    return round(
        score,
        2,
    )