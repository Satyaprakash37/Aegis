"""Risk Prioritization Engine.

Calculates contextual vulnerability risk scores factoring in
CVSS base severity and asset criticality weighting per ARCHITECTURE.md specifications.
"""


def calculate_risk_score(cvss_score: float, asset_criticality: int) -> float:
    """Calculate contextual risk score combining CVSS severity and asset criticality.

    Formula:
        criticality_weight = (criticality / 5) * 10
        risk_score = round((cvss_score * 0.6) + (criticality_weight * 0.4), 2)
    """
    bounded_criticality = max(1, min(5, int(asset_criticality)))
    criticality_weight = (bounded_criticality / 5.0) * 10.0
    computed_score = (float(cvss_score) * 0.6) + (criticality_weight * 0.4)
    return round(computed_score, 2)


def get_risk_tier(risk_score: float) -> str:
    """Classify risk score into operational severity tier.

    Tiers:
        9.0 - 10.0 = CRITICAL
        7.0 - 8.9  = HIGH
        4.0 - 6.9  = MEDIUM
        0.1 - 3.9  = LOW
        0.0        = NONE
    """
    if risk_score >= 9.0:
        return "CRITICAL"
    elif risk_score >= 7.0:
        return "HIGH"
    elif risk_score >= 4.0:
        return "MEDIUM"
    elif risk_score > 0.0:
        return "LOW"
    return "NONE"
