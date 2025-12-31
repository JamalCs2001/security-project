# scanner/utils/scoring.py

def score_from_stats(stats: dict) -> int:
    """
    VirusTotal stats -> percent for donut gauge (malicious + suspicious / total).
    """
    if not isinstance(stats, dict):
        return 0

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)

    total = 0
    for v in stats.values():
        try:
            total += int(v)
        except Exception:
            pass

    if total <= 0:
        return 0

    bad = malicious + suspicious
    pct = int(round((bad / total) * 100))
    return max(0, min(100, pct))


def urlscan_score_to_gauge(score) -> dict:
    """
    urlscan score (0..100) -> gauge dict for donut.
    """
    try:
        s = int(score or 0)
    except Exception:
        s = 0
    s = max(0, min(100, s))

    if s >= 80:
        level = "high"
        label = "High Risk"
    elif s >= 40:
        level = "medium"
        label = "Medium Risk"
    else:
        level = "low"
        label = "Low Risk"

    return {"percent": s, "level": level, "label": label}


# ---------------- IPQS (NEW) ----------------

def ipqs_risk_to_gauge(risk_score) -> dict:
    """
    IPQS URL risk_score is 0..100 (higher = worse).
    """
    try:
        s = int(risk_score or 0)
    except Exception:
        s = 0
    s = max(0, min(100, s))

    if s >= 85:
        level = "high"
        label = "High Risk"
    elif s >= 30:
        level = "medium"
        label = "Suspicious"
    else:
        level = "low"
        label = "Low Risk"

    return {"percent": s, "level": level, "label": f"{label} ({s}/100)"}


def ipqs_email_fraud_to_gauge(fraud_score) -> dict:
    """
    IPQS Email fraud_score is 0..100 (higher = worse).
    """
    try:
        s = int(fraud_score or 0)
    except Exception:
        s = 0
    s = max(0, min(100, s))

    if s >= 80:
        level = "high"
        label = "High Risk"
    elif s >= 40:
        level = "medium"
        label = "Medium Risk"
    else:
        level = "low"
        label = "Low Risk"

    return {"percent": s, "level": level, "label": f"{label} ({s}/100)"}
