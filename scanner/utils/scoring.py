def score_from_stats(stats: dict):
    stats = stats or {}
    detected = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
    percent = round((detected / total) * 100, 1) if total > 0 else 0.0
    return {"detected": detected, "total": total, "percent": percent}


def urlscan_score_to_gauge(score):
    """
    urlscan overall score can be negative/positive.
    Map -100..+100 => 0..100%
    """
    try:
        s = float(score)
    except Exception:
        s = 0.0

    if s < -100:
        s = -100.0
    if s > 100:
        s = 100.0

    percent = round(((s + 100.0) / 200.0) * 100.0, 1)
    return {"score": s, "percent": percent}
