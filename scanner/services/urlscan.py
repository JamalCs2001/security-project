import time
import requests
from config import URLSCAN_API_KEY, URLSCAN_BASE
from scanner.utils.helpers import safe_json


def urlscan_headers():
    return {
        "API-Key": URLSCAN_API_KEY,
        "api-key": URLSCAN_API_KEY,
        "Content-Type": "application/json",
    }


def urlscan_scan_url(url: str, visibility: str):
    allowed = {"public", "unlisted", "private"}
    if visibility not in allowed:
        visibility = "public"

    payload = {"url": url, "visibility": visibility}

    submit = requests.post(
        f"{URLSCAN_BASE}/scan/",
        headers=urlscan_headers(),
        json=payload,
        timeout=30,
    )

    if submit.status_code not in (200, 201):
        return {
            "ok": False,
            "step": "urlscan_submit",
            "status": submit.status_code,
            "body": safe_json(submit),
        }

    j = submit.json()
    uuid = j.get("uuid")
    result_link = j.get("result")

    if not uuid:
        return {"ok": False, "step": "urlscan_missing_uuid", "status": submit.status_code, "body": j}

    def get_result():
        r = requests.get(f"{URLSCAN_BASE}/result/{uuid}/", timeout=30)

        if r.status_code == 200:
            return 200, safe_json(r)

        if r.status_code == 404:
            return 404, {"message": "processing"}

        if r.status_code == 429:
            return 429, safe_json(r)

        return r.status_code, safe_json(r)

    tries = 20
    delay = 2
    last_status = None
    last_body = None

    for _ in range(tries):
        status, body = get_result()
        last_status, last_body = status, body

        if status == 200:
            # Build a small summary used by UI
            overall = (body.get("verdicts", {}) or {}).get("overall", {}) or {}
            summary = {
                "score": overall.get("score"),
                "malicious": overall.get("malicious"),
                "categories": overall.get("categories"),
            }
            return {"ok": True, "result": body, "result_link": result_link, "summary": summary}

        if status == 429:
            time.sleep(5)
            continue

        time.sleep(delay)

    return {
        "ok": False,
        "step": "urlscan_poll",
        "status": last_status,
        "body": last_body,
        "result_link": result_link,
    }
