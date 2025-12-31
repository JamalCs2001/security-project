# scanner/services/ipqs.py
import requests
from urllib.parse import quote_plus

try:
    # Your project already has config.py (not committed if it contains secrets)
    from config import IPQS_API_KEY
except Exception:
    IPQS_API_KEY = ""


IPQS_URL_ENDPOINT = "https://www.ipqualityscore.com/api/json/url/{key}/{value}"
IPQS_EMAIL_ENDPOINT = "https://ipqualityscore.com/api/json/email/{key}/{value}"


def ipqs_url_check(url: str, strictness: int = 0, timeout: int = 5, fast: bool = False) -> dict:
    """
    IPQS Malicious URL Scanner.
    Returns JSON with fields like: success, risk_score, phishing, malware, suspicious, unsafe, domain, final_url, request_id...
    """
    if not IPQS_API_KEY:
        return {"success": False, "message": "IPQS_API_KEY missing"}

    url = (url or "").strip()
    if not url:
        return {"success": False, "message": "No URL provided"}

    endpoint = IPQS_URL_ENDPOINT.format(key=IPQS_API_KEY, value=quote_plus(url))
    params = {
        "strictness": int(strictness),
        "timeout": int(timeout),
        "fast": "true" if fast else "false",
    }

    try:
        r = requests.get(endpoint, params=params, timeout=max(6, timeout + 4))
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"success": False, "message": f"IPQS URL error: {e}"}


def ipqs_email_check(email: str, timeout: int = 7, fast: bool = False, abuse_strictness: int = 0) -> dict:
    """
    IPQS Email Verification.
    Returns JSON with fields like: success, valid, disposable, fraud_score, recent_abuse, honeypot, catch_all, request_id...
    """
    if not IPQS_API_KEY:
        return {"success": False, "message": "IPQS_API_KEY missing"}

    email = (email or "").strip()
    if not email:
        return {"success": False, "message": "No email provided"}

    endpoint = IPQS_EMAIL_ENDPOINT.format(key=IPQS_API_KEY, value=quote_plus(email))
    params = {
        "timeout": int(timeout),
        "fast": "true" if fast else "false",
        "abuse_strictness": int(abuse_strictness),
    }

    try:
        r = requests.get(endpoint, params=params, timeout=max(6, timeout + 4))
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"success": False, "message": f"IPQS Email error: {e}"}
