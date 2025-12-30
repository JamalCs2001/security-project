import requests
from config import VT_API_KEY, VT_BASE
from scanner.utils.helpers import safe_json, poll, vt_url_id


def vt_headers():
    return {"x-apikey": VT_API_KEY}


def vt_scan_url(url: str):
    submit = requests.post(
        f"{VT_BASE}/urls",
        headers=vt_headers(),
        data={"url": url},
        timeout=30,
    )
    if submit.status_code not in (200, 201):
        return {"ok": False, "step": "vt_submit_url", "status": submit.status_code, "body": safe_json(submit)}

    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        return {"ok": False, "step": "vt_missing_analysis_id", "status": submit.status_code, "body": submit.json()}

    def get_analysis():
        r = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=vt_headers(), timeout=30)
        return r.status_code, safe_json(r)

    status, analysis = poll(get_analysis, tries=12, delay=2)
    if status != 200:
        return {"ok": False, "step": "vt_poll_url", "status": status, "body": analysis}

    return {"ok": True, "analysis": analysis}


def vt_get_url_report(url: str):
    url_id = vt_url_id(url)
    r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=vt_headers(), timeout=30)
    if r.status_code != 200:
        return {"ok": False, "step": "vt_get_url_report", "status": r.status_code, "body": safe_json(r)}
    return {"ok": True, "report": safe_json(r), "url_id": url_id}


def vt_scan_file(file_storage):
    files = {"file": (file_storage.filename, file_storage.stream, file_storage.mimetype)}
    submit = requests.post(
        f"{VT_BASE}/files",
        headers=vt_headers(),
        files=files,
        timeout=60,
    )
    if submit.status_code not in (200, 201):
        return {"ok": False, "step": "vt_submit_file", "status": submit.status_code, "body": safe_json(submit)}

    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        return {"ok": False, "step": "vt_missing_analysis_id", "status": submit.status_code, "body": submit.json()}

    def get_analysis():
        r = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=vt_headers(), timeout=30)
        return r.status_code, safe_json(r)

    status, analysis = poll(get_analysis, tries=15, delay=2)
    if status != 200:
        return {"ok": False, "step": "vt_poll_file", "status": status, "body": analysis}

    return {"ok": True, "analysis": analysis}


def vt_get_file_report_by_hash(file_hash: str):
    r = requests.get(f"{VT_BASE}/files/{file_hash}", headers=vt_headers(), timeout=30)
    if r.status_code != 200:
        return {"ok": False, "step": "vt_get_file_report", "status": r.status_code, "body": safe_json(r)}
    return {"ok": True, "report": safe_json(r)}


def vt_poll_file_report(file_hash: str, tries=10, delay=2):
    def get_rep():
        r = requests.get(f"{VT_BASE}/files/{file_hash}", headers=vt_headers(), timeout=30)
        return r.status_code, safe_json(r)

    status, data = poll(get_rep, tries=tries, delay=delay)
    if status != 200:
        return {"ok": False, "step": "vt_poll_file_report", "status": status, "body": data}
    return {"ok": True, "report": data}
