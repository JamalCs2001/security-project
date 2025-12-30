import base64
import hashlib
import time


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {"text": resp.text[:2000]}


def poll(get_fn, tries=12, delay=2):
    last = (None, None)
    for _ in range(tries):
        last = get_fn()
        status, data = last

        if status == 200:
            vt_status = data.get("data", {}).get("attributes", {}).get("status")
            if vt_status is None or vt_status == "completed":
                return last

        time.sleep(delay)
    return last


def sha256_of_filestorage(file_storage) -> str:
    h = hashlib.sha256()
    file_storage.stream.seek(0)
    for chunk in iter(lambda: file_storage.stream.read(8192), b""):
        h.update(chunk)
    file_storage.stream.seek(0)
    return h.hexdigest()


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
