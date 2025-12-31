import requests
from flask import Blueprint, render_template, request

from config import VT_API_KEY, URLSCAN_API_KEY, IPQS_API_KEY

from scanner.utils.helpers import sha256_of_filestorage, vt_url_id
from scanner.utils.scoring import (
    score_from_stats,
    urlscan_score_to_gauge,
    ipqs_risk_to_gauge,
    ipqs_email_fraud_to_gauge,
)

from scanner.services.virustotal import (
    vt_scan_url,
    vt_get_url_report,
    vt_scan_file,
    vt_get_file_report_by_hash,
    vt_poll_file_report,
)

from scanner.services.urlscan import urlscan_scan_url
from scanner.services.ipqs import ipqs_url_check, ipqs_email_check

bp = Blueprint("scanner", __name__)


def _vt_detected_total(stats: dict):
    if not isinstance(stats, dict):
        return 0, 0
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    detected = malicious + suspicious

    total = 0
    for v in stats.values():
        try:
            total += int(v)
        except Exception:
            pass
    return detected, total


@bp.get("/")
def upload_page():
    messages = []
    if not VT_API_KEY:
        messages.append("Missing VT_API_KEY (VirusTotal scans will not work).")
    if not URLSCAN_API_KEY:
        messages.append("Missing URLSCAN_API_KEY (urlscan.io scans will not work).")
    if not IPQS_API_KEY:
        messages.append("Missing IPQS_API_KEY (IPQS URL/Email will not work).")

    return render_template("upload.html", messages=messages, results={})


@bp.get("/test-urlscan")
def test_urlscan():
    r = requests.get(
        "https://urlscan.io/user/quotas/",
        headers={"API-Key": URLSCAN_API_KEY, "api-key": URLSCAN_API_KEY},
        timeout=30,
    )
    return (r.text, r.status_code, {"Content-Type": "text/plain"})


@bp.post("/scan")
def scan():
    messages = []
    results = {}

    if not VT_API_KEY:
        messages.append("Missing VT_API_KEY (VirusTotal scans will not work).")
    if not URLSCAN_API_KEY:
        messages.append("Missing URLSCAN_API_KEY (urlscan.io scans will not work).")
    if not IPQS_API_KEY:
        messages.append("Missing IPQS_API_KEY (IPQS URL/Email will not work).")

    action = request.form.get("action")

    # ================= URL =================
    if action == "scan_url":
        url = (request.form.get("url") or "").strip()
        visibility = request.form.get("visibility") or "public"

        if not url:
            messages.append("Please enter a URL.")
            return render_template("upload.html", messages=messages, results={})

        results["input_type"] = "url"
        results["input_value"] = url

        # -------- VirusTotal URL --------
        if VT_API_KEY:
            vt = vt_scan_url(url)
            results["vt_url"] = vt
            results["vt_url_link"] = f"https://www.virustotal.com/gui/url/{vt_url_id(url)}"

            rep = vt_get_url_report(url)
            results["vt_url_report"] = rep
            if rep.get("ok"):
                attrs = rep["report"].get("data", {}).get("attributes", {}) or {}
                stats = attrs.get("last_analysis_stats", {}) or {}
                reputation = attrs.get("reputation")

                results["vt_url_stats"] = stats
                results["vt_url_reputation"] = reputation

                percent = score_from_stats(stats)  # int in your project
                detected, total = _vt_detected_total(stats)

                results["vt_url_detected"] = detected
                results["vt_url_total"] = total
                results["vt_url_percent"] = percent

        # -------- urlscan.io --------
        if URLSCAN_API_KEY:
            us = urlscan_scan_url(url, visibility)
            results["urlscan"] = us

            if us.get("ok"):
                summary = us.get("summary", {}) or {}
                results["urlscan_summary"] = summary

                # summary score might be missing; default to 0
                score_value = summary.get("score", 0)

                g = urlscan_score_to_gauge(score_value)

                # YOUR urlscan_score_to_gauge likely returns: percent/label/level
                results["urlscan_gauge_percent"] = g.get("percent", 0)
                results["urlscan_gauge_label"] = g.get("label")
                results["urlscan_gauge_level"] = g.get("level")

            else:
                results["urlscan_error"] = us.get("error") or us.get("message") or "urlscan failed"

        # -------- IPQS URL --------
        if IPQS_API_KEY:
            iq = ipqs_url_check(url)
            results["ipqs_url"] = iq

            if iq.get("success") is True:
                results["ipqs_url_risk_score"] = iq.get("risk_score")
                results["ipqs_url_flags"] = {
                    "unsafe": iq.get("unsafe"),
                    "phishing": iq.get("phishing"),
                    "malware": iq.get("malware"),
                    "suspicious": iq.get("suspicious"),
                }
                results["ipqs_url_domain"] = iq.get("domain")
                results["ipqs_url_final_url"] = iq.get("final_url")
                results["ipqs_url_request_id"] = iq.get("request_id")

                g = ipqs_risk_to_gauge(iq.get("risk_score"))
                results["ipqs_url_gauge_percent"] = g["percent"]
                results["ipqs_url_gauge_label"] = g["label"]
            else:
                results["ipqs_url_error"] = iq.get("message") or "IPQS URL check failed"

        return render_template("result.html", messages=messages, results=results)

    # ================= EMAIL =================
    if action == "scan_email":
        email = (request.form.get("email") or "").strip()

        if not email:
            messages.append("Please enter an email.")
            return render_template("upload.html", messages=messages, results={})

        results["input_type"] = "email"
        results["input_value"] = email

        if IPQS_API_KEY:
            er = ipqs_email_check(email)
            results["ipqs_email"] = er

            if er.get("success") is True:
                results["ipqs_email_fraud_score"] = er.get("fraud_score")
                results["ipqs_email_valid"] = er.get("valid")
                results["ipqs_email_disposable"] = er.get("disposable")
                results["ipqs_email_catch_all"] = er.get("catch_all")
                results["ipqs_email_honeypot"] = er.get("honeypot")
                results["ipqs_email_recent_abuse"] = er.get("recent_abuse")
                results["ipqs_email_request_id"] = er.get("request_id")

                g = ipqs_email_fraud_to_gauge(er.get("fraud_score"))
                results["ipqs_email_gauge_percent"] = g.get("percent", 0)
                results["ipqs_email_gauge_label"] = g.get("label")
                results["ipqs_email_gauge_level"] = g.get("level")
            else:
                results["ipqs_email_error"] = er.get("message") or "IPQS Email check failed"

        return render_template("result.html", messages=messages, results=results)

    # ================= FILE / HASH =================
    if action == "scan_file":
        f = request.files.get("file")
        file_hash = (request.form.get("file_hash") or "").strip().lower()

        has_file = bool(f and f.filename)
        has_hash = bool(file_hash)

        if not has_file and not has_hash:
            messages.append("Please upload a file OR enter a hash value.")
            return render_template("upload.html", messages=messages, results={})

        if has_file and has_hash:
            messages.append("Please choose only ONE: upload a file OR enter a hash (not both).")
            return render_template("upload.html", messages=messages, results={})

        # -------- Upload file --------
        if has_file:
            results["input_type"] = "file"
            results["input_value"] = f.filename

            sha256 = sha256_of_filestorage(f)
            results["file_sha256"] = sha256
            results["vt_file_link"] = f"https://www.virustotal.com/gui/file/{sha256}"

            if VT_API_KEY:
                vt = vt_scan_file(f)
                results["vt_file"] = vt

                rep = vt_poll_file_report(sha256, tries=10, delay=2)
                results["vt_file_report"] = rep
                if rep.get("ok"):
                    attrs = rep["report"].get("data", {}).get("attributes", {}) or {}
                    stats = attrs.get("last_analysis_stats", {}) or {}
                    reputation = attrs.get("reputation")

                    results["vt_file_stats"] = stats
                    results["vt_file_reputation"] = reputation

                    percent = score_from_stats(stats)
                    detected, total = _vt_detected_total(stats)

                    results["vt_file_detected"] = detected
                    results["vt_file_total"] = total
                    results["vt_file_percent"] = percent

            return render_template("result.html", messages=messages, results=results)

        # -------- Hash lookup --------
        results["input_type"] = "hash"
        results["input_value"] = file_hash
        results["file_hash_provided"] = file_hash
        results["vt_file_link"] = f"https://www.virustotal.com/gui/file/{file_hash}"

        if VT_API_KEY:
            rep = vt_get_file_report_by_hash(file_hash)
            results["vt_file_report"] = rep

            if rep.get("ok"):
                attrs = rep["report"].get("data", {}).get("attributes", {}) or {}
                stats = attrs.get("last_analysis_stats", {}) or {}
                reputation = attrs.get("reputation")

                results["vt_file_stats"] = stats
                results["vt_file_reputation"] = reputation

                percent = score_from_stats(stats)
                detected, total = _vt_detected_total(stats)

                results["vt_file_detected"] = detected
                results["vt_file_total"] = total
                results["vt_file_percent"] = percent

        return render_template("result.html", messages=messages, results=results)

    messages.append("Unknown action.")
    return render_template("upload.html", messages=messages, results=results)
