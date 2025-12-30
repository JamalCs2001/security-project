import requests
from flask import Blueprint, render_template, request

from config import VT_API_KEY, URLSCAN_API_KEY

from scanner.utils.helpers import sha256_of_filestorage, vt_url_id
from scanner.utils.scoring import score_from_stats, urlscan_score_to_gauge

from scanner.services.virustotal import (
    vt_scan_url,
    vt_get_url_report,
    vt_scan_file,
    vt_get_file_report_by_hash,
    vt_poll_file_report,
)

from scanner.services.urlscan import urlscan_scan_url


bp = Blueprint("scanner", __name__)


@bp.get("/")
def upload_page():
    messages = []
    if not VT_API_KEY:
        messages.append("Missing VT_API_KEY (VirusTotal scans will not work).")
    if not URLSCAN_API_KEY:
        messages.append("Missing URLSCAN_API_KEY (urlscan.io scans will not work).")

    return render_template("upload.html", messages=messages, results={})


@bp.get("/test-urlscan")
def test_urlscan():
    r = requests.get("https://urlscan.io/user/quotas/", headers={
        "API-Key": URLSCAN_API_KEY,
        "api-key": URLSCAN_API_KEY
    }, timeout=30)
    return (r.text, r.status_code, {"Content-Type": "text/plain"})


@bp.post("/scan")
def scan():
    messages = []
    results = {}

    if not VT_API_KEY:
        messages.append("Missing VT_API_KEY (VirusTotal scans will not work).")
    if not URLSCAN_API_KEY:
        messages.append("Missing URLSCAN_API_KEY (urlscan.io scans will not work).")

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

        # VirusTotal
        if VT_API_KEY:
            vt = vt_scan_url(url)
            results["vt_url"] = vt
            results["vt_url_link"] = f"https://www.virustotal.com/gui/url/{vt_url_id(url)}"

            rep = vt_get_url_report(url)
            results["vt_url_report"] = rep
            if rep["ok"]:
                attrs = rep["report"].get("data", {}).get("attributes", {}) or {}
                stats = attrs.get("last_analysis_stats", {}) or {}
                reputation = attrs.get("reputation")

                results["vt_url_stats"] = stats
                results["vt_url_reputation"] = reputation

                s = score_from_stats(stats)
                results["vt_url_detected"] = s["detected"]
                results["vt_url_total"] = s["total"]
                results["vt_url_percent"] = s["percent"]

        # urlscan.io
        if URLSCAN_API_KEY:
            us = urlscan_scan_url(url, visibility)
            results["urlscan"] = us

            if us.get("ok"):
                summary = us.get("summary", {})
                results["urlscan_summary"] = summary

                g = urlscan_score_to_gauge(summary.get("score"))
                results["urlscan_gauge_score"] = g["score"]
                results["urlscan_gauge_percent"] = g["percent"]

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
                if rep["ok"]:
                    attrs = rep["report"].get("data", {}).get("attributes", {}) or {}
                    stats = attrs.get("last_analysis_stats", {}) or {}
                    reputation = attrs.get("reputation")

                    results["vt_file_stats"] = stats
                    results["vt_file_reputation"] = reputation

                    s = score_from_stats(stats)
                    results["vt_file_detected"] = s["detected"]
                    results["vt_file_total"] = s["total"]
                    results["vt_file_percent"] = s["percent"]

            return render_template("result.html", messages=messages, results=results)

        # -------- Hash lookup --------
        results["input_type"] = "hash"
        results["input_value"] = file_hash
        results["file_hash_provided"] = file_hash
        results["vt_file_link"] = f"https://www.virustotal.com/gui/file/{file_hash}"

        if VT_API_KEY:
            rep = vt_get_file_report_by_hash(file_hash)
            results["vt_file_report"] = rep

            if rep["ok"]:
                attrs = rep["report"].get("data", {}).get("attributes", {}) or {}
                stats = attrs.get("last_analysis_stats", {}) or {}
                reputation = attrs.get("reputation")

                results["vt_file_stats"] = stats
                results["vt_file_reputation"] = reputation

                s = score_from_stats(stats)
                results["vt_file_detected"] = s["detected"]
                results["vt_file_total"] = s["total"]
                results["vt_file_percent"] = s["percent"]

        return render_template("result.html", messages=messages, results=results)

    messages.append("Unknown action.")
    return render_template("upload.html", messages=messages, results={})
