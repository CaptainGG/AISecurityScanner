"""Local Flask frontend for AI Code Security Scanner."""

from __future__ import annotations

import json
import os
from typing import Any

from flask import Flask, Response, flash, redirect, render_template, request, session, url_for

from scanner.engine import build_text_report
from utils.file_loader import SUPPORTED_EXTENSIONS
from utils.reporter import format_text_report


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "local-development-only")

SUPPORTED_CHOICES = [".py", ".json", ".env", ".txt", ".md"]


def _is_supported_name(file_name: str) -> bool:
    """Return True when an uploaded file has a supported scanner type."""
    lower_name = file_name.lower()
    return lower_name == ".env" or any(
        lower_name.endswith(suffix) for suffix in SUPPORTED_EXTENSIONS
    )


def _suffix_for_name(file_name: str) -> str:
    """Infer scanner suffix from an uploaded filename."""
    lower_name = file_name.lower()
    if lower_name == ".env" or lower_name.endswith(".env"):
        return ".env"
    for suffix in SUPPORTED_CHOICES:
        if lower_name.endswith(suffix):
            return suffix
    return ""


def _load_report() -> dict[str, Any] | None:
    """Load the latest report from the browser session."""
    raw_report = session.get("latest_report")
    if not raw_report:
        return None
    return json.loads(raw_report)


@app.get("/")
def index() -> str:
    """Render the scanner form."""
    return render_template("index.html", supported_choices=SUPPORTED_CHOICES)


@app.post("/scan")
def scan() -> str:
    """Scan pasted code and uploaded files in memory."""
    items: list[dict[str, str]] = []
    warnings: list[str] = []
    pasted_code = request.form.get("pasted_code", "")
    pasted_suffix = request.form.get("pasted_suffix", ".py")

    if pasted_code.strip():
        if pasted_suffix not in SUPPORTED_CHOICES:
            warnings.append("Pasted content type was not supported and was skipped.")
        else:
            items.append(
                {
                    "label": f"pasted-code{pasted_suffix}",
                    "file_name": f"pasted-code{pasted_suffix}",
                    "suffix": pasted_suffix,
                    "content": pasted_code,
                }
            )

    for uploaded_file in request.files.getlist("files"):
        if not uploaded_file or not uploaded_file.filename:
            continue

        if not _is_supported_name(uploaded_file.filename):
            warnings.append(f"Skipped unsupported file: {uploaded_file.filename}")
            continue

        content = uploaded_file.read().decode("utf-8", errors="replace")
        items.append(
            {
                "label": uploaded_file.filename,
                "file_name": uploaded_file.filename,
                "suffix": _suffix_for_name(uploaded_file.filename),
                "content": content,
            }
        )

    if not items:
        flash("Paste code or upload at least one supported file to scan.")
        return redirect(url_for("index"))

    target = "pasted code"
    if len(items) > 1 or not items[0]["label"].startswith("pasted-code"):
        target = "web upload"

    report = build_text_report(target=target, items=items)
    session["latest_report"] = json.dumps(report)

    return render_template("results.html", report=report, warnings=warnings)


@app.post("/download/json")
def download_json() -> Response:
    """Download the latest scan report as JSON."""
    report = _load_report()
    if report is None:
        flash("Run a scan before downloading a report.")
        return redirect(url_for("index"))

    return Response(
        json.dumps(report, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=security-report.json"},
    )


@app.post("/download/text")
def download_text() -> Response:
    """Download the latest scan report as plain text."""
    report = _load_report()
    if report is None:
        flash("Run a scan before downloading a report.")
        return redirect(url_for("index"))

    return Response(
        format_text_report(report),
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=security-report.txt"},
    )


if __name__ == "__main__":
    app.run(debug=True)
