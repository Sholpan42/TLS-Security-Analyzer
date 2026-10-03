import ssl
import socket
import json
import sys
import os
import argparse
import threading
import textwrap
import tkinter as tk
import urllib.request
import urllib.error
import time
from datetime import datetime, timezone
import customtkinter as ctk
from dateutil import parser as dateparser
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)

# =========================
# APP META
# =========================

WINDOW_TITLE = "TLS Security Analyzer"
APP_HEADER = "Check TLS"


# =========================
# INIT
# =========================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


def save_log(data):
    path = os.path.join(LOG_DIR, "events.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")


def save_report(data):
    stem = data.get("report_stem") or make_report_stem()
    path = os.path.join(
        REPORT_DIR,
        f"{stem}.json"
    )
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    return path


def open_file_path(path):
    try:
        if path and os.path.exists(path):
            os.startfile(path)
    except Exception as e:
        print("Open file error:", e)


def make_report_stem():
    return f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"


def pdf_escape(value):
    text = str(value).encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf_lines(data):
    summary = data.get("summary") or {}
    tls_versions = data.get("tls_versions") or {}
    tls_probe_details = data.get("tls_probe_details") or {}

    lines = [
        "TLS Security Analyzer - PDF Report",
        "",
        f"Generated: {data.get('timestamp', 'Unknown')}",
        f"Domain: {data.get('domain', 'Unknown')}",
        f"Scan Status: {data.get('scan_status', data.get('status', 'Unknown'))}",
        f"Risk Score: {data.get('risk_score', 'N/A') if data.get('risk_score') is not None else 'N/A'}/100 ({data.get('risk_level', 'Unknown')})",
        f"Duration: {data.get('duration_seconds', 'Unknown')} seconds",
        "",
        "Connection",
        f"Current TLS: {data.get('current_tls') or 'Unknown'}",
        f"Cipher: {format_cipher_for_display(data.get('cipher'))}",
        f"HSTS: {'Yes' if summary.get('hsts') else 'No'}",
        f"Certificate received: {'Yes' if summary.get('certificate_received') else 'No'}",
        f"Certificate chain verified: {'Yes' if summary.get('chain_verified') else 'No'}",
        f"Hostname verified: {'Yes' if summary.get('hostname_verified') else 'No'}",
        "",
        "Certificate Summary",
        f"IP: {summary.get('ip', 'Unknown')}",
        f"Issuer: {summary.get('issuer', 'Unknown')}",
        f"Expiration: {summary.get('expiration', 'Unknown')}",
        "",
        "Supported TLS Versions",
    ]

    for name, enabled in tls_versions.items():
        probe = tls_probe_details.get(name, {})
        result = probe.get("status", "SUPPORTED" if enabled else "NOT_SUPPORTED")
        detail = probe.get("error") or "Handshake successful"
        lines.append(f"- {name}: {result} ({detail})")

    lines.extend(["", data.get("risk_analysis", "Risk Analysis: No data available.")])
    return lines


def save_pdf_report(data):
    stem = data.get("report_stem") or make_report_stem()
    path = os.path.join(REPORT_DIR, f"{stem}.pdf")

    try:
        write_reportlab_pdf(path, data)
    except Exception as e:
        print("Styled PDF report error:", e)
        write_text_pdf(path, data)

    return path


def write_text_pdf(path, data):
    lines = []

    for line in build_pdf_lines(data):
        parts = str(line).splitlines() or [""]
        for part in parts:
            if not part:
                lines.append("")
                continue
            wrapped = textwrap.wrap(part, width=92, replace_whitespace=False) or [""]
            lines.extend(wrapped)

    pages = [lines[i:i + 48] for i in range(0, len(lines), 48)] or [[]]
    write_simple_pdf(path, pages)


def pdf_report_color(level):
    colors = {
        "Excellent": "#2ecc71",
        "Good": "#27ae60",
        "Warning": "#f39c12",
        "Critical": "#e74c3c",
        "Unreachable": "#7f8c8d",
        "High": "#e67e22",
        "Medium": "#f39c12",
        "Low": "#2ecc71",
        "SUCCESS": "#2ecc71",
        "TIMEOUT": "#f39c12",
        "DNS_ERROR": "#e74c3c",
        "TLS_ERROR": "#e74c3c",
        "CONNECTION_ERROR": "#e74c3c",
        "N/A": "#7f8c8d",
    }
    return colors.get(str(level), "#111827")


def pdf_yes_no(value):
    return "Yes" if value else "No"


def format_cipher_for_display(cipher):
    if isinstance(cipher, dict):
        return f"{cipher.get('name', 'Unknown')} ({cipher.get('bits', 'Unknown')} bits, {cipher.get('strength', 'Unknown')})"
    return str(cipher or "Unknown")


def pdf_analysis_items(text):
    items = []
    for line in str(text or "").splitlines():
        clean = line.strip()
        if not clean or clean == "Risk Analysis:":
            continue
        if clean.startswith("- "):
            clean = clean[2:].strip()
        if clean:
            items.append(clean)
    return items or ["No urgent risks detected."]


def write_reportlab_pdf(path, data):
    from xml.sax.saxutils import escape
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
    )

    summary = data.get("summary") or {}
    tls_versions = data.get("tls_versions") or {}
    tls_probe_details = data.get("tls_probe_details") or {}
    status = data.get("scan_status", data.get("status", "Unknown"))
    risk_level = data.get("risk_level", "Unknown")
    risk_score = data.get("risk_score")
    risk_score_label = "N/A" if risk_score is None else str(risk_score)
    status_color = pdf_report_color(status)
    risk_color = pdf_report_color(risk_level)

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=36 * mm,
        bottomMargin=18 * mm,
        title="TLS Security Analyzer Report",
    )

    body = ParagraphStyle(
        "Body",
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#1f2937"),
        alignment=TA_LEFT,
    )
    small = ParagraphStyle(
        "Small",
        parent=body,
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#667085"),
    )
    section = ParagraphStyle(
        "Section",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0b0f14"),
        spaceBefore=12,
        spaceAfter=6,
    )
    table_header = ParagraphStyle(
        "TableHeader",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13,
        textColor=colors.white,
    )
    card = ParagraphStyle(
        "Card",
        parent=body,
        fontSize=8,
        leading=18,
        textColor=colors.HexColor("#667085"),
    )

    def safe(value):
        value = "Unknown" if value is None or value == "" else value
        return escape(str(value))

    def page_decorator(canvas, doc_obj):
        width, height = A4
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0b0f14"))
        canvas.rect(0, height - 32 * mm, width, 32 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 18)
        canvas.drawString(18 * mm, height - 19 * mm, "TLS Security Analyzer")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(
            width - 18 * mm,
            height - 13 * mm,
            f"Generated: {data.get('timestamp', 'Unknown')}",
        )
        canvas.setFillColor(colors.HexColor("#9aa8b6"))
        canvas.drawRightString(
            width - 18 * mm,
            10 * mm,
            f"Page {doc_obj.page}",
        )
        canvas.setStrokeColor(colors.HexColor("#d9e2ec"))
        canvas.line(18 * mm, 15 * mm, width - 18 * mm, 15 * mm)
        canvas.restoreState()

    def card_text(label, value, value_color):
        return Paragraph(
            f"<font size='7' color='#667085'>{safe(label)}</font><br/>"
            f"<font size='15' color='{value_color}'><b>{safe(value)}</b></font>",
            card,
        )

    elements = []

    domain = data.get("domain", "Unknown")
    elements.append(Paragraph(f"<b>{safe(domain)}</b>", ParagraphStyle(
        "DomainTitle",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0b0f14"),
    )))
    elements.append(Paragraph("TLS scan result and security posture summary.", small))
    elements.append(Spacer(1, 8))

    score_cards = Table(
        [[
            card_text("STATUS", status, status_color),
            card_text("RISK SCORE", f"{risk_score_label}/100" if risk_score is not None else "N/A", risk_color),
            card_text("CURRENT TLS", data.get("current_tls") or "Unknown", "#111827"),
        ]],
        colWidths=[doc.width / 3] * 3,
        rowHeights=[24 * mm],
    )
    score_cards.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#d9e2ec")),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#d9e2ec")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    elements.append(score_cards)
    elements.append(Spacer(1, 10))

    details = [
        ("IP Address", summary.get("ip", "Unknown")),
        ("Issuer", summary.get("issuer", "Unknown")),
        ("Expiration", summary.get("expiration", "Unknown")),
        ("HSTS", pdf_yes_no(summary.get("hsts"))),
        ("Certificate received", pdf_yes_no(summary.get("certificate_received"))),
        ("Certificate chain verified", pdf_yes_no(summary.get("chain_verified"))),
        ("Hostname verified", pdf_yes_no(summary.get("hostname_verified"))),
        ("Cipher", format_cipher_for_display(data.get("cipher"))),
    ]

    elements.append(Paragraph("Certificate and Connection", section))
    detail_rows = [
        [
            Paragraph(f"<b>{safe(label)}</b>", body),
            Paragraph(safe(value), body),
        ]
        for label, value in details
    ]
    detail_table = Table(detail_rows, colWidths=[46 * mm, doc.width - 46 * mm])
    detail_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#d9e2ec")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5eaf0")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f6fa")),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#fbfcfe")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(detail_table)

    elements.append(Paragraph("TLS Protocol Probes", section))
    tls_rows = [[Paragraph("Protocol", table_header), Paragraph("Result", table_header), Paragraph("Details", table_header)]]
    for protocol, enabled in tls_versions.items():
        probe = tls_probe_details.get(protocol, {})
        result = probe.get("status", "SUPPORTED" if enabled else "NOT_SUPPORTED")
        details = probe.get("error") or ("Handshake successful" if result == "SUPPORTED" else "No additional detail")
        tls_rows.append([
            Paragraph(safe(protocol), body),
            Paragraph(safe(result), body),
            Paragraph(safe(details), small),
        ])

    tls_table = Table(tls_rows, colWidths=[doc.width * 0.22, doc.width * 0.28, doc.width * 0.50])
    tls_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#d9e2ec")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5eaf0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for index, (protocol, enabled) in enumerate(tls_versions.items(), start=1):
        result = tls_probe_details.get(protocol, {}).get("status", "SUPPORTED" if enabled else "NOT_SUPPORTED")
        tls_style.append((
            "BACKGROUND",
            (1, index),
            (1, index),
            colors.HexColor("#eaf7ee" if result == "SUPPORTED" else "#fff8e8" if result == "PROBE_ERROR" else "#fdecec"),
        ))
    tls_table.setStyle(TableStyle(tls_style))
    elements.append(tls_table)

    elements.append(Paragraph("Risk Analysis", section))
    bullet_text = "<br/>".join(
        f"- {safe(item)}" for item in pdf_analysis_items(data.get("risk_analysis"))
    )
    risk_box = Table(
        [[Paragraph(bullet_text, body)]],
        colWidths=[doc.width],
    )
    risk_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff8e8")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#f2d391")),
        ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(risk_color)),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(KeepTogether([risk_box]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "JSON and PDF copies are saved automatically after every scan.",
        small,
    ))

    doc.build(elements, onFirstPage=page_decorator, onLaterPages=page_decorator)


def write_simple_pdf(path, pages):
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        None,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    page_ids = []

    for page_lines in pages:
        commands = ["BT", "/F1 10 Tf", "14 TL", "54 744 Td"]
        first_line = True
        for line in page_lines:
            if first_line:
                first_line = False
            else:
                commands.append("T*")
            if line:
                commands.append(f"({pdf_escape(line)}) Tj")
        commands.append("ET")

        content = "\n".join(commands).encode("latin-1", "replace")
        content_object = (
            f"<< /Length {len(content)} >>\nstream\n".encode("ascii")
            + content
            + b"\nendstream"
        )
        content_id = len(objects) + 1
        objects.append(content_object)

        page_id = len(objects) + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        )
        page_ids.append(page_id)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>"

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        obj_bytes = obj if isinstance(obj, bytes) else obj.encode("latin-1", "replace")
        pdf.extend(f"{object_id} 0 obj\n".encode("ascii"))
        pdf.extend(obj_bytes)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF".encode("ascii")
    )

    with open(path, "wb") as f:
        f.write(pdf)


# =========================
# TLS CORE
# =========================

HTTP_SECURITY_HEADERS = {
    "Strict-Transport-Security": "Medium",
    # These are useful browser-defense controls, but their absence alone does
    # not establish a TLS/HTTPS weakness for an arbitrary public endpoint.
    "Content-Security-Policy": "Low",
    "X-Content-Type-Options": "Info",
    "X-Frame-Options": "Info",
    "Referrer-Policy": "Info",
    "Permissions-Policy": "Info",
    "Cross-Origin-Opener-Policy": "Info",
    "Cross-Origin-Resource-Policy": "Info",
}


def exception_code(error):
    """Return a stable, report-friendly error code without hiding its cause."""
    if isinstance(error, socket.gaierror):
        return "DNS_FAIL"
    if isinstance(error, socket.timeout):
        return "TIMEOUT"
    if isinstance(error, ssl.SSLError):
        return "TLS_HANDSHAKE_FAIL"
    return f"{type(error).__name__}: {error}"


def tls_probe_error_details(error):
    """Classify client-side probe limitations separately from server rejection."""
    reason = (getattr(error, "reason", None) or "").upper()
    client_policy_reasons = {
        "NO_CIPHERS_AVAILABLE": "client_no_compatible_ciphers",
        "NO_PROTOCOLS_AVAILABLE": "client_protocol_disabled",
        "UNSUPPORTED_PROTOCOL": "client_protocol_disabled",
    }
    if reason in client_policy_reasons:
        return "PROBE_ERROR", client_policy_reasons[reason]
    if reason:
        return "NOT_SUPPORTED", reason.lower()
    return "NOT_SUPPORTED", str(error)


def certificate_details(cert, der_certificate, hostname_verified):
    details = {
        "received": cert is not None,
        "chain_verified": hostname_verified,
        "hostname_verified": hostname_verified,
        "expired": False,
        "subject": "Unknown",
        "common_name": "Unknown",
        "san": [],
        "not_before": "Unknown",
        "not_after": "Unknown",
        "days_until_expiration": None,
        "key_type": "Unknown",
        "key_size": None,
        "signature_algorithm": "Unknown",
        "self_signed": False,
    }
    if not cert:
        return details

    details["subject"] = ", ".join(
        f"{key}={value}" for rdn in cert.get("subject", ()) for key, value in rdn
    ) or "Unknown"
    details["common_name"] = next(
        (value for rdn in cert.get("subject", ()) for key, value in rdn if key == "commonName"),
        "Unknown",
    )
    details["san"] = [value for kind, value in cert.get("subjectAltName", ()) if kind in {"DNS", "IP Address"}]

    for source, target in (("notBefore", "not_before"), ("notAfter", "not_after")):
        if cert.get(source):
            try:
                parsed = dateparser.parse(cert[source])
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                details[target] = parsed.isoformat()
                if source == "notAfter":
                    details["days_until_expiration"] = (parsed - datetime.now(timezone.utc)).days
                    details["expired"] = details["days_until_expiration"] < 0
            except (TypeError, ValueError, OverflowError):
                details[target] = cert[source]

    if not der_certificate:
        return details
    try:
        parsed_cert = x509.load_der_x509_certificate(der_certificate)
        public_key = parsed_cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            details["key_type"] = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            details["key_type"] = "EC"
        else:
            details["key_type"] = type(public_key).__name__.replace("PublicKey", "")
        details["key_size"] = getattr(public_key, "key_size", None)
        details["signature_algorithm"] = parsed_cert.signature_hash_algorithm.name.upper()
        details["self_signed"] = parsed_cert.subject == parsed_cert.issuer
    except (ValueError, TypeError, AttributeError) as error:
        details["parse_error"] = str(error)
    return details


def fetch_certificate(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls = ssock.version()
                cipher = ssock.cipher()
                der_certificate = ssock.getpeercert(binary_form=True)
                return cert, tls, cipher, certificate_details(cert, der_certificate, True), None
    except (socket.gaierror, socket.timeout, ssl.SSLError) as error:
        return None, None, None, certificate_details(None, None, False), exception_code(error)
    except Exception as e:
        return None, None, None, certificate_details(None, None, False), exception_code(e)


def probe_tls_versions(domain):
    versions = {
        "TLS 1.3": False,
        "TLS 1.2": False,
        "TLS 1.1": False,
        "TLS 1.0": False
    }
    expected_protocols = {
        "TLS 1.3": "TLSv1.3",
        "TLS 1.2": "TLSv1.2",
        "TLS 1.1": "TLSv1.1",
        "TLS 1.0": "TLSv1",
    }

    details = {}
    for v in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if v == "TLS 1.3":
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            elif v == "TLS 1.2":
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            elif v == "TLS 1.1":
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            else:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1

            if v in {"TLS 1.0", "TLS 1.1"}:
                # OpenSSL often rejects legacy handshakes before contacting the
                # server.  This isolated probe is intentionally relaxed only
                # to determine whether the endpoint still accepts them.
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                    negotiated = tls_sock.version()
                    if negotiated != expected_protocols[v]:
                        details[v] = {
                            "status": "PROBE_ERROR",
                            "error": f"unexpected_protocol_{negotiated or 'unknown'}",
                            "message": f"Requested {v}, but negotiated {negotiated or 'an unknown version'}.",
                        }
                        continue
                    versions[v] = True
                    details[v] = {"status": "SUPPORTED", "error": None}
        except ssl.SSLError as error:
            versions[v] = False
            status, reason = tls_probe_error_details(error)
            details[v] = {"status": status, "error": reason, "message": str(error)}
        except (socket.timeout, OSError, ValueError) as error:
            versions[v] = False
            details[v] = {"status": "PROBE_ERROR", "error": exception_code(error), "message": str(error)}

    return versions, details


def check_security_headers(domain):
    """Try HEAD first, then GET because many servers reject HEAD requests."""
    last_error = None
    headers = None
    for method in ("HEAD", "GET"):
        try:
            request = urllib.request.Request(
                f"https://{domain}", method=method, headers={"User-Agent": "TLS-Security-Analyzer/1.0"}
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                headers = response.headers
                break
        except urllib.error.HTTPError as error:
            # A 4xx/5xx response can still contain security headers.
            if method == "HEAD" and error.code in {405, 501}:
                last_error = exception_code(error)
                continue
            headers = error.headers
            if headers:
                break
            last_error = exception_code(error)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as error:
            last_error = exception_code(error)

    result = {}
    for name in HTTP_SECURITY_HEADERS:
        value = headers.get(name) if headers else None
        result[name] = {"present": bool(value), "value": value or "Missing"}
    return result, last_error


# =========================
# CLASSIFICATION
# =========================

# =========================
# ISSUER
# =========================

def parse_issuer(cert):
    if not cert or "issuer" not in cert:
        return "Unknown"

    try:
        org = None
        cn = None
        country = None

        for rdn in cert["issuer"]:
            for k, v in rdn:
                if k == "organizationName":
                    org = v
                elif k == "commonName":
                    cn = v
                elif k == "countryName":
                    country = v

        issuer = org or cn

        if issuer and country:
            return f"{issuer}, {country}"
        if issuer:
            return issuer

        return "Unknown"
    except (KeyError, TypeError, ValueError):
        return "Unknown"


# =========================
# SUMMARY
# =========================

def extract_summary(domain, cert, tls_map, security_headers, cert_details):
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)})
    except socket.gaierror:
        addresses = []

    exp_fmt = "Unknown"

    if cert and cert.get("notAfter"):
        try:
            exp_dt = dateparser.parse(cert["notAfter"])
            now = datetime.now(timezone.utc)
            days_left = (exp_dt - now).days
            exp_fmt = f"{exp_dt.strftime('%b %d, %Y')} ({days_left} days left)"
        except (TypeError, ValueError, OverflowError):
            exp_fmt = cert["notAfter"]

    tls_list = ", ".join([k for k, v in tls_map.items() if v]) or "None"

    return {
        "ip": ", ".join(addresses) or "Unknown",
        "ipv4": [address for address in addresses if ":" not in address],
        "ipv6": [address for address in addresses if ":" in address],
        "issuer": parse_issuer(cert),
        "certificate_received": cert is not None,
        "chain_verified": cert_details["chain_verified"],
        "hostname_verified": cert_details["hostname_verified"],
        "certificate_expired": cert_details["expired"],
        "expiration": exp_fmt,
        "hsts": security_headers["Strict-Transport-Security"]["present"],
        "hsts_value": security_headers["Strict-Transport-Security"]["value"],
        "tls_list": tls_list
    }


# =========================
# RISK ANALYSIS
# =========================

def certificate_expired(cert):
    if not cert or not cert.get("notAfter"):
        return False

    try:
        expires = dateparser.parse(cert["notAfter"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires < datetime.now(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return False


SEVERITY_WEIGHTS = {"Critical": 40, "High": 25, "Medium": 15, "Low": 5, "Info": 0}
SEVERITY_COLORS = {"Critical": "#e74c3c", "High": "#ff7777", "Medium": "#f39c12", "Low": "#2ecc71", "Info": "#9aa8b6"}


def finding(identifier, severity, description, evidence, recommendation):
    return {"id": identifier, "severity": severity, "description": description, "evidence": evidence, "recommendation": recommendation}


def cipher_details(cipher, tls_version):
    name, protocol, bits = cipher or ("Unknown", "Unknown", 0)
    weak_markers = ("RC4", "3DES", "DES-", "NULL", "MD5", "SHA1")
    matched_marker = next((marker for marker in weak_markers if marker in name.upper()), None)
    strength = "Weak" if matched_marker else "Strong"
    if name.startswith("TLS_"):
        pieces = name.split("_")
        encryption = "-".join(pieces[1:4]) if len(pieces) > 3 else name
        authentication = pieces[-1] if len(pieces) > 1 else "Unknown"
        key_exchange = "TLS 1.3 integrated key exchange"
    else:
        pieces = name.split("-")
        key_exchange = pieces[0] if pieces else "Unknown"
        encryption = "-".join(pieces[2:-1]) if len(pieces) > 3 else name
        authentication = pieces[-1] if len(pieces) > 1 else "Unknown"
    return {
        "name": name, "protocol": tls_version or protocol or "Unknown", "bits": bits,
        "strength": strength, "reason": f"Contains deprecated {matched_marker}." if matched_marker else "Modern cipher suite markers detected.",
        "encryption": encryption, "key_exchange": key_exchange, "authentication": authentication,
    }


def scan_status_from_error(error):
    if error is None:
        return "SUCCESS"
    if error == "DNS_FAIL":
        return "DNS_ERROR"
    if error == "TIMEOUT":
        return "TIMEOUT"
    if error == "TLS_HANDSHAKE_FAIL":
        return "TLS_ERROR"
    return "CONNECTION_ERROR"


def build_findings(tls_map, security_headers, cert, cert_info, cipher, scan_status):
    findings = []
    if scan_status != "SUCCESS":
        return findings
    modern_tls_available = bool(tls_map.get("TLS 1.2") or tls_map.get("TLS 1.3"))
    for protocol in ("TLS 1.0", "TLS 1.1"):
        if tls_map.get(protocol):
            severity = "Info" if modern_tls_available else "High"
            description = (
                f"{protocol} is available as a legacy fallback."
                if modern_tls_available else f"{protocol} is enabled without a modern TLS alternative."
            )
            findings.append(finding(
                f"{protocol.lower().replace(' ', '_')}_enabled",
                severity,
                description,
                f"Probe negotiated {protocol}.",
                "Disable legacy TLS versions and keep TLS 1.2 or TLS 1.3.",
            ))
    if not modern_tls_available:
        findings.append(finding("modern_tls_missing", "Critical", "No modern TLS protocol was detected.", "TLS 1.2 and TLS 1.3 probes were unsuccessful.", "Enable TLS 1.2 and preferably TLS 1.3."))
    elif tls_map.get("TLS 1.2") and not tls_map.get("TLS 1.3"):
        findings.append(finding("tls13_unavailable", "Low", "TLS 1.3 is not available.", "TLS 1.2 was supported but TLS 1.3 was not negotiated.", "Enable TLS 1.3 where supported by the platform."))
    for name, severity in HTTP_SECURITY_HEADERS.items():
        header = security_headers[name]
        if not header["present"]:
            findings.append(finding(f"missing_{name.lower()}", severity, f"{name} header is missing.", "No response header was received over HTTPS.", f"Configure {name} with a policy appropriate for the application."))
    if not cert:
        return findings
    if not cert_info.get("hostname_verified"):
        findings.append(finding("hostname_verification_failed", "High", "Hostname verification failed.", "The certificate did not validate for the requested hostname.", "Issue a certificate whose SAN includes the scanned hostname."))
    elif certificate_expired(cert):
        findings.append(finding("certificate_expired", "Critical", "The TLS certificate has expired.", f"notAfter: {cert.get('notAfter')}", "Renew and deploy the certificate immediately."))
    elif cert_info.get("days_until_expiration") is not None and cert_info["days_until_expiration"] <= 30:
        findings.append(finding("certificate_expiring", "Medium", "The TLS certificate expires soon.", f"{cert_info['days_until_expiration']} days remaining.", "Renew the certificate before it expires and verify automated renewal."))
    if cert_info.get("self_signed"):
        findings.append(finding("self_signed", "High", "The certificate appears self-signed.", "Certificate subject equals issuer.", "Use a certificate issued by a trusted certificate authority for public services."))
    if cipher.get("strength") == "Weak":
        findings.append(finding("weak_cipher", "High", "A weak cipher suite was negotiated.", cipher["name"], "Disable weak cipher suites and prefer modern AEAD suites."))
    return findings


def calculate_risk_score(findings, scan_status="SUCCESS"):
    if scan_status != "SUCCESS":
        return None, "N/A", "#9aa8b6"
    score = min(sum(SEVERITY_WEIGHTS[item["severity"]] for item in findings), 100)
    severities = {item["severity"] for item in findings}
    if "Critical" in severities:
        score = max(score, 80)
        level = "Critical"
    elif "High" in severities:
        score = max(score, 50)
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"
    return score, level, SEVERITY_COLORS[level]


def format_findings(findings):
    if not findings:
        return "No findings. The scanned TLS and HTTP security posture looks strong."
    return "\n\n".join(
        f"[{item['severity'].upper()}] {item['description']}\nEvidence: {item['evidence']}\nRecommendation: {item['recommendation']}"
        for item in findings
    )


def perform_scan(domain):
    """Run the scanner without GUI side effects; shared by the desktop app and CLI."""
    started_at = datetime.now(timezone.utc)
    started_clock = time.monotonic()
    cert, tls, cipher, certificate_info, error = fetch_certificate(domain)
    scan_status = scan_status_from_error(error)
    tls_map, tls_probe_details = probe_tls_versions(domain)
    security_headers, headers_error = check_security_headers(domain)
    summary = extract_summary(domain, cert, tls_map, security_headers, certificate_info)
    cipher_info = cipher_details(cipher, tls)
    findings = build_findings(tls_map, security_headers, cert, certificate_info, cipher_info, scan_status)
    risk_score, risk_level, risk_color = calculate_risk_score(findings, scan_status)
    finished_at = datetime.now(timezone.utc)
    return {
        "timestamp": finished_at.strftime("%Y-%m-%d %H:%M:%S"),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round(time.monotonic() - started_clock, 2),
        "domain": domain,
        "scan_status": scan_status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "current_tls": tls,
        "cipher": cipher_info,
        "tls_versions": tls_map,
        "tls_probe_details": tls_probe_details,
        "summary": summary,
        "certificate": certificate_info,
        "security_headers": security_headers,
        "headers_error": headers_error,
        "findings": findings,
        "error": error,
    }


def normalize_domain_value(value):
    domain = value.strip()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0].split(":")[0].strip()
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def run_cli():
    parser = argparse.ArgumentParser(description="TLS/HTTPS security posture analyzer")
    parser.add_argument("domain", help="Domain to scan, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Print the complete JSON result")
    parser.add_argument("--pdf", action="store_true", help="Save a PDF report")
    parser.add_argument("--save-json", action="store_true", help="Save a JSON report")
    parser.add_argument("--quiet", action="store_true", help="Suppress the summary line")
    parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical"), help="Exit with code 1 at or above this risk level")
    args = parser.parse_args()
    domain = normalize_domain_value(args.domain)
    if not domain:
        parser.error("a domain is required")

    report = perform_scan(domain)
    report["report_stem"] = make_report_stem()
    report["status"] = report["scan_status"]
    report["risk_analysis"] = format_findings(report["findings"])
    if args.save_json:
        report["json_report"] = save_report(report)
    if args.pdf:
        report["pdf_report"] = save_pdf_report(report)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif not args.quiet:
        score = report["risk_score"] if report["risk_score"] is not None else "N/A"
        print(f"{domain}: scan={report['scan_status']}, risk={report['risk_level']} ({score}/100), duration={report['duration_seconds']}s")
        for item in report["findings"]:
            print(f"[{item['severity'].upper()}] {item['description']}")

    if report["scan_status"] != "SUCCESS":
        return 2
    if args.fail_on:
        ranks = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        if ranks.get(report["risk_level"], 0) >= ranks[args.fail_on.title()]:
            return 1
    return 0


if __name__ == "__main__" and len(sys.argv) > 1:
    sys.exit(run_cli())


# =========================
# UI
# =========================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title(WINDOW_TITLE)
app.geometry("1220x820")
app.minsize(1050, 720)

try:
    app.iconbitmap(resource_path("tls_analyzer.ico"))
except Exception as e:
    print("Icon load error:", e)


BG = "#0b0f14"
SIDEBAR_BG = "#101820"
PANEL_BG = "#151b23"
PANEL_ALT = "#0f141b"
BORDER = "#253241"
TEXT_MUTED = "#9aa8b6"
ACCENT = "#2d8cff"

app.grid_columnconfigure(1, weight=1)
app.grid_rowconfigure(0, weight=1)

sidebar = ctk.CTkFrame(app, width=230, corner_radius=0, fg_color=SIDEBAR_BG)
sidebar.grid(row=0, column=0, sticky="nsew")
sidebar.grid_propagate(False)

content_frame = ctk.CTkFrame(app, fg_color=BG, corner_radius=0)
content_frame.grid(row=0, column=1, sticky="nsew")
content_frame.grid_columnconfigure(0, weight=1)
content_frame.grid_rowconfigure(0, weight=1)

nav_buttons = {}
active_page = None
result_frame = None
input_box = None
scan_btn = None
scan_progress = None
scan_status = None
current_domain = ""
is_scanning = False
last_scan_data = None
fast_scrollables = []


def copy_to_clipboard(value):
    app.clipboard_clear()
    app.clipboard_append(str(value))
    app.update()


def install_label_copy_support():
    """Allow copying every native label/button caption with a right click."""
    menu = tk.Menu(app, tearoff=False)

    def show_copy_menu(event):
        try:
            value = event.widget.cget("text")
        except tk.TclError:
            return None
        if not value:
            return None
        menu.delete(0, "end")
        menu.add_command(label="Copy", command=lambda text=value: copy_to_clipboard(text))
        menu.tk_popup(event.x_root, event.y_root)
        return "break"

    # CTkLabel and CTkButton render captions through native tkinter widgets.
    app.bind_class("Label", "<Button-3>", show_copy_menu, add="+")
    app.bind_class("Button", "<Button-3>", show_copy_menu, add="+")


def make_copy_button(parent, value, text="Copy"):
    return ctk.CTkButton(parent, text=text, width=72, height=28, command=lambda: copy_to_clipboard(value))


def copy_field(parent, value, font=("Arial", 15), text_color="#d0d0d0", justify="left",
               width=None, height=None, display_value=None, **pack_kwargs):
    """
    A selectable, copyable piece of text that looks like a label.
    Uses a real read-only Entry, so mouse-drag selection and Ctrl+C
    work natively (no custom click bindings needed, which are unreliable
    on composite CTk widgets like CTkLabel).
    """
    options = {
        "font": font,
        "text_color": text_color,
        "fg_color": "transparent",
        "border_width": 0,
        "justify": justify,
    }
    if height is not None:
        options["height"] = height
    if width is not None:
        options["width"] = width
    entry = ctk.CTkEntry(
        parent,
        **options,
    )
    full_value = "" if value is None else str(value)
    entry.insert(0, full_value if display_value is None else str(display_value))
    entry.configure(state="readonly")

    menu = tk.Menu(app, tearoff=False)

    def do_copy(_event=None):
        try:
            selected = entry.get()[entry.index("sel.first"):entry.index("sel.last")]
        except tk.TclError:
            selected = entry.get()
        copy_to_clipboard(selected)
        return "break"

    def select_all(_event=None):
        entry.select_range(0, "end")
        return "break"

    def copy_full_value():
        copy_to_clipboard(full_value)

    def layout_independent_shortcuts(event):
        if event.keycode == 67:  # physical C key, independent of active layout
            return do_copy(event)
        if event.keycode == 65:  # physical A key
            return select_all(event)
        return None

    menu.add_command(label="Copy", command=do_copy)
    if display_value is not None:
        menu.add_command(label="Copy full value", command=copy_full_value)
    menu.add_command(label="Select all", command=select_all)
    target = entry._entry
    target.bind("<Button-3>", lambda event: (menu.tk_popup(event.x_root, event.y_root), "break")[1])
    target.bind("<Control-c>", do_copy)
    target.bind("<<Copy>>", do_copy)
    target.bind("<Control-Insert>", do_copy)
    target.bind("<Control-KeyPress>", layout_independent_shortcuts, add="+")

    entry.pack(**pack_kwargs)
    return entry


def shorten_value(value, limit=165):
    """Keep dense security data readable without hiding the full copyable value."""
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    cut = text.rfind(", ", 0, limit)
    if cut > limit // 2:
        shown = text[:cut]
        hidden = max(1, text.count(", ") - shown.count(", "))
        return f"{shown}, … (+{hidden} more)"
    return f"{text[:limit - 1]}…"


def make_readonly_textbox(parent, value, own_wheel=False, copy_value=None, **kwargs):
    """Selectable text; only Logs keeps its own scroll area."""
    textbox = ctk.CTkTextbox(parent, **kwargs)
    textbox.insert("1.0", value)

    def allow_copy_or_block(event):
        if event.state & 0x4 and event.keycode in {65, 67}:
            if event.keycode == 67:
                copy_selection_or_all(event)
            elif event.keycode == 65:
                textbox.tag_add("sel", "1.0", "end-1c")
            return "break"
        return "break"

    full_copy_value = str(value) if copy_value is None else str(copy_value)

    def copy_selection_or_all(_event=None):
        try:
            selected = textbox.get("sel.first", "sel.last")
        except tk.TclError:
            selected = full_copy_value
        copy_to_clipboard(selected)

    target = textbox._textbox
    target.bind("<Key>", allow_copy_or_block)
    target.bind("<Control-Insert>", copy_selection_or_all)
    target.bind("<Button-3>", copy_selection_or_all)

    if own_wheel:
        def scroll_textbox(event):
            target.yview_scroll(int(-event.delta / 20), "units")
            return "break"

        target.bind("<MouseWheel>", scroll_textbox)
    return textbox


def copy_wrapped_field(parent, value, text_color="#d0d0d0", **pack_kwargs):
    """Full selectable value, wrapped to the actual scan-table column."""
    raw_text = "" if value is None else str(value)
    lines = []
    for source_line in raw_text.splitlines() or [""]:
        lines.extend(
            textwrap.wrap(
                source_line,
                width=96,
                break_long_words=True,
                break_on_hyphens=False,
            ) or [""]
        )
    display_text = "\n".join(lines)
    height = max(32, 12 + len(lines) * 21)
    field = make_readonly_textbox(
        parent,
        display_text,
        font=("Arial", 15),
        text_color=text_color,
        fg_color="transparent",
        border_width=0,
        height=height,
        wrap="none",
        activate_scrollbars=False,
        copy_value=raw_text,
    )
    field.pack(**pack_kwargs)
    return field


def make_fast_scroll(scrollable_frame):
    """Register a scrollable area for the application-wide faster wheel handler."""
    if scrollable_frame not in fast_scrollables:
        fast_scrollables.append(scrollable_frame)


def install_fast_mousewheel():
    def belongs_to(widget, parent):
        while widget is not None:
            if widget == parent:
                return True
            widget = widget.master
        return False

    def scroll_active_area(event):
        for scrollable in reversed(fast_scrollables):
            surfaces = (scrollable, scrollable._parent_frame, scrollable._parent_canvas)
            if any(belongs_to(event.widget, surface) for surface in surfaces):
                scrollable._parent_canvas.yview_scroll(int(-event.delta / 2), "units")
                return "break"
        return None

    app.bind_all("<MouseWheel>", scroll_active_area)


def configure_domain_entry(entry):
    def paste_from_clipboard(_event=None):
        try:
            value = app.clipboard_get()
        except tk.TclError:
            return "break"
        try:
            entry.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        entry.insert("insert", value)
        return "break"

    def copy_selection(_event=None):
        try:
            copy_to_clipboard(entry.selection_get())
        except tk.TclError:
            copy_to_clipboard(entry.get())
        return "break"

    def cut_selection(_event=None):
        try:
            selected = entry.selection_get()
        except tk.TclError:
            return "break"
        copy_to_clipboard(selected)
        try:
            entry.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        return "break"

    def select_all(_event=None):
        entry.select_range(0, "end")
        entry.icursor("end")
        return "break"

    # Right-click menu is the reliable path: it's mouse-driven, so it works
    # no matter what keyboard layout is active (Ctrl+V/Ctrl+C/Ctrl+X bindings
    # below rely on the "v"/"c"/"x" keysym, which some non-Latin layouts remap).
    menu = tk.Menu(app, tearoff=False)
    menu.add_command(label="Cut", command=cut_selection)
    menu.add_command(label="Paste", command=paste_from_clipboard)
    menu.add_command(label="Copy", command=copy_selection)
    menu.add_command(label="Select all", command=select_all)
    def layout_independent_shortcuts(event):
        # Windows virtual-key codes remain stable when the active layout changes.
        if event.keycode == 86:  # physical V key
            return paste_from_clipboard(event)
        if event.keycode == 67:  # physical C key
            return copy_selection(event)
        if event.keycode == 88:  # physical X key
            return cut_selection(event)
        if event.keycode == 65:  # physical A key
            return select_all(event)
        return None

    target = entry._entry
    target.bind("<Control-v>", paste_from_clipboard)
    target.bind("<<Paste>>", paste_from_clipboard)
    target.bind("<Shift-Insert>", paste_from_clipboard)
    target.bind("<Control-Insert>", copy_selection)
    target.bind("<Control-KeyPress>", layout_independent_shortcuts, add="+")
    target.bind("<Control-c>", copy_selection)
    target.bind("<<Copy>>", copy_selection)
    target.bind("<Control-x>", cut_selection)
    target.bind("<<Cut>>", cut_selection)
    target.bind("<Shift-Delete>", cut_selection)
    target.bind("<Control-a>", select_all)
    target.bind("<Button-3>", lambda event: (menu.tk_popup(event.x_root, event.y_root), "break")[1])


def clear_content():
    for widget in content_frame.winfo_children():
        widget.destroy()


def normalize_domain(value):
    return normalize_domain_value(value)


def set_active(page):
    global active_page
    active_page = page
    for name, button in nav_buttons.items():
        if name == page:
            button.configure(fg_color=ACCENT, text_color="#ffffff")
        else:
            button.configure(fg_color="transparent", text_color="#c8d2dc")


def make_header(parent, title, subtitle):
    header = ctk.CTkFrame(parent, fg_color="transparent")
    header.pack(fill="x", padx=28, pady=(24, 12))

    copy_field(header, title, font=("Arial", 30, "bold"), text_color="#ffffff", height=42,
               fill="x")

    if subtitle:
        copy_field(header, subtitle, font=("Arial", 15), text_color=TEXT_MUTED, height=28,
                   fill="x", pady=(5, 0))

    return header


def make_stat(parent, title, value, color="#ffffff"):
    card = ctk.CTkFrame(parent, fg_color=PANEL_BG, corner_radius=8, border_width=1, border_color=BORDER)
    card.pack(side="left", fill="both", expand=True, padx=6)

    copy_field(card, title, font=("Arial", 13), text_color=TEXT_MUTED,
               fill="x", padx=16, pady=(14, 4))
    value_size = 20 if "_" in str(value) or len(str(value)) > 8 else 26
    copy_field(card, value, font=("Arial", value_size, "bold"), text_color=color, height=38,
               fill="x", padx=16, pady=(0, 14))

    return card


# Dashboard shows only the most recent N scans so it stays fast and
# fits the card without turning into an endless list; the full history
# is still available on the Logs page.
RECENT_ACTIVITY_LIMIT = 10


def read_logs(limit=None):
    path = os.path.join(LOG_DIR, "events.jsonl")
    if not os.path.exists(path):
        return []

    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"raw": line})

    if limit:
        return events[-limit:]
    return events


def build_sidebar():

    ctk.CTkFrame(sidebar, fg_color="transparent", height=24).pack(fill="x")

    pages = [
        ("Dashboard", show_dashboard),
        ("Scan", show_scan),
        ("Logs", show_logs),
        ("About", show_about),
    ]

    for name, command in pages:
        button = ctk.CTkButton(
            sidebar,
            text=name,
            height=42,
            corner_radius=8,
            anchor="w",
            fg_color="transparent",
            hover_color="#1b2734",
            text_color="#c8d2dc",
            command=command
        )
        button.pack(fill="x", padx=14, pady=4)
        nav_buttons[name] = button

    audit_card = ctk.CTkFrame(
        sidebar,
        fg_color="#111b26",
        border_color="#1d2a38",
        border_width=1,
        corner_radius=10,
    )
    audit_card.pack(
        side="bottom",
        fill="x",
        padx=16,
        pady=18
    )

    audit_note = ctk.CTkLabel(
        audit_card,
        text="Saved locally after\nevery scan",
        font=("Arial", 12),
        text_color="#aab8c6",
        justify="center",
        anchor="center",
    )
    audit_note.pack(
        fill="x",
        padx=16,
        pady=14
    )


def show_dashboard():
    clear_content()
    set_active("Dashboard")

    page = ctk.CTkFrame(content_frame, fg_color=BG)
    page.pack(fill="both", expand=True, padx=28, pady=24)
    page.grid_columnconfigure(0, weight=1)
    page.grid_rowconfigure(2, weight=1)

    hero = ctk.CTkFrame(page, fg_color=PANEL_BG, corner_radius=8, border_width=1, border_color=BORDER)
    hero.grid(row=0, column=0, sticky="ew", pady=(0, 16))

    copy_field(hero, "TLS Security Analyzer", font=("Arial", 30, "bold"), text_color="#ffffff", height=42,
               fill="x", padx=24, pady=(18, 4))
    copy_field(hero, "Review security posture, certificate health, protocol probes, HTTP controls, and audit history.",
               font=("Arial", 15), text_color=TEXT_MUTED, height=26, fill="x", padx=24, pady=(0, 18))

    events = read_logs()
    total = len(events)
    low = sum(1 for item in events if item.get("risk_level", item.get("status")) == "Low")
    medium = sum(1 for item in events if item.get("risk_level", item.get("status")) == "Medium")
    high = sum(1 for item in events if item.get("risk_level", item.get("status")) == "High")
    critical = sum(1 for item in events if item.get("risk_level", item.get("status")) == "Critical")

    stats = ctk.CTkFrame(page, fg_color="transparent")
    stats.grid(row=1, column=0, sticky="ew", pady=(0, 12))
    make_stat(stats, "Total Scans", total, "#ffffff")
    make_stat(stats, "Low", low, "#2ecc71")
    make_stat(stats, "Medium", medium, "#f39c12")
    make_stat(stats, "High", high, "#ff7777")
    make_stat(stats, "Critical", critical, "#e74c3c")

    recent_card = ctk.CTkFrame(page, fg_color=PANEL_BG, corner_radius=8, border_width=1, border_color=BORDER)
    recent_card.grid(row=2, column=0, sticky="nsew")
    recent_card.grid_columnconfigure(0, weight=1)
    recent_card.grid_rowconfigure(1, weight=1)

    recent_title = copy_field(recent_card, "Recent Activity", font=("Arial", 20, "bold"), text_color="#ffffff", height=30)
    recent_title.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 10))

    # Exactly eight recent rows are shown; full history remains in Logs.
    # This deliberately is a normal frame, not a second scroll container.
    recent_list = ctk.CTkFrame(recent_card, fg_color="transparent")
    recent_list.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
    recent = list(reversed(read_logs(limit=RECENT_ACTIVITY_LIMIT)))
    if not recent:
        copy_field(recent_list, "No scans yet. Use the Scan section to analyze a domain.",
                   text_color=TEXT_MUTED, font=("Arial", 15), height=28,
                   fill="x", padx=8, pady=(0, 18))
    else:
        for item in recent:
            domain = item.get("domain", "Unknown")
            status = item.get("scan_status", item.get("status", "Unknown"))
            risk_level = item.get("risk_level", "N/A")
            timestamp = item.get("timestamp", "No timestamp")

            row = ctk.CTkFrame(recent_list, fg_color=PANEL_ALT, corner_radius=8, border_width=1, border_color=BORDER)
            row.pack(fill="x", padx=6, pady=3)

            copy_field(
                row, domain, font=("Arial", 15, "bold"), text_color="#ffffff",
                side="left", fill="x", expand=True, padx=(14, 0), pady=4
            )
            copy_field(row, timestamp, font=("Arial", 12), text_color=TEXT_MUTED,
                       side="left", padx=10, pady=4)
            copy_field(row, f"{status} / {risk_level}", font=("Arial", 14, "bold"), text_color=status_color(risk_level),
                       side="right", padx=14, pady=4)


def show_scan(prefill=None):
    global result_frame, input_box, scan_btn, scan_progress, scan_status

    clear_content()
    set_active("Scan")

    page = ctk.CTkFrame(content_frame, fg_color=BG)
    page.pack(fill="both", expand=True)

    make_header(
        page,
        "Scan",
        "Run a TLS scan for a domain and review the security result."
    )

    controls = ctk.CTkFrame(page, fg_color=PANEL_BG, corner_radius=8, border_width=1, border_color=BORDER)
    controls.pack(fill="x", padx=28, pady=(4, 14))

    row = ctk.CTkFrame(controls, fg_color="transparent")
    row.pack(fill="x", padx=18, pady=(18, 10))

    input_box = ctk.CTkEntry(row, height=42, placeholder_text="example.com", font=("Arial", 15))
    input_box.pack(side="left", fill="x", expand=True, padx=(0, 10))
    input_box.insert(0, prefill or current_domain)
    input_box.bind("<Return>", lambda _event: scan())
    configure_domain_entry(input_box)

    scan_btn = ctk.CTkButton(row, text="Scan", width=120, height=42, command=scan)
    scan_btn.pack(side="left")

    scan_progress = ctk.CTkProgressBar(controls, mode="indeterminate")
    scan_progress.set(0)

    scan_status = ctk.CTkLabel(
        controls,
        text="",
        font=("Arial", 13),
        text_color=TEXT_MUTED,
        anchor="w"
    )

    result_frame = ctk.CTkScrollableFrame(page, fg_color="transparent")
    result_frame.pack(fill="both", expand=True, padx=18, pady=(0, 18))
    make_fast_scroll(result_frame)

    if is_scanning:
        set_loading_state(True)
    elif last_scan_data:
        render_scan_result(**last_scan_data)


def show_logs():
    clear_content()
    set_active("Logs")

    page = ctk.CTkFrame(content_frame, fg_color=BG)
    page.pack(fill="both", expand=True)

    make_header(
        page,
        "Logs",
        "Raw local audit events. Use Dashboard for the summary and Logs for review or troubleshooting."
    )

    card = ctk.CTkFrame(page, fg_color=PANEL_BG, corner_radius=8, border_width=1, border_color=BORDER)
    card.pack(fill="both", expand=True, padx=28, pady=(4, 24))
    card.grid_columnconfigure(0, weight=1)
    card.grid_rowconfigure(1, weight=1)

    top = ctk.CTkFrame(card, fg_color="transparent")
    top.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 8))

    copy_field(top, "Audit log · events.jsonl", font=("Arial", 18, "bold"), text_color="#ffffff", height=30,
               side="left", fill="x", expand=True)
    ctk.CTkButton(top, text="Reload", width=100, command=show_logs).pack(side="right")

    events = read_logs()
    text = "No log entries yet." if not events else "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
    make_copy_button(top, text, text="Copy all").pack(side="right", padx=(0, 8))
    textbox = make_readonly_textbox(card, text, font=("Consolas", 13), wrap="word", own_wheel=True)
    textbox.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))


def show_about():
    clear_content()
    set_active("About")

    page = ctk.CTkScrollableFrame(content_frame, fg_color=BG)
    page.pack(fill="both", expand=True)
    make_fast_scroll(page)

    make_header(
        page,
        "About",
        "A focused TLS/HTTPS posture assessment tool, its checks, reports, and scope."
    )

    card = ctk.CTkFrame(page, fg_color=PANEL_BG, corner_radius=8, border_width=1, border_color=BORDER)
    card.pack(fill="x", padx=28, pady=(4, 24))

    sections = [
        ("TLS protocol probes", "Tests TLS 1.3 through TLS 1.0. Each result is shown as SUPPORTED, NOT_SUPPORTED, or PROBE_ERROR with an explanation."),
        ("Certificate validation", "Records receipt, chain and hostname verification, issuer, SAN, expiration, public-key metadata, signature algorithm, and a self-signed heuristic."),
        ("Cipher suites", "Explains the negotiated cipher's encryption, key exchange, authentication, strength, and any legacy-algorithm warning."),
        ("HTTP security headers", "Checks HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, and CORP using HEAD with a GET fallback."),
        ("Findings and risk", "Builds evidence-based findings with recommendations. Only successful scans receive a score: Critical 40, High 25, Medium 15, Low 5."),
        ("Audit log", f"Raw scan events are kept locally for review and troubleshooting: {LOG_DIR}"),
        ("Reports", f"Every GUI scan saves JSON and PDF reports here: {REPORT_DIR}"),
        ("Scope", "This is a TLS/HTTPS posture analyzer, not a port scanner, exploitation tool, or full vulnerability scanner. Scan only systems you own or are authorized to assess."),
    ]

    for title, text in sections:
        block = ctk.CTkFrame(card, fg_color=PANEL_ALT, corner_radius=8)
        block.pack(fill="x", padx=18, pady=8)

        copy_field(block, title, font=("Arial", 17, "bold"), text_color="#ffffff", height=28,
                   fill="x", padx=16, pady=(12, 2))
        description = make_readonly_textbox(block, text, font=("Arial", 14), text_color=TEXT_MUTED,
                                             fg_color="transparent", border_width=0, height=54, wrap="word",
                                             activate_scrollbars=False)
        description.pack(fill="x", padx=16, pady=(0, 12))


def status_color(status):
    colors = {
        "Low": "#2ecc71",
        "Medium": "#f39c12",
        "High": "#ff7777",
        "Critical": "#e74c3c",
        "Unreachable": "#7f8c8d",
        "SUCCESS": "#2ecc71",
        "TIMEOUT": "#f39c12",
        "DNS_ERROR": "#e74c3c",
        "TLS_ERROR": "#e74c3c",
        "CONNECTION_ERROR": "#e74c3c",
    }
    return colors.get(status, "#d0d0d0")


def set_loading_state(loading):
    if scan_btn is not None and scan_btn.winfo_exists():
        scan_btn.configure(text="Loading..." if loading else "Scan", state="disabled" if loading else "normal")

    if scan_progress is not None and scan_progress.winfo_exists():
        if loading:
            if not scan_progress.winfo_ismapped():
                scan_progress.pack(fill="x", padx=18, pady=(0, 8))
            scan_progress.start()
        else:
            scan_progress.stop()
            scan_progress.set(0)
            scan_progress.pack_forget()

    if scan_status is not None and scan_status.winfo_exists():
        scan_status.configure(text="Scanning domain..." if loading else "")
        if loading and not scan_status.winfo_ismapped():
            scan_status.pack(fill="x", padx=18, pady=(0, 16))
        elif not loading:
            scan_status.pack_forget()


# =========================
# RENDER
# =========================

def render_scan_result(domain, status, color, tls, tls_map, summary, cert, error, cipher=None,
                       pdf_report=None, findings=None, certificate_info=None, cipher_info=None,
                       security_headers=None, tls_probe_details=None, risk_level="N/A", risk_score=None,
                       scan_status="SUCCESS", duration_seconds=None):
    if result_frame is None:
        return

    findings = findings or []
    certificate_info = certificate_info or {}
    cipher_info = cipher_info or cipher_details(cipher, tls)
    security_headers = security_headers or {}
    risk_score, risk_level, risk_color = calculate_risk_score(findings, scan_status)

    for w in result_frame.winfo_children():
        w.destroy()

    card = ctk.CTkFrame(result_frame, fg_color=PANEL_BG, corner_radius=8, border_width=1, border_color=BORDER)
    card.pack(fill="x", expand=False, padx=10, pady=10)

    header = ctk.CTkFrame(card, fg_color="transparent")
    header.pack(fill="x", padx=20, pady=(18, 12))

    domain_box = make_readonly_textbox(
        header, domain, font=("Arial", 24, "bold"), text_color="#ffffff",
        fg_color="transparent", border_width=0, height=58, wrap="char",
    )
    domain_box.pack(side="left", fill="x", expand=True, padx=(0, 12))

    if pdf_report:
        ctk.CTkButton(
            header,
            text="Open PDF",
            width=100,
            height=34,
            command=lambda path=pdf_report: open_file_path(path)
        ).pack(side="right", padx=(0, 12))

    metrics = ctk.CTkFrame(card, fg_color="transparent")
    metrics.pack(fill="x", padx=14, pady=(0, 12))
    make_stat(metrics, "Scan Status", scan_status, status_color(scan_status))
    make_stat(metrics, "Risk Level", risk_level, risk_color)
    make_stat(metrics, "Risk Score", f"{risk_score}/100" if risk_score is not None else "N/A", risk_color)
    make_stat(metrics, "Current TLS", tls or "Unknown", "#ffffff")
    make_stat(metrics, "HSTS", "Yes" if summary["hsts"] else "No", "#2ecc71" if summary["hsts"] else "#f39c12")
    make_stat(metrics, "Chain verified", "Yes" if summary["chain_verified"] else "No", "#2ecc71" if summary["chain_verified"] else "#e74c3c")

    table = ctk.CTkFrame(card, fg_color=PANEL_ALT, corner_radius=8)
    table.pack(fill="x", padx=20, pady=10)

    rows = [
        ("IP", summary["ip"]),
        ("Issuer", summary["issuer"]),
        ("Subject / CN", f"{certificate_info.get('subject', 'Unknown')} / {certificate_info.get('common_name', 'Unknown')}"),
        ("SAN", ", ".join(certificate_info.get("san", [])) or "Unknown"),
        ("Expiration", summary["expiration"]),
        ("Hostname verification", "Valid" if summary["hostname_verified"] else "Not verified"),
        ("Certificate key", f"{certificate_info.get('key_type', 'Unknown')} {certificate_info.get('key_size') or ''}".strip()),
        ("Signature algorithm", certificate_info.get("signature_algorithm", "Unknown")),
        ("Risk Level", risk_level),
        ("Supported TLS Versions", summary["tls_list"]),
        ("Cipher", f"{cipher_info['name']} ({cipher_info['bits']} bits, {cipher_info['strength']})"),
        ("HSTS value", summary["hsts_value"]),
        ("Scan duration", f"{duration_seconds} seconds" if duration_seconds is not None else "Unknown"),
    ]

    for k, v in rows:
        row = ctk.CTkFrame(table, fg_color="transparent")
        row.pack(fill="x", padx=15, pady=7)

        is_multiline = k in {"IP", "SAN"} or len(str(v)) > 105
        copy_field(row, k, width=260, font=("Arial", 15, "bold"), text_color="#ffffff",
                   side="left", anchor="n" if is_multiline else "center")
        if is_multiline:
            copy_wrapped_field(row, v, side="left", fill="x", expand=True)
        else:
            copy_field(row, v, font=("Arial", 15), text_color="#d0d0d0", side="left", fill="x", expand=True)

    panel1 = ctk.CTkFrame(card, fg_color=PANEL_ALT, corner_radius=8)
    panel1.pack(fill="x", padx=20, pady=(10, 10))
    copy_field(panel1, "Findings", font=("Arial", 17, "bold"), text_color="#ffffff",
               height=28, fill="x", padx=14, pady=(12, 4))
    findings_text = format_findings(findings)
    findings_height = max(42, 14 + 17 * (findings_text.count("\n") + 1))
    findings_box = make_readonly_textbox(
        panel1, findings_text, font=("Arial", 14), height=findings_height, wrap="word",
        fg_color=PANEL_ALT, border_width=0, activate_scrollbars=False,
    )
    findings_box.pack(fill="x", padx=14, pady=(0, 14))

    if tls_probe_details:
        probes_panel = ctk.CTkFrame(card, fg_color=PANEL_ALT, corner_radius=8)
        probes_panel.pack(fill="x", padx=20, pady=(0, 16))
        copy_field(probes_panel, "TLS Protocol Probes", font=("Arial", 17, "bold"), text_color="#ffffff",
                   height=28, fill="x", padx=14, pady=(12, 6))
        for protocol, probe in tls_probe_details.items():
            result = probe.get("status", "Unknown")
            detail = probe.get("error") or ("Handshake successful" if result == "SUPPORTED" else "No additional detail")
            color = "#2ecc71" if result == "SUPPORTED" else "#f39c12" if result == "PROBE_ERROR" else "#e74c3c"
            row = ctk.CTkFrame(probes_panel, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            copy_field(row, protocol, font=("Arial", 13, "bold"), text_color="#ffffff",
                       width=115, side="left")
            copy_field(row, result, font=("Arial", 13), text_color=color,
                       width=140, side="left")
            copy_field(row, detail, font=("Arial", 15), text_color="#d0d0d0", side="left", fill="x", expand=True)

    if security_headers:
        headers_panel = ctk.CTkFrame(card, fg_color=PANEL_ALT, corner_radius=8)
        headers_panel.pack(fill="x", padx=20, pady=(0, 16))
        copy_field(headers_panel, "HTTP Security Headers", font=("Arial", 17, "bold"), text_color="#ffffff",
                   height=28, fill="x", padx=14, pady=(12, 6))
        for name, header in security_headers.items():
            row = ctk.CTkFrame(headers_panel, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=3)
            header_value = header["value"]
            if len(str(header_value)) > 105:
                copy_field(row, name, font=("Arial", 13, "bold"), text_color="#ffffff",
                           width=260, side="left", anchor="n")
                copy_field(row, "Present" if header["present"] else "Missing", font=("Arial", 13),
                           text_color="#2ecc71" if header["present"] else "#f39c12", width=75, side="left", anchor="n")
                copy_wrapped_field(row, header_value, side="left", fill="x", expand=True)
            else:
                copy_field(row, name, font=("Arial", 13, "bold"), text_color="#ffffff",
                           width=260, side="left")
                copy_field(row, "Present" if header["present"] else "Missing", font=("Arial", 13),
                           text_color="#2ecc71" if header["present"] else "#f39c12", width=75, side="left")
                copy_field(row, header_value, font=("Arial", 15), text_color="#d0d0d0", side="left", fill="x", expand=True)


# =========================
# SCAN
# =========================

def scan_worker(domain):
    scan_result = perform_scan(domain)
    timestamp = scan_result["timestamp"]
    report_stem = make_report_stem()

    save_log({
        "timestamp": timestamp,
        "domain": domain,
        "scan_status": scan_result["scan_status"],
        "risk_level": scan_result["risk_level"],
        "risk_score": scan_result["risk_score"],
        "error": scan_result["error"]
    })

    report_data = {
        "report_stem": report_stem,
        **scan_result,
        "status": scan_result["scan_status"],
        "risk_analysis": format_findings(scan_result["findings"]),
        "json_report": os.path.join(REPORT_DIR, f"{report_stem}.json"),
        "pdf_report": os.path.join(REPORT_DIR, f"{report_stem}.pdf")
    }

    save_report(report_data)
    try:
        save_pdf_report(report_data)
    except Exception as e:
        print("PDF report error:", e)

    data = {
        "domain": domain,
        "status": scan_result["scan_status"],
        "color": scan_result["risk_color"],
        "tls": scan_result["current_tls"],
        "tls_map": scan_result["tls_versions"],
        "summary": scan_result["summary"],
        "cert": None,
        "error": scan_result["error"],
        "cipher": None,
        "certificate_info": scan_result["certificate"],
        "cipher_info": scan_result["cipher"],
        "security_headers": scan_result["security_headers"],
        "tls_probe_details": scan_result["tls_probe_details"],
        "findings": scan_result["findings"],
        "risk_level": scan_result["risk_level"],
        "risk_score": scan_result["risk_score"],
        "scan_status": scan_result["scan_status"],
        "duration_seconds": scan_result["duration_seconds"],
        "pdf_report": report_data["pdf_report"]
    }

    app.after(0, lambda: finish_scan(data))


def finish_scan(data):
    global is_scanning, last_scan_data

    is_scanning = False
    last_scan_data = data
    show_scan(prefill=data["domain"])
    set_loading_state(False)


def scan():
    if input_box is None:
        return
    start_scan_from_value(input_box.get())


def start_scan_from_value(value):
    global current_domain, is_scanning, last_scan_data

    domain = normalize_domain(value)
    if not domain:
        return

    if is_scanning:
        return

    current_domain = domain
    is_scanning = True
    last_scan_data = None
    show_scan(prefill=domain)
    set_loading_state(True)
    threading.Thread(target=scan_worker, args=(domain,), daemon=True).start()


install_label_copy_support()
install_fast_mousewheel()
build_sidebar()
show_dashboard()

app.mainloop()
