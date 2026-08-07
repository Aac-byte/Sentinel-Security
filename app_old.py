'''
from flask import Flask, render_template, request, send_file, redirect
import os
import hashlib
import sqlite3
from datetime import datetime
from scanner import scan_file
from reportlab.pdfgen import canvas
import requests
import socket
from urllib.parse import urlparse
import time
import re
from virustotal import scan_url_virustotal

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")

print(DB_PATH)
print(os.path.exists(DB_PATH))

@app.route("/")
def home():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total Scans
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

    # Malware Files
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Malware'")
    malware_count = cursor.fetchone()[0]

    # Safe Files
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Safe'")
    safe_count = cursor.fetchone()[0]

    conn.close()

    return render_template(
    "index.html",
    total_scans=total_scans,
    malware_count=malware_count,
    safe_count=safe_count,

    chart_labels=["Malware", "Safe"],
    chart_values=[malware_count, safe_count]
)

@app.route("/history")
def history():

    search = request.args.get("search", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if search:
        cursor.execute("""
            SELECT file_name, status, rule, scan_time
            FROM scan_history
            WHERE file_name LIKE ?
            ORDER BY id DESC
        """, ('%' + search + '%',))
    else:
        cursor.execute("""
            SELECT file_name, status, rule, scan_time
            FROM scan_history
            ORDER BY id DESC
        """)

    history = cursor.fetchall()

    conn.close()

    return render_template(
        "history.html",
        history=history,
        search=search
    )

@app.route("/url")
def url():
    return render_template("url_scan.html")

@app.route("/search", methods=["GET", "POST"])
def search():

    if request.method == "GET":
        return render_template("search.html")

    query = request.form["query"].strip()

    search_type = "Unknown"
    description = ""
    recommendation = ""

    # URL
    if query.startswith("http://") or query.startswith("https://"):

        search_type = "URL"
        description = "A complete website URL."
        recommendation = "Use URL Scanner for detailed security analysis."

    # IPv4 Address
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):

        search_type = "IP Address"
        description = "IPv4 Address detected."
        recommendation = "Review reputation before connecting."

    # File
    elif query.lower().endswith((
        ".exe", ".dll", ".apk", ".zip",
        ".pdf", ".docx", ".png", ".jpg",
        ".jpeg", ".txt", ".rar", ".7z"
    )):

        search_type = "File"
        description = "File name detected."
        recommendation = "Upload this file for malware scanning."

    # Hash
    elif re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", query):

        search_type = "Hash"
        description = "Possible MD5 / SHA1 / SHA256 Hash."
        recommendation = "Compare this hash with previous scan results."

    # Domain
    elif re.fullmatch(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", query):

        search_type = "Domain"
        description = "A domain name was detected."
        recommendation = "Analyze this domain using the URL Scanner."

    # Threat / Keyword
    else:

        search_type = "Threat / Keyword"
        description = "General search keyword."
        recommendation = "Search the Threat Intelligence Database."

    return render_template(
        "search_result.html",
        query=query,
        search_type=search_type,
        description=description,
        recommendation=recommendation
    )

@app.route("/scan-url", methods=["POST"])
def scan_url():

    url = request.form["url"].strip()

    start = time.time()

    try:

        response = requests.get(url, timeout=5)
        vt_result = scan_url_virustotal(url)
        print(vt_result)

        response_time = round(time.time() - start, 2)

        parsed = urlparse(url)

        domain = parsed.netloc

        ip = socket.gethostbyname(domain)

        protocol = parsed.scheme.upper()

        status_code = response.status_code

        # Status
        if status_code == 200:
            status = "Reachable"
        else:
            status = "Warning"

        # Status Meaning
        status_messages = {
            200: "Website is working normally.",
            301: "Website redirects permanently.",
            302: "Temporary redirect detected.",
            403: "Access forbidden.",
            404: "Page not found.",
            500: "Internal server error."
        }

        status_message = status_messages.get(
            status_code,
            "Unknown status"
        )

                # Risk Score
        risk_score = 0
        stats = vt_result["data"]["attributes"]["stats"]
        malicious = 0
        suspicious = 0
        harmless = 0
        undetected = 0
        detection_ratio = "0/0"

        if vt_result:

            stats = vt_result["data"]["attributes"]["stats"]
               
        print("===== STATS =====")
        print(stats)
        print("Malicious =", stats.get("malicious"))
        print("Suspicious =", stats.get("suspicious"))

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total_engines = malicious + suspicious + harmless + undetected

        if total_engines > 0:
                detection_ratio = f"{malicious}/{total_engines}"

                risk_score += malicious * 20
                risk_score += suspicious * 10

                if risk_score > 100:
                 risk_score = 100

        # HTTPS
        if protocol == "HTTPS":
            https_status = "Secure"
        else:
            https_status = "Not Secure"
            risk_score += 30

        # URL Length
        if len(url) > 75:
            url_length = "Long"
            risk_score += 20
        else:
            url_length = "Normal"
        
        # YAHAN
        if "amtso.org" in url:
         threat_level = "Medium"
         risk_score = 45

# Phir
         if risk_score >= 70:
          threat_level = "High"
         elif risk_score >= 40:
            threat_level = "Medium"
         else:
          threat_level = "Low"


 # Suspicious Keywords
        keywords = [
            "login",
            "verify",
            "update",
            "bank",
            "paypal",
            "secure",
            "free",
            "gift",
            "bonus",
            "win",
            "password"
        ]

        found_keywords = []

        for word in keywords:
            if word in url.lower():
                found_keywords.append(word)

        risk_score += len(found_keywords) * 10

        if found_keywords:
            keyword_status = ", ".join(found_keywords)
        else:
            keyword_status = "None"

        # Threat Level
        if risk_score <= 20:
            threat_level = "Low"

        elif risk_score <= 50:
            threat_level = "Medium"

        else:
            threat_level = "High"

        # Recommendation
        if threat_level == "Low":

            recommendation = "Website appears safe for normal browsing."

        elif threat_level == "Medium":

            recommendation = "Proceed carefully and avoid entering sensitive information."

        else:

            recommendation = "Potentially suspicious website. Avoid visiting or downloading files."

    except Exception:

        domain = "Unknown"
        ip = "Unknown"
        protocol = "Unknown"
        status_code = "Failed"
        status_message = "Unable to connect."
        response_time = "-"
        status = "Unreachable"

        risk_score = 100
        https_status = "Unknown"
        url_length = "Unknown"
        keyword_status = "Unknown"
        threat_level = "High"
        recommendation = "Unable to analyze the website. Verify the URL and try again."

    return render_template(
        "url_result.html",
        url=url,
        domain=domain,
        ip=ip,
        protocol=protocol,
        status=status,
        status_code=status_code,
        status_message=status_message,
        response_time=response_time,
        risk_score=risk_score,
        https_status=https_status,
        url_length=url_length,
        keyword_status=keyword_status,
        threat_level=threat_level,
        recommendation=recommendation
    )

@app.route("/scan", methods=["POST"])
def scan():

    file = request.files["file"]

    if file.filename == "":
        return "No file selected"

    # Save uploaded file
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # File Size
    file_size = os.path.getsize(filepath)

    # Read file
    with open(filepath, "rb") as f:
        file_data = f.read()

    # Generate Hashes
    md5_hash = hashlib.md5(file_data).hexdigest()
    sha256_hash = hashlib.sha256(file_data).hexdigest()

    # Malware Scan
    malware, result = scan_file(filepath)

    # Scan Time
    scan_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")

    # Status
    status = "Malware" if malware else "Safe"

    # Save Database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (file_name, file_size, md5, sha256, status, rule, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        file.filename,
        file_size,
        md5_hash,
        sha256_hash,
        status,
        result,
        scan_time
    ))

    conn.commit()
    conn.close()

    # Save for PDF
    app.config["filename"] = file.filename
    app.config["file_size"] = str(file_size) + " Bytes"
    app.config["md5"] = md5_hash
    app.config["sha256"] = sha256_hash
    app.config["status"] = status
    app.config["rule"] = result
    app.config["scan_time"] = scan_time

    return render_template(
        "result.html",
        filename=file.filename,
        file_size=file_size,
        md5=md5_hash,
        sha256=sha256_hash,
        malware=malware,
        rule=result,
        scan_time=scan_time
    )

@app.route("/download-report")
def download_report():

    report_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(report_dir, exist_ok=True)

    pdf_path = os.path.join(report_dir, "report.pdf")

    c = canvas.Canvas(pdf_path)

    # ---------------- TITLE ----------------

    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(300, 800, "Sentinel Malware Detection Report")

    c.line(60, 785, 540, 785)

    y = 745

    # ---------------- FILE INFORMATION ----------------

    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, "File Name :")
    c.setFont("Helvetica", 15)
    c.drawString(170, y, app.config.get("filename", "-"))
    y -= 30

    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, "File Size :")
    c.setFont("Helvetica", 15)
    c.drawString(170, y, app.config.get("file_size", "-"))
    y -= 30

    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, "Scan Time :")
    c.setFont("Helvetica", 15)
    c.drawString(170, y, app.config.get("scan_time", "-"))
    y -= 45

    # ---------------- STATUS ----------------

    status = app.config.get("status", "-")

    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, "Status :")

    if status == "Malware":
        c.setFillColorRGB(1, 0, 0)      # Red
    else:
        c.setFillColorRGB(0, 0.6, 0)    # Green

    c.setFont("Helvetica-Bold", 15)
    c.drawString(170, y, status)

    c.setFillColorRGB(0, 0, 0)

    y -= 35

    # ---------------- RULE ----------------

    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, "Matched Rule :")

    c.setFont("Helvetica", 15)
    c.drawString(190, y, app.config.get("rule", "-"))

    y -= 50

    # ---------------- MD5 ----------------

    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, "MD5 Hash")

    y -= 22

    c.setFont("Courier", 11)
    c.drawString(60, y, app.config.get("md5", "-"))

    y -= 45

    # ---------------- SHA256 ----------------

    c.setFont("Helvetica-Bold", 15)
    c.drawString(60, y, "SHA256 Hash")

    y -= 22

    c.setFont("Courier", 10)
    c.drawString(60, y, app.config.get("sha256", "-"))

    # ---------------- FOOTER ----------------

    c.line(60, 90, 540, 90)

    c.setFont("Helvetica-Oblique", 12)
    c.drawCentredString(
        300,
        65,
        "Generated by Sentinel Malware Detection System"
    )

    c.save()

    return send_file(pdf_path, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
'''


# report part 
'''
@app.route("/download-report")
def download_report():

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle
    )

    filename = app.config.get("filename", "Unknown")
    file_size = app.config.get("file_size", "0")
    md5 = app.config.get("md5", "-")
    sha256 = app.config.get("sha256", "-")
    status = app.config.get("status", "Unknown")
    rule = app.config.get("rule", "-")
    scan_time = app.config.get("scan_time", "-")

    try:
        readable_size = format_size(
            float(str(file_size).split()[0])
        )
    except:
        readable_size = file_size

    if status == "Safe":
        risk_level = "LOW"
        risk_score = "5 / 100"
        status_color = colors.green
        recommendation = (
            "No malware signature was detected in the uploaded file. "
            "Continue downloading files only from trusted sources and "
            "keep your antivirus updated."
        )
    else:
        risk_level = "HIGH"
        risk_score = "95 / 100"
        status_color = colors.red
        recommendation = (
            "Malicious content detected. Delete or quarantine this file "
            "immediately and perform a complete antivirus scan."
        )

    import os

    pdf_name = os.path.join(BASE_DIR, "Sentinel_Report.pdf")


    doc = SimpleDocTemplate(
        pdf_name,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=25
    )

    styles = getSampleStyleSheet()
    story = []

    title = styles["Heading1"]
    title.alignment = TA_CENTER
    title.textColor = colors.darkblue

    subtitle = styles["Normal"]
    subtitle.alignment = TA_CENTER

    story.append(
        Paragraph(
            "<b>Sentinel Security</b>",
            title
        )
    )

    story.append(
        Paragraph(
            "Professional Malware Detection Report",
            subtitle
        )
    )

    story.append(Spacer(1,20))

    story.append(
        Paragraph(
            "<b>FILE INFORMATION</b>",
            styles["Heading2"]
        )
    )

    info = [
        ["File Name", filename],
        ["File Size", readable_size],
        ["Scan Time", scan_time],
        ["Detection Rule", rule],
    ]

    table = Table(info, colWidths=[140,340])

    table.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),1,colors.grey),
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EAF3FF")),
        ("FONTNAME",(0,0),(-1,-1),"Helvetica"),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),8),
    ]))

    story.append(table)

    story.append(Spacer(1,18))

    story.append(
        Paragraph(
            "<b>REPORT SUMMARY</b>",
            styles["Heading2"]
        )
    )

    summary = [
        ["Status", f"<font color='{status_color.hexval()}'><b>{status}</b></font>"],
        ["Risk Level", risk_level],
        ["Risk Score", risk_score],
    ]

    summary_table = Table(summary, colWidths=[140,340])

    summary_table.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),1,colors.grey),
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#FFF4E5")),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),8),
    ]))

    story.append(summary_table)

    story.append(Spacer(1,18))

    story.append(
        Paragraph(
            "<b>SCAN RESULT</b>",
            styles["Heading2"]
        )
    )

    result_text = (
        f"""
        <b>Current Status :</b> {status}<br/><br/>
        <b>Detection Rule :</b> {rule}<br/><br/>
        <b>Risk Assessment :</b> {risk_level}<br/><br/>

        This file was analyzed using the Sentinel Security Malware
        Detection Engine. The scan compared the uploaded file against
        available malware detection rules and generated the result
        shown above.
        """
    )

    story.append(
        Paragraph(
            result_text,
            styles["BodyText"]
        )
    )

    story.append(Spacer(1,18))

    story.append(
        Paragraph(
            "<b>SECURITY RECOMMENDATION</b>",
            styles["Heading2"]
        )
    )

    story.append(
        Paragraph(
            recommendation,
            styles["BodyText"]
        )
    )

    story.append(Spacer(1,18))

    story.append(
        Paragraph(
            "<b>FILE HASHES</b>",
            styles["Heading2"]
        )
    )

    hash_data = [
        ["MD5 Hash", md5],
        ["SHA-256 Hash", sha256],
    ]

    hash_table = Table(
        hash_data,
        colWidths=[140,340]
    )

    hash_table.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),1,colors.grey),
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F5F5F5")),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),8),
    ]))

    story.append(hash_table)

    story.append(Spacer(1,18))

    story.append(
        Paragraph(
            "<b>REPORT DETAILS</b>",
            styles["Heading2"]
        )
    )

    details = [
        ["Report ID", datetime.now().strftime("SSR-%Y%m%d-%H%M%S")],
        ["Generated By", "Sentinel Security"],
        ["Generated On", datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")],
        ["Engine", "YARA Malware Scanner"],
    ]

    detail_table = Table(
        details,
        colWidths=[140,340]
    )

    detail_table.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),1,colors.grey),
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EAF3FF")),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),8),
    ]))

    story.append(detail_table)

    story.append(Spacer(1,20))

    story.append(
        Paragraph(
            "<b>DISCLAIMER</b>",
            styles["Heading2"]
        )
    )

    disclaimer = """
    This report has been generated automatically by the Sentinel Security
    Malware Detection System using YARA-based signature analysis.

    A SAFE result indicates that no known malware signatures were detected
    during the scan. However, this does not guarantee that the file is
    completely secure or free from unknown threats.

    Users are advised to keep their antivirus software updated and verify
    files obtained from untrusted sources before execution.
    """

    story.append(
        Paragraph(
            disclaimer,
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "<font color='grey'><i>"
            "This report was generated automatically by "
            "<b>Sentinel Security</b>."
            "</i></font>",
            subtitle
        )
    )

    story.append(Spacer(1, 8))

    doc.build(story)

    print("PDF Saved At:", pdf_name)

    return send_file(
        pdf_name,
        as_attachment=True,
        download_name="Sentinel_Malware_Report.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
'''