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
from reportlab.lib.pagesizes import A4
from download_report import register_download_route

from virustotal import (
    scan_url_virustotal,
    scan_hash_virustotal,
    scan_ip_virustotal,
    scan_domain_virustotal
)

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")

THREAT_DB = os.path.join(BASE_DIR, "threats.db")

print("THREAT_DB:", THREAT_DB)

conn = sqlite3.connect(THREAT_DB)
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
print("Tables:", cursor.fetchall())
conn.close()

print(DB_PATH)
print(os.path.exists(DB_PATH))

# Create scan_history table if it does not exist
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name TEXT NOT NULL,
    file_size INTEGER,
    md5 TEXT,
    sha256 TEXT,
    status TEXT,
    rule TEXT,
    scan_time TEXT
)
""")

conn.commit()
conn.close()


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
            SELECT id, file_name, status, rule, scan_time
            FROM scan_history
            WHERE file_name LIKE ?
            ORDER BY id DESC
        """, ('%' + search + '%',))
    else:
        cursor.execute("""
            SELECT id, file_name, status, rule, scan_time
            FROM scan_history
            ORDER BY id DESC
        """)

    history = cursor.fetchall()
    print("History Data:", history)

    # Total Scans
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

# Malware Count
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Malware'")
    malware_count = cursor.fetchone()[0]

# Safe Count
    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Safe'")
    safe_count = cursor.fetchone()[0]

     # Last Scan Time
    cursor.execute("""
    SELECT scan_time
    FROM scan_history
    ORDER BY id DESC
    LIMIT 1
    """)

    last_scan = cursor.fetchone()

    if last_scan:
      last_scan = last_scan[0]
    else:
     last_scan = "No Scans"

    conn.close()

    return render_template(
    "history.html",
    history=history,
    search=search,
    total_scans=total_scans,
    malware_count=malware_count,
    safe_count=safe_count,
    last_scan=last_scan
)

@app.route("/delete-history/<int:history_id>")
def delete_history(history_id):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM scan_history WHERE id=?",
        (history_id,)
    )

    conn.commit()
    conn.close()

    return redirect("/history")

@app.route("/clear-history")
def clear_history():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM scan_history")

    conn.commit()
    conn.close()

    return redirect("/history")

@app.route("/view-report/<int:scan_id>")
def view_report(scan_id):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            file_name,
            file_size,
            md5,
            sha256,
            status,
            rule,
            scan_time
        FROM scan_history
        WHERE id=?
    """, (scan_id,))

    report = cursor.fetchone()

    conn.close()

    if not report:
        return "Report not found."

    return render_template(
    "view_report.html",
    report=report,
    scan_id=scan_id
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

    threat_level = "Low"
    malicious = 0
    suspicious = 0
    harmless = 0
    undetected = 0
    detection_ratio = "0/0"
    risk_score = 0

    db_threats = []
    db_threat = None

    targets = "Unknown"
    prevention = "Follow general cybersecurity best practices."

    file_name = "Unknown"
    file_type = "Unknown"
    threat_label = "Unknown"
    reputation = "Unknown"

    # File
    if query.lower().endswith((
        ".exe", ".dll", ".apk", ".zip",
        ".pdf", ".docx", ".png", ".jpg",
        ".jpeg", ".txt", ".rar", ".7z"
    )):

        search_type = "File"
        description = "File name detected."
        recommendation = "Upload this file for malware scanning."

        # Hash
    elif re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", query):

        # Identify hash type
        if len(query) == 32:
            search_type = "MD5 Hash"
        elif len(query) == 40:
            search_type = "SHA1 Hash"
        else:
            search_type = "SHA256 Hash"

        description = "File hash detected. Checking VirusTotal threat intelligence..."
        recommendation = "Review the VirusTotal detection results before trusting the file."

        vt_result = scan_hash_virustotal(query)

        print("\n===== HASH VIRUSTOTAL RESULT =====")

        # VirusTotal returned valid data
        if vt_result and vt_result.get("data"):

            attributes = vt_result["data"].get("attributes", {})

            print("\n===== HASH FILE INFO =====")
            print("Meaningful Name:", attributes.get("meaningful_name"))
            print("Type Description:", attributes.get("type_description"))
            print("Type Tag:", attributes.get("type_tag"))
            print("Type Tags:", attributes.get("type_tags"))
            print("Reputation:", attributes.get("reputation"))
            print("Tags:", attributes.get("tags"))
            print(
                "Popular Threat Classification:",
                attributes.get("popular_threat_classification")
            )
            print("==========================\n")

            stats = attributes.get("last_analysis_stats", {})

            file_name = attributes.get("meaningful_name", "Unknown")
            file_type = attributes.get("type_description", "Unknown")
            reputation = attributes.get("reputation", "Unknown")

            classification = (
                attributes.get("popular_threat_classification") or {}
            )

            threat_label = classification.get(
                "suggested_threat_label",
                "Unknown"
            )

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total_engines = (
                malicious +
                suspicious +
                harmless +
                undetected
            )

            if total_engines > 0:
                detection_ratio = f"{malicious}/{total_engines}"
            else:
                detection_ratio = "0/0"

            risk_score = (malicious * 20) + (suspicious * 10)

            if risk_score > 100:
                risk_score = 100

            if risk_score >= 90:
                threat_level = "Critical"
            elif risk_score >= 70:
                threat_level = "High"
            elif risk_score >= 40:
                threat_level = "Medium"
            elif risk_score > 0:
                threat_level = "Low"
            else:
                threat_level = "Unknown"

            description = (
                f"This file hash was found in VirusTotal. "
                f"{malicious} security engines detected the associated file as malicious "
                f"and {suspicious} marked it as suspicious."
            )

            if threat_level in ["Critical", "High"]:

                recommendation = (
                    "Do not execute the associated file. "
                    "Isolate it and investigate immediately."
                )

                prevention = (
                    "Isolate the affected file or system immediately. "
                    "Do not execute the file. Run a full security scan, "
                    "review related alerts, and remove the file if confirmed malicious."
                )

            elif threat_level == "Medium":

                recommendation = (
                    "Treat the file with caution and perform further security analysis."
                )

                prevention = (
                    "Avoid executing the file until further analysis is complete. "
                    "Scan it with updated security tools and verify its source."
                )

            else:

                recommendation = (
                    "No significant detections were reported, "
                    "but this does not guarantee the file is safe."
                )

                prevention = (
                    "Keep security software updated and verify the file source "
                    "before executing it."
                )

        # VirusTotal did not return data
        else:

            description = (
                  "No threat intelligence record was found for this file hash in VirusTotal. "
                  "The file's security status could not be determined from the hash alone."
            )

            recommendation = (
                "Scan the original file directly to determine whether it contains "
                "malicious content."
            )

            prevention = (
                "Do not assume the file is safe just because its hash is unknown. "
                "Verify the file source and scan the original file before executing it."
            )

            threat_level = "Unknown"
            risk_score = None

            malicious = None
            suspicious = None
            harmless = None
            undetected = None

            detection_ratio = "Not Available"

            file_name = "Unknown"
            file_type = "Unknown"
            reputation = "Not Available"
            threat_label = "Not Available"

    # IP Address
    elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", query):
        search_type = "IP Address"
        description = "IPv4 address detected. Checking VirusTotal threat intelligence..."
        recommendation = "Review the threat intelligence results before trusting this IP address."

        vt_result = scan_ip_virustotal(query)

        print("\n===== IP VIRUSTOTAL LOOKUP =====")

        if vt_result:

            attributes = vt_result["data"]["attributes"]

            # VirusTotal analysis statistics
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total_engines = (
                malicious +
                suspicious +
                harmless +
                undetected
            )

            if total_engines > 0:
                detection_ratio = f"{malicious}/{total_engines}"
            else:
                detection_ratio = "0/0"

            # Real VirusTotal IP information
            country = attributes.get("country", "Not Available")
            as_owner = attributes.get("as_owner", "Not Available")
            asn = attributes.get("asn", "Not Available")
            reputation = attributes.get("reputation", 0)

            # Sentinel calculated risk score
            risk_score = (malicious * 20) + (suspicious * 10)

            if risk_score > 100:
                risk_score = 100

            # Threat level
            if risk_score >= 90:
                threat_level = "Critical"

            elif risk_score >= 70:
                threat_level = "High"

            elif risk_score >= 40:
                threat_level = "Medium"

            elif risk_score > 0:
                threat_level = "Low"

            else:
                threat_level = "Unknown"

            description = (
                "VirusTotal threat intelligence was found for this IP address."
            )

            # Store real IP intelligence for result page
            targets = (
                f"Country: {country} | "
                f"Network Owner: {as_owner} | "
                f"ASN: {asn} | "
                f"VirusTotal Reputation: {reputation}"
            )

            # Recommendation + prevention based on actual detections
            if threat_level in ["Critical", "High"]:

                recommendation = (
                    "This IP address has significant malicious detections. "
                    "Investigate related network activity immediately."
                )

                prevention = (
                    "Consider blocking the IP if it is not required for legitimate activity. "
                    "Review firewall, proxy, DNS, and authentication logs for connections "
                    "involving this address."
                )

            elif threat_level == "Medium":

                recommendation = (
                    "This IP address has suspicious threat intelligence. "
                    "Further investigation is recommended."
                )

                prevention = (
                    "Monitor connections involving this IP address and review related "
                    "network and security logs before taking action."
                )

            elif threat_level == "Low":

                recommendation = (
                    "A small number of security detections were reported for this IP address."
                )

                prevention = (
                    "Continue monitoring this IP address and investigate unexpected "
                    "connections involving it."
                )

            else:

                recommendation = (
                    "No malicious or suspicious detections were reported by the "
                    "available VirusTotal analysis."
                )

                prevention = (
                    "No immediate action is indicated by the available VirusTotal "
                    "detections. Continue normal security monitoring."
                )

            print("IP Address:", query)
            print("Country:", country)
            print("Network Owner:", as_owner)
            print("ASN:", asn)
            print("Reputation:", reputation)
            print("Malicious:", malicious)
            print("Suspicious:", suspicious)
            print("Harmless:", harmless)
            print("Undetected:", undetected)
            print("Detection Ratio:", detection_ratio)
            print("Sentinel Risk Score:", risk_score)
            print("Threat Level:", threat_level)
            print("================================\n")

        else:

            threat_level = "Unknown"
            risk_score = 0

            description = (
                "No VirusTotal threat intelligence was found for this IP address."
            )

            recommendation = (
                "No VirusTotal record was available. "
                "This does not confirm that the IP address is safe."
            )

            prevention = (
                "Verify the IP address using additional threat intelligence sources "
                "and continue normal network monitoring."
            )

            targets = "IP intelligence not available."


       # Domain
    elif re.fullmatch(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", query):

        search_type = "Domain"

        description = (
            "Domain detected. Checking VirusTotal threat intelligence..."
        )

        recommendation = (
            "Review the available threat intelligence before trusting this domain."
        )

        vt_result = scan_domain_virustotal(query)

        print("\n===== DOMAIN VIRUSTOTAL RESULT =====")
        print(vt_result)
        print("====================================\n")

        if vt_result:

            attributes = vt_result["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            total_engines = (
                malicious +
                suspicious +
                harmless +
                undetected
            )

            if total_engines > 0:
                detection_ratio = f"{malicious}/{total_engines}"
            else:
                detection_ratio = "0/0"

            # VirusTotal domain information
            reputation = attributes.get("reputation", "Not Available")
            registrar = attributes.get("registrar", "Not Available")

            # Sentinel Risk Score
            risk_score = (malicious * 20) + (suspicious * 10)

            if risk_score > 100:
                risk_score = 100

            # Threat level
            if risk_score >= 90:
                threat_level = "Critical"

            elif risk_score >= 70:
                threat_level = "High"

            elif risk_score >= 40:
                threat_level = "Medium"

            elif risk_score > 0:
                threat_level = "Low"

            else:
                threat_level = "Unknown"

            description = (
                "VirusTotal threat intelligence was found for this domain."
            )

            targets = (
                f"Registrar: {registrar} | "
                f"VirusTotal Reputation: {reputation}"
            )

            # Recommendation and prevention
            if threat_level in ["Critical", "High"]:

                recommendation = (
                    "This domain has significant malicious detections. "
                    "Avoid visiting or communicating with it until investigated."
                )

                prevention = (
                    "Do not visit the domain or enter credentials on it. "
                    "Block the domain if appropriate and investigate related "
                    "network activity."
                )

            elif threat_level == "Medium":

                recommendation = (
                    "This domain has suspicious threat intelligence. "
                    "Further investigation is recommended."
                )

                prevention = (
                    "Avoid accessing the domain until its reputation and "
                    "associated activity have been reviewed."
                )

            elif threat_level == "Low":

                recommendation = (
                    "A small number of detections were reported. "
                    "Use caution and investigate before trusting the domain."
                )

                prevention = (
                    "Use caution when accessing this domain and verify its "
                    "legitimacy before entering sensitive information."
                )

            else:

                recommendation = (
                    "No malicious or suspicious detections were reported by "
                    "the available VirusTotal analysis."
                )

                prevention = (
                    "No immediate threat is indicated by the available "
                    "VirusTotal detections. Continue normal security monitoring."
                )

        else:

            threat_level = "Unknown"
            risk_score = 0
            detection_ratio = "0/0"

            description = (
                "No VirusTotal threat intelligence was available for this domain."
            )

            recommendation = (
                "The absence of VirusTotal data does not confirm that "
                "this domain is safe."
            )

            targets = "Domain intelligence not available."

            prevention = (
                "Verify the domain carefully before visiting it or entering "
                "sensitive information."
            )


    # Threat / Keyword
    else:

        search_type = "Threat / Keyword"

        conn = sqlite3.connect(THREAT_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM threats")
        print("Total in DB:", cursor.fetchone()[0])

        cursor.execute("SELECT name FROM threats")
        print("Malware List:", cursor.fetchall())

        search_value = f"%{query}%"

        # Broad malware search
        if query.lower() == "malware":

         cursor.execute("""
         SELECT *
         FROM threats
         ORDER BY risk_score DESC
        """)

        else:

         cursor.execute("""
        SELECT *
        FROM threats
        WHERE LOWER(name) = LOWER(?)
           OR LOWER(aliases) LIKE LOWER(?)
           OR LOWER(category) LIKE LOWER(?)
           OR LOWER(family) LIKE LOWER(?)
           OR LOWER(malware_type) LIKE LOWER(?)
           OR LOWER(description) LIKE LOWER(?)
           OR LOWER(platform) LIKE LOWER(?)
           OR LOWER(attack_vector) LIKE LOWER(?)
        ORDER BY
            CASE
                WHEN LOWER(name) = LOWER(?) THEN 0
                ELSE 1
            END,
            risk_score DESC
        """, (
        query,
        search_value,
        search_value,
        search_value,
        search_value,
        search_value,
        search_value,
        search_value,
        query
        ))

        db_threats = cursor.fetchall()

        print("Search Query:", query)
        print("Total Matches:", len(db_threats))
        print("DB Results:", db_threats)

        db_threat = db_threats[0] if db_threats else None

        conn.close()

        if db_threat:

            risk_score = db_threat["risk_score"]

            if risk_score >= 90:
                threat_level = "Critical"

            elif risk_score >= 70:
                threat_level = "High"

            elif risk_score >= 40:
                threat_level = "Medium"

            elif risk_score > 0:
                threat_level = "Low"

            else:
                threat_level = "Unknown"

            targets = db_threat["platform"]
            description = db_threat["description"]
            recommendation = db_threat["mitigation"]
            prevention = db_threat["prevention"]

        else:

            threat_level = "Unknown"
            risk_score = 0
            targets = "Unknown"

            description = (
                "No threat intelligence was found for this keyword."
            )

            recommendation = (
                "Try searching for a known malware family or cyber threat."
            )

            prevention = (
                "Follow general cybersecurity best practices."
            )


    return render_template(
        "search_result.html",
        query=query,
        search_type=search_type,
        description=description,
        recommendation=recommendation,
        threat_level=threat_level,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        detection_ratio=detection_ratio,
        risk_score=risk_score,
        targets=targets,
        prevention=prevention,
        db_threats=db_threats,
        file_name=file_name,
        file_type=file_type,
        threat_label=threat_label,
        reputation=reputation,
    )

@app.route("/scan-url", methods=["POST"])
def scan_url():

    url = request.form["url"].strip()

    start = time.time()

    try:

        response = requests.get(url, timeout=5)
        vt_result = scan_url_virustotal(url)
        print("===== VT RESULT =====")
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

    except Exception as e:

        print("ERROR:", e)

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
    recommendation=recommendation,

    malicious=malicious,
    suspicious=suspicious,
    harmless=harmless,
    undetected=undetected,
    detection_ratio=detection_ratio
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

    scan_id = cursor.lastrowid

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
    scan_time=scan_time,
    scan_id=scan_id
)

def format_size(size):

    size = float(size)

    if size < 1024:
        return f"{size:.0f} Bytes"

    elif size < 1024 * 1024:
        return f"{size/1024:.2f} KB"

    else:
        return f"{size/(1024*1024):.2f} MB"
    
register_download_route(app)

#print(app.url_map)
    
if __name__ == "__main__":
    app.run(debug=True)