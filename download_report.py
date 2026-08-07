from flask import send_file
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
import sqlite3
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")


class SentinelPDFReport:

    def __init__(self, app, report):

        self.app = app

        self.width = 595
        self.height = 842

        self.margin = 25

        self.primary = HexColor("#0F4C81")
        self.secondary = HexColor("#EAF3FF")
        self.success = HexColor("#198754")
        self.danger = HexColor("#DC3545")
        self.warning = HexColor("#FFF4D6")
        self.gray = HexColor("#666666")
        self.light = HexColor("#F8FAFC")

        self.filename = report[0]
        self.file_size = str(report[1]) + " Bytes"
        self.md5 = report[2]
        self.sha256 = report[3]
        self.status = report[4]
        self.rule = report[5]
        self.scan_time = report[6]

        if self.status.lower() == "safe":

            self.risk_level = "Low Risk"
            self.risk_score = 5
            self.status_color = self.success

            self.recommendation = (
                "No malware signature detected. "
                "Always keep your antivirus updated and "
                "scan downloaded files before opening."
            )

        else:

            self.risk_level = "High Risk"
            self.risk_score = 95
            self.status_color = self.danger

            self.recommendation = (
                "Malware signature detected. "
                "Delete or quarantine the file immediately "
                "and perform a full system scan."
            )

        self.report_id = "SNT-" + datetime.now().strftime("%Y%m%d-%H%M%S")

        self.generated_on = datetime.now().strftime(
            "%d-%m-%Y %I:%M:%S %p"
        )

    # ---------------------------------

    def draw_title(self, c, text, y):

        c.setFillColor(self.primary)

        c.setFont("Helvetica-Bold", 16)

        c.drawString(45, y, text)

    # ---------------------------------

    def draw_value(self, c, label, value, x, y):

        c.setFillColor(black)

        c.setFont("Helvetica-Bold", 11)

        c.drawString(x, y, label)

        c.setFont("Helvetica", 11)

        c.drawString(x + 140, y, str(value))

    # ---------------------------------
    def draw_box(self, c, x, y, w, h, title, bg):

        c.setStrokeColor(self.primary)
        c.setLineWidth(1)

    # Outer Box
        c.roundRect(
        x,
        y,
        w,
        h,
        10
    )

    # Header
        c.setFillColor(bg)

        c.roundRect(
        x,
        y + h - 40,
        w,
        40,
        10,
        fill=1,
        stroke=0
    )

    # Separator line
        c.setStrokeColor(HexColor("#D6DCE5"))

        c.line(
        x,
        y + h - 40,
        x + w,
        y + h - 40
    )

    # Title
        c.setFillColor(black)

        c.setFont(
        "Helvetica-Bold",
        15
    )

        c.drawString(
        x + 18,
        y + h - 25,
        title
    )    
    
            # ---------------------------------

    def create_pdf(self):

        pdf_name = os.path.join(
            os.getcwd(),
            "Sentinel_Report.pdf"
        )

        c = canvas.Canvas(
            pdf_name,
            pagesize=(self.width, self.height)
        )

        self.draw_page1(c)

        c.showPage()

        self.draw_page2(c)

        c.save()

        return pdf_name

    # ---------------------------------

    def draw_page1(self, c):

        # OUTER BORDER

        c.setStrokeColor(self.primary)
        c.setLineWidth(2)

        c.roundRect(
            10,
            10,
            self.width - 20,
            self.height - 20,
            12
        )

        # HEADER

        c.setFillColor(self.primary)

        c.rect(
            10,
            770,
            self.width - 20,
            62,
            fill=1,
            stroke=0
        )

        # LOGO

        logo = os.path.join(
            "static",
            "images",
            "logo.png"
        )

        if os.path.exists(logo):

            c.drawImage(
                logo,
                25,
                778,
                width=42,
                height=42,
                preserveAspectRatio=True,
                mask="auto"
            )

        c.setFillColor(white)

        c.setFont(
            "Helvetica-Bold",
            22
        )

        c.drawString(
            82,
            796,
            "Sentinel Malware Detection Report"
        )

        c.setFont(
            "Helvetica",
            11
        )

        c.drawString(
            82,
            780,
            "Professional Malware Analysis Report"
        )

        # REPORT ID

        c.setFont(
            "Helvetica-Bold",
            10
        )

        c.drawRightString(
           565,
           795,
            self.report_id
        )

        c.setFont(
            "Helvetica",
            10
        )

        c.drawRightString(
            565,
            780,
            self.generated_on
        )

        # Divider

        c.setStrokeColor(
            HexColor("#D5E7FF")
        )

        c.line(
            25,
            755,
            570,
            755
        )

        # Next section starts here

        y = 615

                # ==========================
        # FILE INFORMATION
        # ==========================

        self.draw_box(
            c,
            25,
            y,
            545,
            125,
            "FILE INFORMATION",
            self.secondary
        )

        self.draw_value(
            c,
            "File Name",
            self.filename,
            45,
            y + 72
        )

        self.draw_value(
            c,
            "File Size",
            self.file_size,
            45,
            y + 47
        )

        self.draw_value(
            c,
            "Scan Time",
            self.scan_time,
            45,
            y + 22
        )

        # ==========================
        # REPORT SUMMARY
        # ==========================

        y = 490

        self.draw_box(
            c,
            25,
            y,
            545,
            110,
            "REPORT SUMMARY",
            HexColor("#F3FFF5")
        )

        self.draw_value(
            c,
            "Report ID",
            self.report_id,
            45,
            y + 55
        )

        self.draw_value(
            c,
            "Generated On",
            self.generated_on,
            45,
            y + 30
        )

        c.setFont(
            "Helvetica-Bold",
            11
        )

        c.drawString(
            45,
            y + 5,
            "Risk Level"
        )

        c.setFillColor(
            self.status_color
        )

        c.setFont(
            "Helvetica-Bold",
            12
        )

        c.drawString(
            205,
            y + 5,
            self.risk_level
        )

        c.setFillColor(black)

                # ==========================
        # SCAN RESULT
        # ==========================

        y = 370

        self.draw_box(
            c,
            25,
            y,
            545,
            105,
            "SCAN RESULT",
            HexColor("#F8FFF8")
        )

        # Status Badge

        c.setFillColor(self.status_color)

        c.roundRect(
            45,
            y + 18,
            480,
            40,
            20,
            fill=1,
            stroke=0
        )

        c.setFillColor(white)

        c.setFont(
            "Helvetica-Bold",
            15
        )

        if self.status.lower() == "safe":
            status_text = "✓  FILE APPEARS SAFE"
        else:
            status_text = "⚠  MALWARE DETECTED"

        text_width = stringWidth(
            status_text,
            "Helvetica-Bold",
            15
        )

        c.drawString(
            45 + (480 - text_width) / 2,
            y + 31,
            status_text
        )

        # ==========================
        # RISK SCORE
        # ==========================

        y = 265

        self.draw_box(
            c,
            25,
            y,
            545,
            90,
            "RISK SCORE",
            HexColor("#EEF6FF")
        )

        # Background Bar

        c.setFillColor(
            HexColor("#D9D9D9")
        )

        c.roundRect(
            45,
            y + 24,
            410,
            16,
            8,
            fill=1,
            stroke=0
        )

        # Progress Bar

        progress = (
            410 * self.risk_score
        ) / 100

        c.setFillColor(
            self.status_color
        )

        c.roundRect(
            45,
            y + 24,
            progress,
            16,
            8,
            fill=1,
            stroke=0
        )

        # Percentage

        c.setFillColor(black)

        c.setFont(
            "Helvetica-Bold",
            13
        )

        c.drawString(
            485,
            y + 25,
            f"{self.risk_score}/100"
        )

        c.setFont(
            "Helvetica",
            10
        )

        c.setFillColor(
            self.gray
        )

        c.drawString(
            45,
            y + 8,
            "Overall malware risk based on scan results."
        )

                # ==========================
        # RECOMMENDATION
        # ==========================

        y = 140

        self.draw_box(
            c,
            25,
            y,
            545,
            110,
            "RECOMMENDATION",
            self.warning
        )

        text = c.beginText()

        text.setTextOrigin(
            45,
            y + 40
        )

        text.setFont(
            "Helvetica",
            11
        )

        for line in self.recommendation.split(". "):

            line = line.strip()

            if line:

                if not line.endswith("."):
                    line += "."

                text.textLine("• " + line)

        c.drawText(text)

        # ==========================
        # FILE HASHES
        # ==========================

        y = 20

        self.draw_box(
        c,
        25,
        y,
        545,
        110,
        "FILE HASHES",
        HexColor("#EEF6FF")
        )

        c.setFont(
            "Helvetica-Bold",
            10
        )

        c.drawString(
            45,
            y + 58,
            "MD5"
        )

        c.drawString(
            45,
            y + 30,
            "SHA256"
        )

        c.setFont(
            "Courier",
            10
        )

        md5 = self.md5 if self.md5 else "-"

        sha256 = self.sha256 if self.sha256 else "-"

        if len(md5) > 60:
            md5 = md5[:57] + "..."

        if len(sha256) > 60:
            sha256 = sha256[:57] + "..."

        c.drawString(
            140,
            y + 58,
            md5
        )

        c.drawString(
            140,
            y + 30,
            sha256
        )

            # ---------------------------------

    def draw_page2(self, c):

        # ==========================
        # PAGE BORDER
        # ==========================

        c.setStrokeColor(self.primary)
        c.setLineWidth(2)

        c.roundRect(
            10,
            10,
            self.width - 20,
            self.height - 20,
            12
        )

        # ==========================
        # HEADER
        # ==========================

        c.setFillColor(self.primary)

        c.rect(
            10,
            770,
            self.width - 20,
            62,
            fill=1,
            stroke=0
        )

        c.setFillColor(white)

        c.setFont(
            "Helvetica-Bold",
            22
        )

        c.drawString(
            30,
            802,
            "REPORT DETAILS"
        )

        c.setFont(
            "Helvetica",
            11
        )

        c.drawString(
            30,
            785,
            "Detailed Malware Analysis Information"
        )

        c.setFont(
            "Helvetica-Bold",
            10
        )

        c.drawRightString(
            565,
            800,
            self.report_id
        )

        # ==========================
        # REPORT INFORMATION
        # ==========================

        self.draw_box(
            c,
            25,
            580,
            545,
            180,
            "REPORT INFORMATION",
            self.secondary
        )

        self.draw_value(
            c,
            "Report ID",
            self.report_id,
            45,
            700
        )

        self.draw_value(
            c,
            "Generated On",
            self.generated_on,
            45,
            670
        )

        self.draw_value(
            c,
            "Generated By",
            "Sentinel Security",
            45,
            640
        )

        self.draw_value(
            c,
            "Detection Rule",
            self.rule,
            45,
            610
        )

        # ==========================
        # ANALYSIS SUMMARY
        # ==========================

        self.draw_box(
            c,
            25,
            360,
            545,
            205,
            "ANALYSIS SUMMARY",
            HexColor("#F8FBFF")
        )

        analysis = c.beginText()

        analysis.setTextOrigin(
            45,
            500
        )

        analysis.setFont(
            "Helvetica",
            11
        )

        analysis.textLine(f"• Scan Status : {self.status}")
        analysis.textLine("")
        analysis.textLine(f"• Risk Level : {self.risk_level}")
        analysis.textLine("")
        analysis.textLine(f"• Risk Score : {self.risk_score}/100")
        analysis.textLine("")
        analysis.textLine(f"• Detection Rule : {self.rule}")
        analysis.textLine("")
        analysis.textLine("• Report generated successfully.")
        analysis.textLine("")
        analysis.textLine("• Scan completed without internal errors.")

        c.drawText(analysis)

                # ==========================
        # DISCLAIMER
        # ==========================

        self.draw_box(
            c,
            25,
            125,
            545,
            220,
            "DISCLAIMER",
            self.warning
        )

        disclaimer = c.beginText()

        disclaimer.setTextOrigin(
            45,
            280
        )

        disclaimer.setFont(
            "Helvetica",
            11
        )

        disclaimer.textLine("• This report was generated automatically by Sentinel Security.")
        disclaimer.textLine("")
        disclaimer.textLine("• Malware detection is based on the available YARA rules.")
        disclaimer.textLine("")
        disclaimer.textLine("• A SAFE result does not guarantee the file is completely harmless.")
        disclaimer.textLine("")
        disclaimer.textLine("• Always verify suspicious files before executing them.")
        disclaimer.textLine("")
        disclaimer.textLine("• Keep your operating system and antivirus software updated.")
        disclaimer.textLine("")
        disclaimer.textLine("• This report is intended for educational and cybersecurity analysis.")

        c.drawText(disclaimer)

        # ==========================
        # SECURITY TIPS
        # ==========================

        c.setFont(
            "Helvetica-Bold",
            12
        )

        c.setFillColor(self.primary)

        c.drawString(
            40,
            100,
            "Quick Security Tips"
        )

        c.setFillColor(black)

        tips = c.beginText()

        tips.setTextOrigin(
            40,
            90
        )

        tips.setFont(
            "Helvetica",
            9
        )

        tips.textLine("• Download software only from trusted websites.")
        tips.textLine("• Scan every downloaded file before opening it.")
        tips.textLine("• Never disable Windows Defender or Antivirus.")
        tips.textLine("• Keep regular backups of important files.")

        c.drawText(tips)

        # ==========================
        # FOOTER
        # ==========================

        c.setStrokeColor(self.primary)

        c.line(
        25,
        40,
        570,
        40
        )

        c.setFillColor(self.gray)

        c.setFont(
            "Helvetica",
            9
        )

        c.drawString(
            30,
            28,
            "Generated by Sentinel Security Malware Detection System"
        )

        c.drawRightString(
            565,
            18,
            "Page 2 of 2"
        )

        c.setFont(
            "Helvetica-Oblique",
            18
        )

    
        # ------------------------------------------------
# Flask Route
# ------------------------------------------------

def register_download_route(app):

    @app.route("/download-report/<int:scan_id>")
    def download_report(scan_id):

        print(">>> DOWNLOAD ROUTE CALLED <<<", scan_id) 

        try:
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
                WHERE id = ?
            """, (scan_id,))

            report = cursor.fetchone()
            conn.close()

            print("DATABASE RESULT:", report)

            if report is None:
                return f"No report found for ID {scan_id}"

            pdf = SentinelPDFReport(app, report)
            pdf_path = pdf.create_pdf()

            return send_file(
                pdf_path,
                as_attachment=True,
                download_name="Sentinel_Malware_Report.pdf",
                mimetype="application/pdf"
            )

        except Exception as e:
            return f"ERROR: {e}"