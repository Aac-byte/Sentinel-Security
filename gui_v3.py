import customtkinter as ctk
from tkinter import filedialog
import os
import hashlib
from scanner import scan_file as yara_scan


class MalwareGUI:

    def __init__(self, root):

        self.root = root
        self.selected_file = ""

        self.root.configure(fg_color="#0F172A")

        # ================= HEADER =================

        header = ctk.CTkFrame(
            self.root,
            fg_color="#111827",
            corner_radius=15,
            height=90
        )
        header.pack(fill="x", padx=20, pady=15)

        title = ctk.CTkLabel(
            header,
            text="🛡 Sentinel AI Malware Scanner",
            font=("Arial", 30, "bold"),
            text_color="white"
        )
        title.pack(pady=(12,2))

        subtitle = ctk.CTkLabel(
            header,
            text="Secure • Fast • Offline Malware Scanner",
            font=("Arial",15),
            text_color="lightgray"
        )
        subtitle.pack()

        # ================= MAIN CARD =================

        self.card = ctk.CTkFrame(
            self.root,
            fg_color="#1E293B",
            corner_radius=20
        )

        self.card.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20
        )

        # ================= Browse Button =================

        self.browse_btn = ctk.CTkButton(
            self.card,
            text="📂 Browse File",
            width=220,
            height=45,
            command=self.browse_file
        )

        self.browse_btn.pack(pady=15)

        # ================= File Info =================

        self.info = ctk.CTkTextbox(
            self.card,
            width=900,
            height=220
        )

        self.info.pack(pady=10)

        # ================= Scan Button =================

        self.scan_btn = ctk.CTkButton(
            self.card,
            text="🔍 Scan File",
            width=220,
            height=45,
            command=self.scan_file
        )

        self.scan_btn.pack(pady=10)

        # ================= Progress =================

        self.progress = ctk.CTkProgressBar(
            self.card,
            width=500
        )

        self.progress.pack(pady=10)
        self.progress.set(0)

        # ================= Risk =================

        self.risk = ctk.CTkLabel(
            self.card,
            text="Risk Score : 0%",
            font=("Arial",20,"bold")
        )

        self.risk.pack()

        # ================= Result =================

        self.result = ctk.CTkLabel(
            self.card,
            text="Waiting For Scan",
            font=("Arial",22,"bold")
        )

        self.result.pack(pady=15)

        # ================= Report =================

        self.report = ctk.CTkTextbox(
            self.card,
            width=900,
            height=170
        )

        self.report.pack(pady=10)

        self.report.insert(
            "end",
            "Scan report will appear here..."
        )

        # ================= Buttons =================

        self.button_frame = ctk.CTkFrame(
            self.card,
            fg_color="transparent"
        )

        self.button_frame.pack(pady=15)

        self.export_btn = ctk.CTkButton(
            self.button_frame,
            text="📄 Export Report",
            width=180,
            command=self.export_report
        )

        self.export_btn.grid(row=0, column=0, padx=10)

        self.reset_btn = ctk.CTkButton(
            self.button_frame,
            text="🔄 Reset",
            width=180,
            command=self.reset_scan
        )

        self.reset_btn.grid(row=0, column=1, padx=10)


    def browse_file(self):

        self.selected_file = filedialog.askopenfilename()

        if not self.selected_file:
            return

        file_size = os.path.getsize(self.selected_file)

        sha256 = hashlib.sha256()

        with open(self.selected_file, "rb") as file:

            while True:

                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        self.info.delete("1.0", "end")

        self.info.insert(
            "end",
            "═══════════════════════════════════════════════\n"
        )

        self.info.insert(
            "end",
            "              FILE INFORMATION\n"
        )

        self.info.insert(
            "end",
            "═══════════════════════════════════════════════\n\n"
        )

        self.info.insert(
            "end",
            f"📄 File Name : {os.path.basename(self.selected_file)}\n\n"
        )

        self.info.insert(
            "end",
            f"📂 File Path : {self.selected_file}\n\n"
        )

        self.info.insert(
            "end",
            f"📦 File Size : {file_size} Bytes\n\n"
        )

        self.info.insert(
            "end",
            f"📝 Extension : {os.path.splitext(self.selected_file)[1]}\n\n"
        )

        self.info.insert(
            "end",
            "🔐 SHA256 HASH\n\n"
        )

        self.info.insert(
            "end",
            sha256.hexdigest()
        )

        self.progress.set(0)

        self.risk.configure(
            text="Risk Score : 0%",
            text_color="white"
        )

        self.result.configure(
            text="Waiting For Scan",
            text_color="white"
        )

        self.report.delete("1.0", "end")

        self.report.insert(
            "end",
            "Click 'Scan File' to start scanning..."
        )
    def scan_file(self):

        if self.selected_file == "":
            self.result.configure(
                text="⚠ Please Select a File First",
                text_color="orange"
            )
            return

        # Reset Progress
        self.progress.set(0.10)
        self.root.update()

        # Scan File
        malware, message = yara_scan(self.selected_file)

        self.progress.set(0.60)
        self.root.update()

        self.progress.set(1.00)
        self.root.update()

        if malware:

            self.risk.configure(
                text="Risk Score : 95%",
                text_color="red"
            )

            self.result.configure(
                text="⚠ MALWARE DETECTED",
                text_color="red"
            )

            self.report.delete("1.0", "end")

            self.report.insert(
                "end",
                f"""
=========================================
            SCAN REPORT
=========================================

Status          : MALWARE DETECTED

Threat Level    : HIGH

Matched Rule    : {message}

Engine          : YARA

Risk Score      : 95 %

Recommendation:

• Delete the file immediately.
• Do not execute this file.
• Quarantine the file.
• Scan the complete system.
"""
            )

        else:

            self.risk.configure(
                text="Risk Score : 5%",
                text_color="green"
            )

            self.result.configure(
                text="✔ FILE LOOKS SAFE",
                text_color="green"
            )

            self.report.delete("1.0", "end")

            self.report.insert(
                "end",
                """
=========================================
            SCAN REPORT
=========================================

Status          : SAFE

Threat Level    : LOW

Matched Rule    : None

Engine          : YARA

Risk Score      : 5 %

Recommendation:

• No malware signature found.
• File appears safe.
"""
            )

    def export_report(self):

        report_text = self.report.get("1.0", "end").strip()

        if report_text == "":
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")]
        )

        if file_path:

            with open(file_path, "w", encoding="utf-8") as file:
                file.write(report_text)

            self.result.configure(
                text="📄 Report Exported Successfully",
                text_color="cyan"
            )


    def reset_scan(self):

        self.selected_file = ""

        self.progress.set(0)

        self.info.delete("1.0", "end")

        self.report.delete("1.0", "end")

        self.report.insert(
            "end",
            "Scan report will appear here..."
        )

        self.risk.configure(
            text="Risk Score : 0%",
            text_color="white"
        )

        self.result.configure(
            text="Waiting For Scan",
            text_color="white"
        )

        