import customtkinter as ctk
from tkinter import filedialog
import os
import hashlib
from scanner import scan_file as yara_scan


class MalwareGUI:

    def __init__(self, root):

        self.root = root
        self.root.configure(fg_color="#0F172A")
        self.selected_file = ""

        # ================= TITLE =================

        title = ctk.CTkLabel(
            root,
            text="🛡 Sentinel AI Malware Scanner",
            font=("Arial", 32, "bold"),
            text_color="white"
        )
        title.pack(pady=(20,5))

        subtitle = ctk.CTkLabel(
            root,
            text="Secure • Fast • Offline Malware Scanner",
            font=("Arial",16),
            text_color="lightgray"
        )
        subtitle.pack(pady=(0,20))

        # ================= Browse Button =================

        self.browse_btn = ctk.CTkButton(
            root,
            text="📂 Browse File",
            width=220,
            height=45,
            corner_radius=12,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.browse_file
        )

        self.browse_btn.pack(pady=10)

        # ================= File Information =================

        self.info = ctk.CTkTextbox(
            root,
            width=980,
            height=300,
            corner_radius=15,
            border_width=2,
            border_color="#334155",
            font=("Consolas",15)
        )

        self.info.pack(pady=20)

        # ================= Scan Button =================

        self.scan_btn = ctk.CTkButton(
            root,
            text="🔍 Scan File",
            width=220,
            height=45,
            corner_radius=12,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.scan_file
        )

        self.scan_btn.pack(pady=10)

        # ================= Progress =================

        self.progress = ctk.CTkProgressBar(
            root,
            width=500,
            progress_color="#22C55E"
        )

        self.progress.pack(pady=12)
        self.progress.set(0)

        # ================= Risk Score =================

        self.risk = ctk.CTkLabel(
            root,
            text="Risk Score : 0%",
            font=("Arial",20,"bold"),
            text_color="white"
        )

        self.risk.pack()

        # ================= Result =================

        self.result = ctk.CTkLabel(
            root,
            text="",
            font=("Arial",24,"bold")
        )

        self.result.pack(pady=20)

    # ======================================================

    def browse_file(self):

        self.selected_file = filedialog.askopenfilename()

        if not self.selected_file:
            return

        size = os.path.getsize(self.selected_file)

        sha256 = hashlib.sha256()

        with open(self.selected_file,"rb") as f:

            while True:

                data = f.read(4096)

                if not data:
                    break

                sha256.update(data)

        self.info.delete("1.0","end")

        self.info.insert(
            "end",
            "══════════════════════════════════════════════════════\n"
        )

        self.info.insert(
            "end",
            "               FILE INFORMATION\n"
        )

        self.info.insert(
            "end",
            "══════════════════════════════════════════════════════\n\n"
        )

        self.info.insert(
            "end",
            f"📄 File Name      : {os.path.basename(self.selected_file)}\n\n"
        )

        self.info.insert(
            "end",
            f"📂 File Path      : {self.selected_file}\n\n"
        )

        self.info.insert(
            "end",
            f"📦 File Size      : {size} Bytes\n\n"
        )

        self.info.insert(
            "end",
            f"📝 Extension      : {os.path.splitext(self.selected_file)[1]}\n\n"
        )

        self.info.insert(
            "end",
            "🔐 SHA256 HASH\n"
        )

        self.info.insert(
            "end",
            sha256.hexdigest()
        )

        self.info.insert(
            "end",
            "\n\n══════════════════════════════════════════════════════"
        )
        
    def scan_file(self):

        if self.selected_file == "":
            self.result.configure(
                text="⚠ Please Select a File First",
                text_color="orange"
            )
            return

        # Progress Animation
        self.progress.set(0.10)
        self.root.update()

        self.progress.set(0.30)
        self.root.update()

        malware, message = yara_scan(self.selected_file)

        self.progress.set(0.70)
        self.root.update()

        self.progress.set(1.0)
        self.root.update()

        if malware:

            self.risk.configure(
                text="Risk Score : 95%",
                text_color="#EF4444"
            )

            self.result.configure(
                text="⚠ MALWARE DETECTED",
                text_color="#EF4444"
            )

            self.info.insert(
                "end",
                "\n\n=============================="
            )

            self.info.insert(
                "end",
                "\nSCAN RESULT\n\n"
            )

            self.info.insert(
                "end",
                "Status : MALWARE DETECTED\n"
            )

            self.info.insert(
                "end",
                f"Matched Rule : {message}\n"
            )

        else:

            self.risk.configure(
                text="Risk Score : 5%",
                text_color="#22C55E"
            )

            self.result.configure(
                text="✔ FILE LOOKS SAFE",
                text_color="#22C55E"
            )

            self.info.insert(
                "end",
                "\n\n=============================="
            )

            self.info.insert(
                "end",
                "\nSCAN RESULT\n\n"
            )

            self.info.insert(
                "end",
                "Status : FILE LOOKS SAFE\n"
            )

            self.info.insert(
                "end",
                "Matched Rule : None\n"
            )