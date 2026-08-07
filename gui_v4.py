import customtkinter as ctk
from tkinter import filedialog
import os
from scanner import scan_file

class MalwareGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("Sentinel Malware Detection System")
        self.root.configure(fg_color="#0F172A")

        # ==========================
        # HEADER
        # ==========================

        header = ctk.CTkFrame(
            self.root,
            height=100,
            fg_color="#111827",
            corner_radius=0
        )

        header.pack(fill="x")

        title = ctk.CTkLabel(
            header,
            text="🛡 Sentinel Malware Detection System",
            font=("Arial", 30, "bold")
        )

        title.pack(pady=(15, 2))

        subtitle = ctk.CTkLabel(
            header,
            text="Yara Based Malware Scanner | File • URL • Hash Analysis",
            font=("Arial", 14),
            text_color="lightgray"
        )

        subtitle.pack()

        # ==========================
        # MAIN CONTAINER
        # ==========================

        self.main = ctk.CTkFrame(
            self.root,
            fg_color="#0F172A"
        )

        self.main.pack(fill="both", expand=True, padx=20, pady=20)

        # ==========================
        # TAB VIEW
        # ==========================

        self.tabs = ctk.CTkTabview(
            self.main,
            width=1200,
            height=650
        )

        self.tabs.pack(fill="both", expand=True)

        self.file_tab = self.tabs.add("📂 File")

        self.url_tab = self.tabs.add("🌐 URL")

        self.hash_tab = self.tabs.add("🔍 Hash Search")

    # ==========================
    # FILE TAB
    # ==========================

        self.file_title = ctk.CTkLabel(
        self.file_tab,
        text="Scan a File",
        font=("Arial", 22, "bold")
)
        self.file_title.pack(pady=(20, 10))

        self.browse_btn = ctk.CTkButton(
        self.file_tab,
        text="📂 Browse File",
        width=220,
        height=45,
        command=self.browse_file

)
        self.browse_btn.pack(pady=10)

        self.file_info = ctk.CTkTextbox(
        self.file_tab,
        width=900,
        height=220
)
        self.file_info.pack(pady=15)

        self.scan_btn = ctk.CTkButton(
        self.file_tab,
        text="🔍 Scan File",
        width=220,
        height=45,
        command=self.scan_selected_file

)
        self.scan_btn.pack(pady=10)
        self.progress = ctk.CTkProgressBar(
        self.file_tab,
        width=600
)
        self.progress.pack(pady=10)
        self.progress.set(0)

        self.result = ctk.CTkLabel(
    self.file_tab,
    text="Waiting For Scan",
    font=("Arial", 20, "bold")
)
        self.result.pack(pady=10)

        # ==========================
        # URL TAB
        # ==========================

        self.url_title = ctk.CTkLabel(
    self.url_tab,
    text="Scan a URL",
    font=("Arial", 22, "bold")
)
        self.url_title.pack(pady=(20,10))

        self.url_entry = ctk.CTkEntry(
    self.url_tab,
    width=700,
    height=45,
    placeholder_text="Enter Website URL"
)
        self.url_entry.pack(pady=15)

        self.url_scan_btn = ctk.CTkButton(
    self.url_tab,
    text="🌐 Scan URL",
    width=220,
    height=45
)
        self.url_scan_btn.pack(pady=10)

        self.url_result = ctk.CTkTextbox(
    self.url_tab,
    width=900,
    height=250
)
        self.url_result.pack(pady=20)

    def browse_file(self):
      file_path = filedialog.askopenfilename()

      if file_path:
        self.selected_file = file_path

        self.file_info.delete("1.0", "end")

        size = os.path.getsize(file_path)

        self.file_info.insert(
            "end",
            f"Selected File:\n{file_path}\n\n"
            f"Size: {size} bytes"
        )

    def scan_selected_file(self):

     if not hasattr(self, "selected_file"):
        self.result.configure(
            text="Please Select a File First",
            text_color="orange"
        )
        return

     self.progress.set(0.2)

     detected, report = scan_file(self.selected_file)

     self.progress.set(1)

     if detected:

        self.result.configure(
            text="⚠ Malware Detected",
            text_color="red"
        )

        self.file_info.insert(
            "end",
            f"\n\nResult:\nMalware Found\nRules: {report}"
        )

     else:

        self.result.configure(
            text="✅ File is Safe",
            text_color="green"
        )

        self.file_info.insert(
            "end",
            f"\n\nResult:\n{report}"
        )