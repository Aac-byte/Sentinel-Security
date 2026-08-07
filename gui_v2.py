import tkinter as tk
from tkinter import filedialog, messagebox
import yara
import os
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULE_PATH = os.path.join(BASE_DIR, "..", "rules", "test_rule.yara")
rules = yara.compile(filepath=RULE_PATH)

selected_file = ""

# Browse File
def browse_file():
    global selected_file

    selected_file = filedialog.askopenfilename()

    if selected_file:
        file_label.config(text=selected_file)

        file_name.config(
            text="Name : " + os.path.basename(selected_file)
        )

        size = os.path.getsize(selected_file)
        file_size.config(text=f"Size : {size} bytes")

        ext = os.path.splitext(selected_file)[1]
        file_type.config(text="Extension : " + ext)

        sha256 = hashlib.sha256()

        with open(selected_file, "rb") as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                sha256.update(data)

        hash_label.config(
            text="SHA256 : " + sha256.hexdigest()
        )

# Scan File
def scan_file():

    if selected_file == "":
        messagebox.showwarning(
            "Warning",
            "Please select a file first!"
        )
        return

    matches = rules.match(selected_file)

    if matches:
        result_label.config(
            text="Malware Detected!",
            fg="red"
        )
    else:
        result_label.config(
            text="No Malware Found",
            fg="green"
        )

# GUI
root = tk.Tk()
root.title("Malware Detection System")
root.geometry("700x500")

title = tk.Label(
    root,
    text="Malware Detection System",
    font=("Arial",18,"bold")
)
title.pack(pady=15)

browse_btn = tk.Button(
    root,
    text="Browse File",
    command=browse_file
)
browse_btn.pack()

file_label = tk.Label(root, text="No file selected")
file_label.pack(pady=5)

file_name = tk.Label(root, text="Name : ")
file_name.pack()

file_size = tk.Label(root, text="Size : ")
file_size.pack()

file_type = tk.Label(root, text="Extension : ")
file_type.pack()

hash_label = tk.Label(root, text="SHA256 : ")
hash_label.pack(pady=5)

scan_btn = tk.Button(
    root,
    text="Scan File",
    command=scan_file
)
scan_btn.pack(pady=15)

result_label = tk.Label(
    root,
    text="",
    font=("Arial",16,"bold")
)
result_label.pack()

root.mainloop()