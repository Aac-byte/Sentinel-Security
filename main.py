import customtkinter as ctk
from gui_v4 import MalwareGUI

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()

app.title("Sentinel AI Malware Scanner")
app.geometry("1400x850")
app.minsize(1200, 750)

MalwareGUI(app)

app.mainloop()