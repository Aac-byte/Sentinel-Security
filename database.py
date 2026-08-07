import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "scanner.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    file_name TEXT,

    file_size INTEGER,

    md5 TEXT,

    sha256 TEXT,

    status TEXT,

    rule TEXT,

    scan_time TEXT

)
""")

scan_id = cursor.lastrowid

conn.commit()
conn.close()

print("Database created successfully!")