# 🛡️ Sentinel Malware Detection System

## Project Overview

Sentinel Malware Detection System is a web-based malware scanning application developed using Python Flask and YARA. The system allows users to upload files, scan them using custom YARA rules, generate MD5 and SHA256 hashes, store scan history in SQLite database, and download a PDF report of the scan results.

---

## Features

- File Upload
- YARA-based Malware Detection
- MD5 Hash Generation
- SHA256 Hash Generation
- File Size Display
- Scan Time Display
- Safe / Malware Detection Status
- Scan History
- Search Scan History
- Clear Scan History
- SQLite Database Storage
- PDF Report Generation
- Responsive Dark Theme User Interface

---

## Technologies Used

- Python
- Flask
- HTML5
- CSS3
- SQLite
- YARA
- ReportLab
- Hashlib

---

## Project Structure

```
Sentinel-Malware-Detection-System
│
├── app.py
├── scanner.py
├── scanner.db
├── README.md
│
├── rules
│   └── test_rule.yara
│
├── templates
│   ├── index.html
│   ├── result.html
│   └── history.html
│
├── static
│   └── style.css
│
├── uploads
│
└── reports
```

---

## Installation

Clone the repository.

Install the required libraries.

```bash
pip install flask
pip install yara-python
pip install reportlab
```

Run the application.

```bash
python app.py
```

Open your browser.

```
http://127.0.0.1:5000
```

---

## How It Works

1. User uploads a file.
2. The application generates MD5 and SHA256 hashes.
3. The uploaded file is scanned using YARA rules.
4. The scan result is displayed as Safe or Malware.
5. Scan information is stored in the SQLite database.
6. A PDF report can be generated and downloaded.

---

## Project Workflow

```
Upload File
      ↓
Generate MD5
      ↓
Generate SHA256
      ↓
YARA Scan
      ↓
Malware / Safe Detection
      ↓
Store in SQLite Database
      ↓
Generate PDF Report
```

---

## Screenshots

- Home Page
- Scan Result
- Scan History
- PDF Report

(Add screenshots here.)

---

## Future Scope

- URL Scanning
- VirusTotal API Integration
- Folder Scanning
- Multiple File Upload
- User Authentication
- Email Notifications
- Cloud Database Integration

---

## Author

**Aanchal Dewangan**

B.Tech Cyber Security

---

## License

This project is developed for educational and learning purposes.