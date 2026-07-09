# SIEM-Lite — Windows Security Monitor

A Python-based security monitoring tool that collects 
Windows event logs, detects threats in real time, and 
displays results on a web dashboard.

## What it does
- Collects Windows Security logs via PowerShell
- Detects suspicious activity using rule-based engine
- Maps threats to MITRE ATT&CK techniques
- Monitors running processes for anomalies
- Calculates overall threat score
- Displays alerts and charts on a Flask dashboard
- Generates incident reports in PDF and TXT format

## Tech Stack
Python, Flask, PowerShell, JavaScript, Chart.js, psutil, ReportLab

## Project Structure
- `collector/` — log collection and process monitoring
- `detection/` — threat detection logic
- `dashboard/` — Flask web app and frontend
- `storage/` — log storage
- `alerts/` — alert management

## Run Locally
```bash
git clone https://github.com/meghana-reddy-p/SIEM-lite.git
cd SIEM-lite
pip install flask pandas psutil reportlab
python main.py
```

Then start the dashboard:
```bash
cd dashboard
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

## Monitored Events
Failed logins, admin access, process creation, 
credential manager access, and more via Windows Event IDs.
