# 🛡️ Log File Analyzer for Intrusion Detection

A Python-based tool that analyzes Apache and SSH log files to detect suspicious patterns like brute-force attacks, scans, and DoS.

---

## 🚀 Features

- Parse and analyze SSH log files
- Detect brute-force attempts based on IP frequency
- Compare IPs against a blacklist
- Export incident reports as CSV
- Visualize hourly activity

---

## 🛠️ How to Run
pip install -r requirements.txt
python log_analyzer.py

## Inputs:
logs/sample_ssh.log — example log file
blacklist.txt — IPs to flag immediately

## Outputs:
incident_report.csv — flagged IP activity
visuals/activity_plot.png — bar graph of log volume by hour
