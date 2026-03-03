# 🛡️ PORT-SOC

Portable Offline SOC for Air-Gapped and Isolated Environments

📌 Overview

PORT-SOC is a lightweight, offline Security Operations Center (SOC) built for:

Air-gapped networks

Isolated lab environments

Academic research projects

Small organizations

Incident response simulations

It performs full log ingestion, normalization, detection, correlation, and visualization — without requiring internet connectivity or enterprise SIEM products.

🚀 Core Capabilities
🔍 Log Collection Modes

Live Syslog Mode

UDP Syslog Server (Port 5514)

Real-time detection loop

Automatic raw log trimming

Integrated UI

Local Ubuntu Log Import

/var/log/auth.log

/var/log/syslog

/var/log/ufw.log

Offset-based incremental parsing

Offline Log Import

Manual upload to storage/import/

Historical attack detection

Bulk log processing

🧠 Detection Engine

PORT-SOC includes modular detection plugins mapped to MITRE ATT&CK:

Brute Force Detection (T1110)

Password Spraying (T1110)

Low & Slow Attacks (T1110)

Successful Login After Failures (T1078)

Privileged Account Access Attempt (T1078)

Suspicious Privileged Command Execution (T1059)

Security Control Tampering (T1562)

Off-Hours Privileged Access (T1078)

Volume-Based Anomaly Detection (T1499)

Each alert includes:

Real event timestamp (parsed from logs)

Source IP

Username

MITRE ID

Severity

Reputation tag

Risk score

🗂️ Normalized Event Schema (SQLite)

All logs are structured into:

timestamp

source_ip

event_type

username

raw_log

This enables fast querying, detection logic, and incident correlation.

🎯 Incident Correlation Engine

Alerts are grouped and risk-scored using:

Alert Severity Weight

IP Reputation Risk

Event Volume

MITRE Criticality

Incidents are classified as:

High

Medium

Low

🔐 Log Integrity Protection

PORT-SOC builds a SHA-256 hash chain for raw logs:

Each log line is hashed

Each hash links to previous hash

Tampering breaks chain integrity

Stored in: storage/raw_logs.hashchain

This enables forensic verification of log integrity.

🖥️ Web Dashboard

Flask-based local dashboard provides:

Alert timeline

Incident overview

Severity highlighting

MITRE mapping display

Real event timestamps

Clean minimal UI

Runs on:

http://127.0.0.1:5000

⚙️ Installation
1️⃣ Clone Repository

git clone https://github.com/YOUR_USERNAME/isolated-network-log-SOC-tool.git

cd isolated-network-log-SOC-tool

2️⃣ Create Virtual Environment

python3 -m venv venv
source venv/bin/activate

3️⃣ Install Requirements

pip install -r requirements.txt

▶️ Usage
Recommended (One-Command Launcher)

./venv/bin/python portsoc.py start

Select:

Live Syslog SOC

Import Local Ubuntu Logs

Offline Import

Manual Commands

./venv/bin/python portsoc.py live
./venv/bin/python portsoc.py local
./venv/bin/python portsoc.py import
./venv/bin/python portsoc.py pipeline
./venv/bin/python portsoc.py ui
./venv/bin/python portsoc.py reset

🏗️ Architecture Flow

Logs → Raw Storage → Parser → Normalization
↓
Detection Modules
↓
Alert Table
↓
Incident Correlation
↓
Risk Scoring
↓
Flask Dashboard

🧪 Testing Scenarios

You can simulate:

SSH brute force attempts

Invalid user sprays

sudo privilege escalation

Suspicious shell spawning

Firewall tampering

Off-hours administrative access

🛡️ Why PORT-SOC?

Traditional SIEM tools:

Expensive

Cloud dependent

Heavy infrastructure

PORT-SOC:

Lightweight

Offline capable

Research-friendly

Fully customizable

Transparent detection logic

📚 Research Contribution

PORT-SOC demonstrates:

Log normalization techniques

Behavioral detection modeling

MITRE ATT&CK mapping implementation

Risk-based alert scoring

Incident correlation logic

Forensic hash chain validation

SOC design for air-gapped systems

🔮 Future Improvements

Multi-host log aggregation

Threat intelligence auto-sync

ML-based anomaly scoring

Role-based access control

Email alerting

Dockerized deployment

👨‍💻 Author

Ashithosh Nair
BTech – Cloud Technology & Cybersecurity

