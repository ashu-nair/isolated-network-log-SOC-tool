import sqlite3
from datetime import datetime, timedelta
from config.settings import DB_PATH

WINDOW_MINUTES = 15

SCORE_RULES = {
    "Brute Force Attack": 25,
    "Identity Abuse / Password Spraying": 30,
    "Privileged Account Access Attempt": 20,
    "Suspicious Privileged Command Execution": 50,
    "Security Control Tampering": 60,
    "Policy Violation": 15,
    "Anomalous Activity": 10,
}

def severity_from_score(score: int):
    if score >= 80:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Use latest log time
cursor.execute("SELECT MAX(timestamp) FROM logs")
latest_ts = cursor.fetchone()[0]

if not latest_ts:
    print("[INFO] No logs found for incident correlation.")
    conn.close()
    exit()

latest_dt = datetime.strptime(latest_ts, "%Y-%m-%d %H:%M:%S")
window_start = latest_dt - timedelta(minutes=WINDOW_MINUTES)

# Get alerts in time window
cursor.execute("""
SELECT id, alert_type, source_ip, severity, mitre_id, detected_at, ip_tag, ip_risk
FROM alerts
WHERE detected_at >= ?
""", (window_start.strftime("%Y-%m-%d %H:%M:%S"),))

alerts = cursor.fetchall()

if not alerts:
    print("[+] No alerts to correlate")
    conn.close()
    exit()

# Group alerts by source_ip
grouped = {}
for a in alerts:
    alert_id, alert_type, ip, sev, mitre, detected_at, ip_tag, ip_risk = a
    grouped.setdefault(ip, []).append(a)

for ip, ip_alerts in grouped.items():
    alert_types = [x[1] for x in ip_alerts]
    mitres = sorted(set([x[4] for x in ip_alerts if x[4]]))

    # Reputation from latest alert
    ip_tag = ip_alerts[-1][6] or "unknown"
    ip_risk = ip_alerts[-1][7] or "unknown"

    # Risk scoring
    score = 0
    for t in set(alert_types):
        score += SCORE_RULES.get(t, 5)

    if ip_risk == "high":
        score += 20
    elif ip_risk == "critical":
        score += 35

    if score > 100:
        score = 100

    incident_severity = severity_from_score(score)

    # Dedup: avoid duplicate incident for same IP in same window
    cursor.execute("""
    SELECT COUNT(*) FROM incidents
    WHERE source_ip = ?
    AND created_at >= ?
    """, (
        ip,
        window_start.strftime("%Y-%m-%d %H:%M:%S")
    ))

    if cursor.fetchone()[0] > 0:
        continue

    cursor.execute("""
    INSERT INTO incidents (
        incident_type, source_ip, techniques,
        alert_count, created_at, ip_tag, ip_risk,
        risk_score, severity
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "Correlated Security Incident",
        ip,
        ",".join(mitres),
        len(ip_alerts),
        latest_dt.strftime("%Y-%m-%d %H:%M:%S"),
        ip_tag,
        ip_risk,
        score,
        incident_severity
    ))

    print(f"[INCIDENT] Incident created for {ip} | score={score} | severity={incident_severity}")

conn.commit()
conn.close()
