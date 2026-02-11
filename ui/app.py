from flask import Flask, render_template
import sqlite3
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "storage", "portsoc.db")


@app.route("/")
def alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    rows = cursor.execute("""
    SELECT detected_at, alert_type, source_ip,
           severity, mitre_id, event_count, time_window,
           ip_tag, ip_risk
    FROM alerts
    ORDER BY detected_at DESC
    """).fetchall()

    conn.close()
    return render_template("alerts.html", alerts=rows)


@app.route("/incidents")
def incidents():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    rows = cursor.execute("""
    SELECT created_at, incident_type, source_ip,
           alert_count, techniques,
           risk_score, severity,
           ip_tag, ip_risk
    FROM incidents
    ORDER BY created_at DESC
    """).fetchall()

    conn.close()
    return render_template("incidents.html", incidents=rows)


if __name__ == "__main__":
    app.run(debug=False)
