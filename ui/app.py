from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DB_PATH = "../storage/portsoc.db"

@app.route("/")
def alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    rows = cursor.execute("""
    SELECT detected_at, alert_type, source_ip,
           severity, mitre_id, event_count, time_window
    FROM alerts
    ORDER BY detected_at DESC
    """).fetchall()

    conn.close()
    return render_template("alerts.html", alerts=rows)

if __name__ == "__main__":
    app.run(debug=False)
