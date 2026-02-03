import sqlite3
import csv

conn = sqlite3.connect("storage/portsoc.db")
cursor = conn.cursor()

rows = cursor.execute("SELECT * FROM alerts").fetchall()

with open("reports/alerts_report.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "ID", "Attack Type", "Source IP", "Event Count",
        "Time Window", "Severity", "MITRE ID", "Detected At"
    ])
    writer.writerows(rows)

conn.close()
print("[+] alerts_report.csv generated")
