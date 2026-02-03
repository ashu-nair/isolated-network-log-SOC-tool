import sqlite3

conn = sqlite3.connect("storage/portsoc.db")
cursor = conn.cursor()

for row in cursor.execute("SELECT * FROM logs"):
    print(row)

conn.close()
