import sqlite3
import os

# Ensure processed directory exists
os.makedirs("data/processed", exist_ok=True)

# Path to the database
db_path = "data/processed/not_today_bot.db"

# Connect to SQLite database (creates it if it doesn't exist)
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create a table for network logs
cursor.execute('''
CREATE TABLE IF NOT EXISTS network_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    packet_size INTEGER,
    classification TEXT
)
''')

# Save and close
conn.commit()
conn.close()

print(f"✅ Database created at: {db_path}")