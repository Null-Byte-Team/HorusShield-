import sqlite3

DB = r"D:\HorusShield_2.0\backend\database\horus.db"
NEW_CLIENT_ID = "84532770868-ere6dbvhfi09s719g7r50rj1v49a0g1e.apps.googleusercontent.com"

conn = sqlite3.connect(DB)
conn.execute("UPDATE settings SET value=? WHERE key='google_client_id'", (NEW_CLIENT_ID,))
conn.execute("INSERT OR IGNORE INTO settings(key, value, description) VALUES ('google_client_id', ?, 'Google OAuth 2.0 Client ID for Sign-In with Google')", (NEW_CLIENT_ID,))
conn.commit()
row = conn.execute("SELECT value FROM settings WHERE key='google_client_id'").fetchone()
print(row[0] if row else 'missing')
conn.close()
