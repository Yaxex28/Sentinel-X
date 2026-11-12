import sqlite3
import shutil
import os

DB_PATH = "data/sentinel.db"
BACKUP_PATH = "data/sentinel.db.bak"

def clean():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    # Backup
    shutil.copy(DB_PATH, BACKUP_PATH)
    print(f"Backed up to {BACKUP_PATH}")

    # Delete
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT count(*) FROM events WHERE source = 'network_monitor'")
        count = cursor.fetchone()[0]

        cursor.execute("DELETE FROM events WHERE source = 'network_monitor'")
        conn.commit()
        print(f"Deleted {count} network monitor events.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    clean()
