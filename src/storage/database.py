import sqlite3
from pathlib import Path

def init_db(db_path: str):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY,timestamp TEXT NOT NULL,host TEXT NOT NULL,source TEXT NOT NULL,event_type TEXT NOT NULL,severity TEXT, description TEXT,raw_data TEXT)")
    conn.commit()
    return conn