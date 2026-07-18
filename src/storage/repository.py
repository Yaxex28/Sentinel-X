import sqlite3
import json
from core.models import Event


def insert_event(conn: sqlite3.Connection, event: Event) -> None:
    """Insert an Event into the events table."""
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO events (id, timestamp, host, source, event_type, severity, description, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.id,
            event.timestamp,
            event.host,
            event.source,
            event.event_type,
            event.severity,
            event.description,
            json.dumps(event.raw_data)
        )
    )
    conn.commit()