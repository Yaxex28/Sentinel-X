import pytest
from storage.database import init_db
from core.models import Event
from storage.repository import insert_event, query_events

@pytest.fixture
def db_conn():
    conn = init_db(":memory:")
    yield conn
    conn.close()

def test_insert_and_query_by_severity(db_conn):
    event = Event(
        host="TEST-HOST",
        source="process_monitor",
        event_type="process_started",
        severity="high",
        description="Test event",
        raw_data={"pid":1234}
    )
    insert_event(db_conn, event)

    results =  query_events(db_conn,severity="high")

    assert len(results) == 1
    assert results[0][0] == event.id

def test_query_no_match_returns_empty(db_conn):
    event = Event(
        host="TEST_HOST",
        source="process_monitor",
        event_type="process_started",
        severity="low",
        description="Test event",
        raw_data={"pid":4261}
    )
    insert_event(db_conn, event)
    results = query_events(db_conn, severity="high")

    assert len(results) == 0
