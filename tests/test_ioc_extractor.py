import json

from engine.ioc_extractor import extract_iocs


def row(ts, event_type, raw, source="network_monitor"):
    return ("id", ts, "h", source, event_type, "low", "d", json.dumps(raw))


def test_public_ip_is_extracted_and_counted():
    rows = [
        row("2026-01-01T00:00:01", "network_connection_new",
            {"process": "a.exe", "remote_ip": "93.184.216.34", "remote_port": 443}),
        row("2026-01-01T00:00:09", "network_connection_new",
            {"process": "b.exe", "remote_ip": "93.184.216.34", "remote_port": 80}),
    ]
    iocs = extract_iocs(rows)
    assert len(iocs) == 1
    assert iocs[0]["value"] == "93.184.216.34"
    assert iocs[0]["count"] == 2
    assert iocs[0]["first_seen"] == "2026-01-01T00:00:01"
    assert iocs[0]["last_seen"] == "2026-01-01T00:00:09"
    assert iocs[0]["contexts"] == ["a.exe", "b.exe"]


def test_private_and_loopback_addresses_are_not_indicators():
    rows = [row("t1", "x", {"remote_ip": "192.168.1.10"}),
            row("t2", "x", {"remote_ip": "127.0.0.1"}),
            row("t3", "x", {"remote_ip": "10.0.0.5"})]
    assert extract_iocs(rows) == []


def test_valid_sha256_is_extracted_and_malformed_is_not():
    good = "a" * 64
    rows = [row("t1", "file_created", {"path": "x.exe", "sha256": good}, source="file_monitor"),
            row("t2", "file_created", {"path": "y.exe", "sha256": "not-a-hash"}, source="file_monitor"),
            row("t3", "file_created", {"path": "z.exe", "sha256": None}, source="file_monitor")]
    iocs = extract_iocs(rows)
    assert [i["value"] for i in iocs] == [good]
    assert iocs[0]["type"] == "sha256"


def test_broken_raw_data_is_skipped_not_fatal():
    rows = [("id", "t", "h", "s", "e", "low", "d", "{not json"),
            row("t2", "x", {"remote_ip": "93.184.216.34"})]
    assert len(extract_iocs(rows)) == 1


def test_markup_in_remote_ip_field_is_rejected():
    rows = [row("t1", "x", {"remote_ip": "<script>alert(1)</script>"})]
    assert extract_iocs(rows) == []
