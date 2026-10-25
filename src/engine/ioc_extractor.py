import ipaddress
import json
import re

SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_CONTEXTS = 3
MAX_CONTEXT_LEN = 120


def _public_ip(value):
    """Return the address as a string if it is a public (globally routable) IP, else None."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not ip.is_global or ip.is_multicast:
        return None
    return str(ip)


def _sha256(value):
    """Return a lower-case SHA-256 hex digest if the value is exactly one, else None."""
    if isinstance(value, str) and SHA256.match(value.lower()):
        return value.lower()
    return None


def extract_iocs(rows) -> list:
    """Extract indicators of compromise from stored event rows.

    Row columns: 0=id, 1=timestamp, 2=host, 3=source, 4=event_type,
    5=severity, 6=description, 7=raw_data (JSON text).

    Values are validated (a real public IP, or exactly 64 hex characters), so an
    indicator can never contain markup. The context text (process or path) is
    still untrusted and must be escaped when displayed.
    """
    found = {}
    for row in sorted(rows, key=lambda r: r[1]):
        try:
            raw = json.loads(row[7]) if row[7] else {}
        except (ValueError, TypeError):
            continue
        if not isinstance(raw, dict):
            continue

        candidates = []
        ip = _public_ip(raw.get("remote_ip"))
        if ip:
            candidates.append(("ip", ip))
        digest = _sha256(raw.get("sha256"))
        if digest:
            candidates.append(("sha256", digest))
        if not candidates:
            continue

        context = str(raw.get("process") or raw.get("path") or "")[:MAX_CONTEXT_LEN]
        for kind, value in candidates:
            entry = found.get((kind, value))
            if entry is None:
                entry = {"type": kind, "value": value, "count": 0,
                         "first_seen": row[1], "last_seen": row[1], "contexts": []}
                found[(kind, value)] = entry
            entry["count"] += 1
            entry["last_seen"] = row[1]
            if context and context not in entry["contexts"] and len(entry["contexts"]) < MAX_CONTEXTS:
                entry["contexts"].append(context)

    return sorted(found.values(), key=lambda e: (-e["count"], e["last_seen"]))
