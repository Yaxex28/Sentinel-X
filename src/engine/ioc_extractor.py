import ipaddress
import json
import re

SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_CONTEXTS = 3
MAX_CONTEXT_LEN = 120

REASON_SUSPICIOUS_PORT = "connected on a commonly abused port"
REASON_DELETED = "file was deleted after being seen"


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


def _parse_raw(row):
    """Return the row's raw_data as a dict, or None if it is missing or not valid JSON."""
    try:
        raw = json.loads(row[7]) if row[7] else {}
    except (ValueError, TypeError):
        return None
    return raw if isinstance(raw, dict) else None


def _indicators(raw) -> list:
    """Return the (type, value) indicators contained in one raw_data dict."""
    found = []
    ip = _public_ip(raw.get("remote_ip"))
    if ip:
        found.append(("ip", ip))
    digest = _sha256(raw.get("sha256"))
    if digest:
        found.append(("sha256", digest))
    return found


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
        raw = _parse_raw(row)
        if raw is None:
            continue
        candidates = _indicators(raw)
        if not candidates:
            continue

        context = str(raw.get("process") or raw.get("path") or "")[:MAX_CONTEXT_LEN]
        for kind, value in candidates:
            entry = found.get((kind, value))
            if entry is None:
                entry = {"type": kind, "value": value, "count": 0, "first_seen": row[1],
                         "last_seen": row[1], "contexts": [], "reasons": []}
                found[(kind, value)] = entry
            entry["count"] += 1
            entry["last_seen"] = row[1]
            if context and context not in entry["contexts"] and len(entry["contexts"]) < MAX_CONTEXTS:
                entry["contexts"].append(context)

    return sorted(found.values(), key=lambda e: (-e["count"], e["last_seen"]))


def annotate_iocs(iocs, groups) -> list:
    """Attach a `reasons` list to each indicator that has context worth reviewing.

    groups is a list of (cluster_number, rows, elevated), where rows are the
    event rows of one cluster and elevated says that cluster contains a medium
    or high severity event. An empty `reasons` list means ordinary activity.
    """
    reasons = {}
    for number, rows, elevated in groups:
        for row in rows:
            raw = _parse_raw(row)
            if raw is None:
                continue
            for key in _indicators(raw):
                bucket = reasons.setdefault(key, [])
                found = []
                if row[4] == "network_suspicious_port":
                    found.append(REASON_SUSPICIOUS_PORT)
                if row[4] == "file_deleted":
                    found.append(REASON_DELETED)
                if elevated:
                    found.append("seen during elevated activity (cluster " + str(number) + ")")
                for reason in found:
                    if reason not in bucket:
                        bucket.append(reason)
    for ioc in iocs:
        ioc["reasons"] = reasons.get((ioc["type"], ioc["value"]), [])
    return iocs
