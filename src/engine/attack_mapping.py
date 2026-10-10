"""Lightweight MITRE ATT&CK tagging for Sentinel-X event types.

Only event types with a defensible technique mapping are tagged. Routine
activity (process starts, successful logins, ordinary file modifications) is
deliberately left unmapped, because no single ATT&CK technique describes it.

The `confidence` field is an honest label: "high" means the detection logic
itself matches the technique's definition (e.g. a threshold-based brute-force
alert); "low" means the event is only *consistent with* the technique and
needs analyst context to confirm it.
"""

ATTACK_MAP = {
    "brute_force_detected": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "high",
    },
    "login_failure": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "low",
    },
    "usb_inserted": {
        "technique_id": "T1091",
        "technique": "Replication Through Removable Media",
        "tactic": "Initial Access / Lateral Movement",
        "confidence": "low",
    },
    "file_deleted": {
        "technique_id": "T1070.004",
        "technique": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
        "confidence": "low",
    },
}


def get_attack_tag(event_type: str):
    """Return the ATT&CK tag dict for an event type, or None if unmapped."""
    return ATTACK_MAP.get(event_type)