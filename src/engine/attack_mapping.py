"""Lightweight MITRE ATT&CK tagging for Sentinel-X event types.

Only event types with a defensible technique mapping are tagged. Routine
activity (ordinary file modifications, successful logins) is deliberately
left unmapped, because no single ATT&CK technique describes it.

Rationales for mappings:
- brute_force_detected (T1110): Direct high-confidence match for repeated failed login attempts.
- login_failure (T1110): Low-confidence indicator consistent with credential guessing.
- usb_inserted (T1091): Indicates potential removable media usage for initial access or transfer.
- file_deleted (T1070.004): Indicates indicator removal via file deletion.
- network_suspicious_port (T1571): Indicates non-standard port usage for C2 communications.
- file_created (T1059): Indicates script or payload drop prior to execution.
"""

ATTACK_MAP = {
    "brute_force_detected": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "high",
        "rationale": "Direct threshold-based detection of repeated login failures.",
    },
    "login_failure": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "low",
        "rationale": "Single failed login attempt consistent with password guessing.",
    },
    "usb_inserted": {
        "technique_id": "T1091",
        "technique": "Replication Through Removable Media",
        "tactic": "Initial Access / Lateral Movement",
        "confidence": "low",
        "rationale": "Removable USB storage inserted into host device.",
    },
    "file_deleted": {
        "technique_id": "T1070.004",
        "technique": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
        "confidence": "low",
        "rationale": "Deletion of files observed which may indicate cleanup.",
    },
    "network_suspicious_port": {
        "technique_id": "T1571",
        "technique": "Non-Standard Port",
        "tactic": "Command and Control",
        "confidence": "low",
        "rationale": "Outbound connection on a known non-standard or suspicious port.",
    },
    "file_created": {
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "confidence": "low",
        "rationale": "Creation of executable or script files in watched paths.",
    },
}

def get_attack_tag(event_type: str):
    """Return the ATT&CK tag dict for an event type, or None if unmapped."""
    return ATTACK_MAP.get(event_type)
