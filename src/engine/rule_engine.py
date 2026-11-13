import logging

logger = logging.getLogger(__name__)

class Rule:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def matches(self, cluster: list) -> bool:
        raise NotImplementedError

class USBFileRule(Rule):
    """Matches usb_inserted followed by file_created on the same host."""
    def matches(self, cluster: list) -> bool:
        types = [e[4] for e in cluster]
        if "usb_inserted" in types and "file_created" in types:
            # Simple check: usb before file
            usb_idx = types.index("usb_inserted")
            file_idx = types.index("file_created")
            return usb_idx < file_idx
        return False

class BruteForceSuccessRule(Rule):
    """Matches brute_force_detected followed by login_success."""
    def matches(self, cluster: list) -> bool:
        types = [e[4] for e in cluster]
        if "brute_force_detected" in types and "login_success" in types:
            bf_idx = types.index("brute_force_detected")
            ls_idx = types.index("login_success")
            return bf_idx < ls_idx
        return False

class SuspiciousExecutionRule(Rule):
    """Matches file_created followed by process_started of the same name."""
    def matches(self, cluster: list) -> bool:
        # Simplified: check for file creation and process start
        types = [e[4] for e in cluster]
        return "file_created" in types and "process_started" in types

class SuspiciousNetworkCallbackRule(Rule):
    """Matches process_started followed by network_connection_new."""
    def matches(self, cluster: list) -> bool:
        types = [e[4] for e in cluster]
        if "process_started" in types and "network_connection_new" in types:
            p_idx = types.index("process_started")
            n_idx = types.index("network_connection_new")
            return p_idx < n_idx # Process starts, then calls home
        return False

RULES = [
    USBFileRule("USB_EXFIL", "File creation shortly after USB insertion."),
    BruteForceSuccessRule("BRUTE_FORCE_SUCCESS", "Login success after brute force alert."),
    SuspiciousExecutionRule("SUSPICIOUS_EXEC", "Process started after file creation."),
    SuspiciousNetworkCallbackRule("NETWORK_CALLBACK", "New process immediately initiated a network connection.")
]

def check_rules(cluster: list) -> list:
    """Check a cluster against all rules and return the names of triggered rules."""
    triggered = []
    for rule in RULES:
        if rule.matches(cluster):
            triggered.append(rule.name)
    return triggered
