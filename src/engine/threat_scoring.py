BASELINE_SCORES ={
        "process_started": 1,
        "file_created": 2,
        "file_modified": 2,
        "file_deleted": 2,
        "login_success": 1,
        "login_failure": 4,
        "usb_inserted": 5,
        "brute_force_detected": 9,
        "network_connection_new": 1,
        "network_suspicious_port": 5,
        "listening_port_opened": 2,
}

def apply_cluster_multiplier(base_score:float, cluster_is_interesting:bool) -> float:
    """boost a score if the event occured within a flagged (correlated) cluster."""
    if cluster_is_interesting:
        return base_score * 1.5
    return base_score

def score_event(event_type: str, cluster_is_interesting: bool = False) -> float:
    """Compute a threat score an event, given its type and cluster context."""
    base_score = BASELINE_SCORES.get(event_type, 1)
    return apply_cluster_multiplier(base_score, cluster_is_interesting)