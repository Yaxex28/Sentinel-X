from engine.threat_scoring import score_event

def test_score_event_unknown_type_defaults_to_baseline_one():
    assert score_event("totally_unknown_type") == 1


def test_score_event_applies_cluster_multiplier():
    base = score_event("usb_inserted", cluster_is_interesting=False)
    boosted = score_event("usb_inserted", cluster_is_interesting=True)
    assert boosted == base * 1.5