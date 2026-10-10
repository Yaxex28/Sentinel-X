from engine.attack_mapping import ATTACK_MAP, get_attack_tag


def test_brute_force_maps_to_t1110():
    tag = get_attack_tag("brute_force_detected")
    assert tag["technique_id"] == "T1110"
    assert tag["confidence"] == "high"


def test_unmapped_event_type_returns_none():
    assert get_attack_tag("process_started") is None
    assert get_attack_tag("totally_unknown_type") is None


def test_all_mappings_have_required_fields():
    required = {"technique_id", "technique", "tactic", "confidence"}
    for event_type, tag in ATTACK_MAP.items():
        assert required.issubset(tag.keys()), event_type