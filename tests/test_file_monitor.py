import tempfile
import os
from collectors.file_monitor import hash_file, should_record
from collectors.file_monitor import hash_file

def test_hash_file_same_content_same_hash():
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write("hello")
        path = f.name

    hash1 = hash_file(path)
    hash2 = hash_file(path)

    os.remove(path)
    assert hash1 == hash2

def test_hash_file_different_content_different_hash():
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
        f.write("hello")
        path = f.name

    hash1 = hash_file(path)
    with open(path, "w") as f:
        f.write("hello world")

    hash2 = hash_file(path)

    os.remove(path)
    assert hash1 != hash2

def test_should_record_debounces_rapid_calls():
    """First call on a path should record; an immediate second call should be debounced."""
    assert should_record("some/fake/path.txt") is True
    assert should_record("some/fake/path.txt") is False