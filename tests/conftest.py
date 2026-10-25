import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path():
    """A private temp folder per test, independent of pytest's shared basetemp folder."""
    with tempfile.TemporaryDirectory(prefix="sentinel-test-", ignore_cleanup_errors=True) as d:
        yield Path(d)