import pytest
from core.exceptions import ConfigError
from core.config import Config


def test_load_valid_config():
    """Loading a valid config file should succeed and populate _data."""
    config = Config("config/default.yaml")
    assert config._data is not None
    assert config._data["app"]["name"] == "Sentinel-X"


def test_load_missing_file_raises_error():
    with pytest.raises(ConfigError):
        Config("config/does_not_exist.yaml")
       

def test_get_existing_key():
    """get() should return the actual value for a key that exists."""
    config = Config("config/default.yaml")
    assert config.get("app.log_level") == "INFO"


def test_get_missing_key_returns_default():
    """get() should return the default value (not raise) for a missing key."""
    config = Config("config/default.yaml")
    assert config.get("this.does.not.exist") is None
    assert config.get("this.does.not.exist", default="fallback") == "fallback"       