from pathlib import Path
import yaml
# from dataclasses import dataclass
from .exceptions import ConfigError

class Config:
    REQUIRED_KEYS = ["app.name","app.log_level","app.log_dir"]
    def __init__(self,config_path: str="config/default.yaml") -> None:
        self.config_path = config_path
        self._data = self._load()
        self._validate()

    def _load(self) -> dict:
        """load YAML file. Raise ConfigError if file is missing or invalid YAML."""
        path = Path(self.config_path)

        if not path.exists():
            raise ConfigError(f"Config file not found at: {path}")
    
        with open(path,"r") as f:
            try:
                return yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ConfigError(f"Failed to parse YAML at {path}:{e}")
        
    def _key_exists(self, dotted_key: str) -> bool:
        """Check whether a dotted key path (e.g. 'app.log_level') exists in self._data."""
        steps = dotted_key.split(".")
        current = self._data

        for step in steps:
            # your code here:
            # 1. update `current` by looking up `step`
            # 2. if `current` is now None, return False immediately
            current = current.get(step)
            if current is None:
                return False
            

        # if we got through the whole loop without returning False,
        # the key exists
        return True
    def _validate(self) -> None:
        for key in self.REQUIRED_KEYS:
            if not self._key_exists(key):
                raise ConfigError(f"Missing required config key: {key}")
            
    def get(self, dotted_key: str, default=None):
        """
        Get a config value by dotted key path (e.g. 'app.log_level').
        Returns `default` if the key doesn't exist, instead of raising.
        """
        steps = dotted_key.split(".")
        current = self._data

        for step in steps:
        # same walking logic as _key_exists() —
        # but this time, if you hit None, return `default` instead of False
            current = current.get(step)
            if current is None:
                return default
    # if the loop finished without hitting None, `current` IS the value
        return current