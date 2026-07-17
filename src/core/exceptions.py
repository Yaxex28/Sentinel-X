class SentinelXError(Exception):
    """Base exception for all Sentinel-X custom errors."""
    pass


class ConfigError(SentinelXError):
    """Raised when configuration loading or validation fails."""
    pass