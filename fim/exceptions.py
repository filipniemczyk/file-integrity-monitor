"""Project-specific exceptions."""


class FIMError(Exception):
    """Base exception for the entire project."""


class ConfigError(FIMError):
    """Configuration file error."""


class ScanError(FIMError):
    """File or directory scan error."""


class DatabaseError(FIMError):
    """SQLite database operation error."""
