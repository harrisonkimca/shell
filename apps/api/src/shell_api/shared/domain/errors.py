"""Framework-independent failures; adapters translate external failures here."""


class Conflict(Exception):
    """The requested change conflicts with existing state."""


class ProviderUnavailable(Exception):
    """The identity provider is temporarily unavailable."""
