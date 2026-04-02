from datetime import datetime, timezone


def utcnow():
    """Return the current UTC datetime without timezone info (naive), for SQLite compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
