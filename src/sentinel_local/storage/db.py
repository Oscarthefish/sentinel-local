"""SQLite path setup for local storage."""

from pathlib import Path

from sentinel_local.core.config import Settings
from sentinel_local.storage.repository import init_analysis_table


def initialise_storage(settings: Settings) -> None:
    """Create local directories used by the application."""
    sqlite_path = settings.sqlite_path
    sqlite_parent = sqlite_path.parent
    reports_dir = Path(settings.reports_dir)

    sqlite_parent.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    init_analysis_table(sqlite_path)
