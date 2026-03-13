"""Application configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SENTINEL_",
        extra="ignore",
    )

    environment: str = Field(
        default="development",
        validation_alias=AliasChoices("SENTINEL_ENV", "SENTINEL_ENVIRONMENT"),
    )
    app_name: str = Field(default="Sentinel Local")
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    log_level: str = Field(default="INFO")
    database_url: str = Field(default="sqlite:///./data/sentinel_local.db")
    reports_dir: Path = Field(default=Path("./data/reports"))
    ollama_base_url: str = Field(default="http://127.0.0.1:11434")
    ollama_model: str | None = Field(default=None)
    lm_studio_base_url: str | None = Field(default="http://127.0.0.1:1234")
    lm_studio_model: str | None = Field(default=None)
    enable_llm: bool = Field(default=False)
    llm_provider: str = Field(default="ollama")
    llm_timeout_seconds: int = Field(default=180)
    enable_enrichment: bool = Field(default=False)
    virustotal_api_key: str | None = Field(default=None)
    abuseipdb_api_key: str | None = Field(default=None)
    enrichment_timeout_seconds: int = Field(default=10)
    enable_attachment_scanning: bool = Field(default=False)
    yara_binary_path: str | None = Field(default=None)
    yara_rules_path: Path | None = Field(default=None)
    clamscan_binary_path: str | None = Field(default=None)
    attachment_scan_timeout_seconds: int = Field(default=20)
    url_resolution_timeout_seconds: int = Field(default=15)
    enable_url_screenshots: bool = Field(default=False)
    screenshot_provider: str = Field(default="playwright")  # "playwright" | "custom" | "thum_io" | "none"
    screenshot_base_url: str | None = Field(default=None)

    @property
    def sqlite_path(self) -> Path:
        """Resolve the local SQLite database path from the configured URL."""
        if not self.database_url.startswith("sqlite:///"):
            raise ValueError("Only sqlite:/// URLs are supported in Milestone 1.")

        raw_path = self.database_url.removeprefix("sqlite:///")
        return Path(raw_path)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached settings object."""
    return Settings()
