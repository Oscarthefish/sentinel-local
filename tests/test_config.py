from sentinel_local.core.config import Settings


def test_settings_use_expected_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.app_name == "Sentinel Local"
    assert settings.database_url.startswith("sqlite:///")
    assert settings.enable_enrichment is False


def test_sqlite_path_is_derived_from_database_url() -> None:
    settings = Settings(_env_file=None, database_url="sqlite:///./tmp/sentinel.db")

    assert settings.sqlite_path.as_posix() == "tmp/sentinel.db"


def test_settings_support_prefixed_env_style_fields() -> None:
    settings = Settings(
        _env_file=None,
        enable_llm=True,
        enable_enrichment=True,
        ollama_model="qwen2.5:7b-instruct",
    )

    assert settings.enable_llm is True
    assert settings.enable_enrichment is True
    assert settings.ollama_model == "qwen2.5:7b-instruct"
