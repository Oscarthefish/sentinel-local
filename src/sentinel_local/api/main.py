"""FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from sentinel_local.core.config import get_settings
from sentinel_local.core.logging import configure_logging
from sentinel_local.domain.models import HealthStatus
from sentinel_local.storage.db import initialise_storage

settings = get_settings()
configure_logging(settings.log_level)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Prepare local storage paths when the app boots."""
    initialise_storage(settings)
    yield


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Local-first email analysis and triage tool for macOS.",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthStatus, tags=["system"])
def healthcheck() -> HealthStatus:
    """Return a lightweight health response for local monitoring."""
    return HealthStatus(status="ok", environment=settings.environment, version="0.1.0")
