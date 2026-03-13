"""Parser selection and orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, model_validator

from sentinel_local.domain.models import ParsedEmail
from sentinel_local.parsers.eml_parser import parse_eml_bytes
from sentinel_local.parsers.msg_parser import parse_msg_file
from sentinel_local.parsers.txt_parser import parse_pasted_text, parse_txt_bytes


class UnsupportedInputError(ValueError):
    """Raised when an input type cannot be parsed."""


class ParseRequest(BaseModel):
    """Represents one inbound parsing request."""

    source_type: Literal["eml", "msg", "txt", "pasted"]
    file_path: Path | None = None
    content: bytes | str | None = None
    raw_headers: str | None = None
    analyst_note: str | None = None

    @model_validator(mode="after")
    def validate_source(self) -> "ParseRequest":
        """Ensure the request contains the required input material."""
        if self.source_type == "pasted":
            if not isinstance(self.content, str) or not self.content.strip():
                raise ValueError("Pasted parsing requires string content.")
            return self

        if self.file_path is None and self.content is None:
            raise ValueError("File-based parsing requires a file path or raw content.")

        return self


class ParseResult(BaseModel):
    """Parsed email plus context from the parse operation."""

    parsed_email: ParsedEmail
    analyst_note: str | None = None


def parse_email_input(request: ParseRequest) -> ParseResult:
    """Parse the provided email input into a canonical ParsedEmail object."""
    if request.source_type == "pasted":
        parsed = parse_pasted_text(request.content, raw_headers=request.raw_headers)
        return ParseResult(parsed_email=parsed, analyst_note=request.analyst_note)

    if request.source_type == "eml":
        parsed = parse_eml_bytes(_read_bytes(request))
        return ParseResult(parsed_email=parsed, analyst_note=request.analyst_note)

    if request.source_type == "txt":
        parsed = parse_txt_bytes(_read_bytes(request))
        return ParseResult(parsed_email=parsed, analyst_note=request.analyst_note)

    if request.source_type == "msg":
        parsed = parse_msg_file(_resolve_path(request))
        return ParseResult(parsed_email=parsed, analyst_note=request.analyst_note)

    raise UnsupportedInputError(f"Unsupported input type: {request.source_type}")


def _read_bytes(request: ParseRequest) -> bytes:
    """Return raw bytes from the request."""
    if isinstance(request.content, bytes):
        return request.content
    if isinstance(request.content, str):
        return request.content.encode("utf-8")

    path = _resolve_path(request)
    return path.read_bytes()


def _resolve_path(request: ParseRequest) -> Path:
    """Resolve a file path from the parse request."""
    if request.file_path is None:
        raise ValueError("A file path is required for this parser.")
    return Path(request.file_path)
