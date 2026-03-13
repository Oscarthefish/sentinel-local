"""Parser package for supported email input types."""

from sentinel_local.parsers.service import (
    ParseRequest,
    ParseResult,
    UnsupportedInputError,
    parse_email_input,
)

__all__ = [
    "ParseRequest",
    "ParseResult",
    "UnsupportedInputError",
    "parse_email_input",
]
