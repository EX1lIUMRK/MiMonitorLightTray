"""Strip Xiaomi account secrets from log records."""

from __future__ import annotations

import logging
import re

# Keys that show up in Xiaomi account JSON, form bodies, and Set-Cookie headers.
# ``location`` is included because the STS redirect carries a one-time login code.
_SECRET_NAMES = (
    "serviceToken",
    "yetAnotherServiceToken",
    "ssecurity",
    "passToken",
    "cUserId",
    "password",
    "pwd",
    "_sign",
    "nonce",
    "location",
    "hash",
)

_ASSIGNED = re.compile(
    r"(?i)(\"?(?:"
    + "|".join(_SECRET_NAMES)
    + r")\"?\s*[:=]\s*)(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}&]+)"
)
_COOKIE = re.compile(
    r"(?i)\b((?:serviceToken|yetAnotherServiceToken|ssecurity|passToken)=)([^;\s]+)"
)
# miio device tokens and the Xiaomi password hash are 32 hex characters.
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{32}\b")


def redact_secrets(text: str) -> str:
    """Return ``text`` with account tokens and 32-hex secrets replaced."""
    if not text:
        return text

    def _assigned(match: re.Match[str]) -> str:
        value = match.group(2)
        hidden = '"***"' if value[:1] in "\"'" else "***"
        return match.group(1) + hidden

    cleaned = _ASSIGNED.sub(_assigned, text)
    cleaned = _COOKIE.sub(r"\1***", cleaned)
    return _HEX_TOKEN.sub("***", cleaned)


class RedactingFilter(logging.Filter):
    """Redact secrets in every record, including messages from python-miio."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        cleaned = redact_secrets(rendered)
        if cleaned != rendered:
            record.msg = cleaned
            record.args = ()
            record.message = cleaned
        return True


def install_log_redaction() -> None:
    root = logging.getLogger()
    if not any(isinstance(item, RedactingFilter) for item in root.filters):
        root.addFilter(RedactingFilter())
