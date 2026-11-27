"""Account responses and debug logs must not contain Xiaomi secrets."""

from __future__ import annotations

import logging
from pathlib import Path

from mi_monitor_light_tray.redact import install_log_redaction, redact_secrets


_SAMPLE = (
    '&&&START&&&{"qs":"%3Fsid%3Dxiaomiio","ssecurity":"QWxhZGRpbjpvcGVuIHNlc2FtZQ==",'
    '"passToken":"pass-token-value","location":"https://sts.api.io.mi.com/sts?code=SECRET",'
    '"serviceToken":"svc-token-value"}'
)


def test_redact_strips_account_fields_cookies_and_hex_tokens():
    raw = _SAMPLE + " serviceToken=cookie-token; userId=1 token=00112233445566778899aabbccddeeff"
    cleaned = redact_secrets(raw)
    for secret in (
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "pass-token-value",
        "svc-token-value",
        "cookie-token",
        "SECRET",
        "00112233445566778899aabbccddeeff",
    ):
        assert secret not in cleaned
    assert "ssecurity" in cleaned
    assert "userId=1" in cleaned
    assert redact_secrets("lamp is on") == "lamp is on"


def test_log_filter_redacts_even_if_the_caller_forgets():
    from mi_monitor_light_tray.redact import RedactingFilter

    install_log_redaction()
    assert any(isinstance(item, RedactingFilter) for item in logging.getLogger().filters)
    record = logging.LogRecord(
        "mi_monitor_light_tray.token_extractor.auth",
        logging.DEBUG,
        __file__,
        1,
        "login_step_1 response: %s",
        (_SAMPLE,),
        None,
    )
    assert RedactingFilter().filter(record) is True
    rendered = record.getMessage()
    assert "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" not in rendered
    assert "ssecurity" in rendered


def test_auth_module_does_not_log_raw_response_text():
    source = Path("mi_monitor_light_tray/token_extractor/auth.py").read_text(encoding="utf-8")
    assert "response.text[:200]" not in source
    assert "redact_secrets" in source
