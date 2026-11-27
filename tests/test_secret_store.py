"""Token encryption, legacy migration, and private config permissions."""

from __future__ import annotations

import base64
import json
import stat
import sys
from pathlib import Path

import pytest

from mi_monitor_light_tray.config import AppConfig, DeviceConfig
from mi_monitor_light_tray.secret_store import DpapiTokenCipher, use_cipher


class PrefixCipher:
    prefix = "testseal:v1:"

    def protects(self) -> bool:
        return True

    def is_sealed(self, stored: str) -> bool:
        return stored.startswith(self.prefix)

    def protect(self, token: str) -> str:
        if not token or self.is_sealed(token):
            return token
        return self.prefix + base64.b64encode(token.encode()).decode("ascii")

    def unprotect(self, stored: str) -> str:
        if not self.is_sealed(stored):
            return stored
        return base64.b64decode(stored[len(self.prefix):]).decode("utf-8")


class BrokenCipher(PrefixCipher):
    def unprotect(self, stored: str) -> str:
        if self.is_sealed(stored):
            raise ValueError("wrong windows account")
        return stored


@pytest.fixture(autouse=True)
def _reset_cipher():
    previous = use_cipher(None)
    yield
    use_cipher(previous)


def test_plaintext_token_is_encrypted_on_save_and_roundtrips(tmp_path: Path):
    use_cipher(PrefixCipher())
    token = "ab" * 16
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({
            "devices": [{
                "id": "lamp",
                "ip": "192.0.2.10",
                "token": token,
                "name": "Моя лампа",
                "model": "yeelink.light.lamp22",
            }],
            "language": "ru",
        }),
        encoding="utf-8",
    )
    loaded = AppConfig.load(path)
    assert loaded.secrets_need_migration is True
    assert loaded.devices[0].token == token
    assert loaded.language == "ru"
    loaded.save(path)

    raw = path.read_text(encoding="utf-8")
    assert token not in raw
    assert "testseal:v1:" in raw
    again = AppConfig.load(path)
    assert again.devices[0].token == token
    assert again.secrets_need_migration is False
    assert again.devices[0].name == "Моя лампа"
    assert again.devices[0].model == "yeelink.light.lamp22"


def test_failed_decrypt_keeps_the_sealed_blob(tmp_path: Path):
    cipher = PrefixCipher()
    sealed = cipher.protect("cd" * 16)
    use_cipher(BrokenCipher())
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"devices": [{"id": "lamp", "ip": "192.0.2.10", "token": sealed}]}),
        encoding="utf-8",
    )
    loaded = AppConfig.load(path)
    assert loaded.tokens_need_reentry is True
    assert loaded.devices[0].token == ""
    assert loaded.secrets_need_migration is False
    loaded.save(path)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["devices"][0]["token"] == sealed


def test_config_file_is_not_world_readable(tmp_path: Path):
    path = tmp_path / "config.json"
    AppConfig(devices=[DeviceConfig(id="lamp", ip="192.0.2.10", token="ab" * 16)]).save(path)
    if sys.platform == "win32":
        from mi_monitor_light_tray.secret_store import _current_user_sid, file_dacl_sddl

        sddl = file_dacl_sddl(path).upper()
        assert _current_user_sid().upper() in sddl
        # Everyone, Authenticated Users, and Builtin Users must not have an ACE.
        for world in (";WD)", ";AU)", ";BU)"):
            assert world not in sddl
    else:
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI exists only on Windows")
def test_dpapi_roundtrip_does_not_store_the_token():
    cipher = DpapiTokenCipher()
    token = "ef" * 16
    sealed = cipher.protect(token)
    assert sealed.startswith("dpapi:v1:")
    assert token not in sealed
    assert cipher.unprotect(sealed) == token
    assert cipher.protect(token) != sealed
