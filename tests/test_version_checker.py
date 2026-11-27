"""Update checks are notify-only: HTTPS, timeout, no download, no redirect."""

from __future__ import annotations

from unittest.mock import Mock

from mi_monitor_light_tray import version_checker
from mi_monitor_light_tray.version_checker import check_for_updates, release_page_url


def _response(payload, status=200, redirect=False):
    response = Mock()
    response.status_code = status
    response.is_redirect = redirect
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


def test_update_check_returns_a_page_and_does_not_fetch_assets(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return _response({
            "tag_name": "v9.9.9",
            "html_url": "https://github.com/EX1lIUMRK/MiMonitorLightTray/releases/tag/v9.9.9",
            "body": "notes",
            "assets": [{
                "name": "MiMonitorLightTray.exe",
                "browser_download_url": "https://example.invalid/MiMonitorLightTray.exe",
            }],
        })

    monkeypatch.setattr(version_checker.requests, "get", fake_get)
    monkeypatch.setattr(version_checker, "get_current_version", lambda: "1.0.0")
    info = check_for_updates()
    assert info is not None
    assert set(info) == {"version", "url", "body"}
    assert info["version"] == "9.9.9"
    assert info["url"] == "https://github.com/EX1lIUMRK/MiMonitorLightTray/releases/tag/v9.9.9"
    assert "example.invalid" not in str(info)
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == "https://api.github.com/repos/EX1lIUMRK/MiMonitorLightTray/releases/latest"
    assert kwargs["allow_redirects"] is False
    assert kwargs["verify"] is True
    assert kwargs["timeout"][0] > 0
    assert kwargs["timeout"][1] > 0


def test_update_check_refuses_redirects_and_odd_repositories(monkeypatch):
    called = []
    monkeypatch.setattr(
        version_checker.requests,
        "get",
        lambda *args, **kwargs: called.append(args) or _response({}, status=302, redirect=True),
    )
    monkeypatch.setattr(version_checker, "get_current_version", lambda: "1.0.0")
    assert check_for_updates() is None
    assert check_for_updates(repo="https://evil.example/x") is None
    assert check_for_updates(repo="owner/name/extra") is None
    assert len(called) == 1


def test_release_page_url_rejects_offsite_and_cleartext_links():
    repo = "EX1lIUMRK/MiMonitorLightTray"
    assert release_page_url("http://github.com/EX1lIUMRK/MiMonitorLightTray/releases", repo) is None
    assert release_page_url("https://github.com.evil.example/EX1lIUMRK/MiMonitorLightTray", repo) is None
    assert release_page_url("https://example.invalid/MiMonitorLightTray.exe", repo) is None
    page = release_page_url(
        "https://github.com/EX1lIUMRK/MiMonitorLightTray/releases/tag/v1.6.0?evil=1#x",
        repo,
    )
    assert page == "https://github.com/EX1lIUMRK/MiMonitorLightTray/releases/tag/v1.6.0"


def test_unsafe_html_url_falls_back_to_the_repo_releases_page(monkeypatch):
    monkeypatch.setattr(
        version_checker.requests,
        "get",
        lambda *args, **kwargs: _response({
            "tag_name": "v9.9.9",
            "html_url": "https://evil.example/download.exe",
            "body": "x",
        }),
    )
    monkeypatch.setattr(version_checker, "get_current_version", lambda: "1.0.0")
    info = check_for_updates()
    assert info is not None
    assert info["url"] == "https://github.com/EX1lIUMRK/MiMonitorLightTray/releases/latest"
