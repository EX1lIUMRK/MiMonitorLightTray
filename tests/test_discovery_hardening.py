"""Rediscovery must not persist an IP that fails an authenticated miio check."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mi_monitor_light_tray import discovery, miio_client
from mi_monitor_light_tray.discovery import DiscoveredDevice
from mi_monitor_light_tray.miio_client import MiMonitorLight


def test_find_device_by_id_refuses_an_unauthenticated_match(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "discover_devices",
        lambda timeout=5.0: [DiscoveredDevice("192.0.2.20", 0x10)],
    )
    with pytest.raises(TypeError):
        discovery.find_device_by_id(0x10)


def test_candidate_filter_drops_spoofed_and_non_matching_addresses(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "discover_devices",
        lambda timeout=5.0: [
            DiscoveredDevice("192.0.2.20", 0x10),
            DiscoveredDevice("192.0.2.21", 0x99),
            DiscoveredDevice("255.255.255.255", 0x10),
            DiscoveredDevice("127.0.0.1", 0x10),
            DiscoveredDevice("224.0.0.1", 0x10),
            DiscoveredDevice("not-an-ip", 0x10),
        ],
    )
    assert discovery.find_candidate_ips(0x10, timeout=0.1) == ["192.0.2.20"]


@pytest.mark.parametrize(
    ("ip", "ok", "reported", "expected"),
    [
        ("198.51.100.8", True, 0x99, False),
        ("198.51.100.8", True, 0, False),
        ("198.51.100.8", False, 0x10, False),
        ("192.0.2.10", True, 0x10, False),
        ("127.0.0.1", True, 0x10, False),
        ("198.51.100.8", True, 0x10, True),
    ],
)
def test_candidate_is_trusted(ip, ok, reported, expected):
    trusted = discovery.candidate_is_trusted(
        candidate_ip=ip,
        current_ip="192.0.2.10",
        authenticated=ok,
        reported_device_id=reported,
        expected_device_id=0x10,
    )
    assert trusted is expected


def _light(monkeypatch, on_ip):
    monkeypatch.setattr(miio_client, "Yeelight", MagicMock())
    light = MiMonitorLight(
        ip="192.0.2.10",
        token="ab" * 16,
        model="yeelink.light.lamp1",
        device_id=0x10,
        on_ip_changed=on_ip,
    )
    light.refresh = lambda: None  # type: ignore[method-assign]
    return light


def test_rediscover_skips_a_spoofed_reply_and_keeps_a_verified_one(monkeypatch):
    saved: list[str] = []
    probed: list[tuple[str, str]] = []

    def ping(ip, token, timeout=3.0):
        probed.append((ip, token))
        if ip == "198.51.100.8":
            return False, "no answer", 0
        if ip == "192.0.2.30":
            return True, "ok", 0x10
        return True, "wrong lamp", 0x99

    monkeypatch.setattr(
        discovery,
        "find_candidate_ips",
        lambda device_id, timeout=5.0: ["198.51.100.8", "192.0.2.30"],
    )
    monkeypatch.setattr(miio_client, "quick_ping", ping)
    light = _light(monkeypatch, saved.append)
    light._try_rediscover()
    assert saved == ["192.0.2.30"]
    assert light._ip == "192.0.2.30"
    assert probed[0][1] == "ab" * 16


def test_rediscover_does_not_persist_when_the_token_is_rejected(monkeypatch):
    saved: list[str] = []
    monkeypatch.setattr(
        discovery,
        "find_candidate_ips",
        lambda device_id, timeout=5.0: ["198.51.100.8"],
    )
    monkeypatch.setattr(
        miio_client,
        "quick_ping",
        lambda ip, token, timeout=3.0: (False, "timeout", 0),
    )
    light = _light(monkeypatch, saved.append)
    light._try_rediscover()
    assert saved == []
    assert light._ip == "192.0.2.10"
