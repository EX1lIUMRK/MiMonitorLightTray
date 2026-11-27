"""A saved lamp must be polled on its own IP, and a failed poll must be retried."""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from miio.exceptions import DeviceException

import pytest

from mi_monitor_light_tray import discovery, miio_client
from mi_monitor_light_tray.reconnect import plan_light_updates
from mi_monitor_light_tray.config import DeviceConfig
from mi_monitor_light_tray.miio_client import MiMonitorLight


TOKEN = "ab" * 16


@pytest.fixture
def fake_yeelight(monkeypatch):
    factory = MagicMock()
    monkeypatch.setattr(miio_client, "Yeelight", factory)
    return factory


def _online_status():
    return SimpleNamespace(is_on=True, brightness=40, color_temp=4500)


def _light(fake_yeelight, status):
    device = MagicMock()
    if callable(status) or isinstance(status, Exception):
        device.status = MagicMock(side_effect=status)
    else:
        device.status = MagicMock(return_value=status)
    device.info = MagicMock(return_value=MagicMock(model="yeelink.light.lamp1"))
    fake_yeelight.return_value = device
    light = MiMonitorLight(ip="192.168.1.203", token=TOKEN, model="yeelink.light.lamp1")
    return light, device


def test_failed_poll_retries_on_the_saved_ip_without_discovery(fake_yeelight, monkeypatch):
    calls = {"n": 0}

    def status():
        calls["n"] += 1
        if calls["n"] == 1:
            raise DeviceException("Unable to discover the device 192.168.1.203")
        return _online_status()

    seen = []
    light, _device = _light(fake_yeelight, status)
    light.set_listener(lambda state: seen.append(state.reachable))
    monkeypatch.setattr(
        discovery,
        "find_candidate_ips",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("discovery")),
    )

    first = light.ensure_connected(delays=(0.05,))
    assert first.reachable is False
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and not light.state.reachable:
        time.sleep(0.02)
    light.close()
    assert light.state.reachable is True
    assert light.state.brightness == 40
    assert light.ip == "192.168.1.203"
    assert calls["n"] >= 2
    assert True in seen


def test_plain_refresh_does_not_keep_polling(fake_yeelight):
    light, device = _light(fake_yeelight, DeviceException("noop"))
    light.refresh()
    time.sleep(0.08)
    light.close()
    assert device.status.call_count == 1
    assert light.state.reachable is False


def test_first_success_does_not_schedule_another_poll(fake_yeelight):
    light, device = _light(fake_yeelight, _online_status())
    state = light.ensure_connected(delays=(0.05, 0.05))
    time.sleep(0.15)
    light.close()
    assert state.reachable is True
    assert device.status.call_count == 1


def test_new_and_changed_devices_reconnect_changed_endpoint_is_replaced():
    token_b = "cd" * 16
    kept = SimpleNamespace(
        ip="192.168.1.203",
        token=TOKEN,
        model="yeelink.light.lamp22",
        enable_miot_for_unknown=False,
        state=SimpleNamespace(reachable=False),
    )
    stale = SimpleNamespace(
        ip="192.168.1.50",
        token=TOKEN,
        model="yeelink.light.lamp22",
        enable_miot_for_unknown=False,
        state=SimpleNamespace(reachable=True),
    )
    built = []

    def build(dev):
        light = SimpleNamespace(
            ip=dev.ip,
            token=dev.token,
            model=dev.model,
            enable_miot_for_unknown=dev.enable_miot_for_unknown,
            state=SimpleNamespace(reachable=False),
        )
        built.append(light)
        return light

    same = DeviceConfig(
        id="same", ip="192.168.1.203", token=TOKEN, model="yeelink.light.lamp22",
    )
    moved = DeviceConfig(
        id="moved", ip="192.168.1.203", token=token_b, model="yeelink.light.lamp22",
    )
    added = DeviceConfig(
        id="added", ip="192.168.1.203", token=TOKEN, model="yeelink.light.lamp22",
        device_id=0,
    )
    plan = plan_light_updates(
        {"same": kept, "moved": stale},
        [same, moved, added],
        build,
    )
    assert plan.lights["same"] is kept
    assert kept in plan.connect  # saved session is offline, so poll it again
    assert plan.lights["moved"] is not stale
    assert stale in plan.close
    assert plan.lights["added"] in plan.connect
    assert plan.lights["moved"] in plan.connect
    assert all(light.ip == "192.168.1.203" for light in built)
    assert added.device_id == 0
