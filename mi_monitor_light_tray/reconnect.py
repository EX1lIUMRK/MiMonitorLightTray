"""Choose which live lamp sessions to keep after a config save."""

from __future__ import annotations

from typing import Callable

from .config import DeviceConfig


def _same_connection(light: object, dev: DeviceConfig) -> bool:
    """True when the live session already targets this saved endpoint."""
    if light.ip != dev.ip or light.token != dev.token:  # type: ignore[attr-defined]
        return False
    model = dev.model
    if model and light.model != model:  # type: ignore[attr-defined]
        return False
    if light.enable_miot_for_unknown != dev.enable_miot_for_unknown:  # type: ignore[attr-defined]
        return False
    return True


class LightPlan:
    def __init__(self, lights: dict, connect: list, close: list) -> None:
        self.lights = lights
        self.connect = connect
        self.close = close


def plan_light_updates(
    old: dict,
    devices: list[DeviceConfig],
    build: Callable[[DeviceConfig], object],
) -> LightPlan:
    """Decide which sessions to keep, which to open, and which to stop.

    A saved IP and token are used directly. Nothing here waits for UDP
    discovery, so the first cloud import is not blocked on a broadcast.
    """
    lights: dict = {}
    connect: list = []
    used: set[int] = set()
    for dev in devices:
        if not dev.is_complete():
            continue
        existing = old.get(dev.id)
        if existing is not None and _same_connection(existing, dev):
            lights[dev.id] = existing
            used.add(id(existing))
            if not existing.state.reachable:
                connect.append(existing)
        else:
            created = build(dev)
            lights[dev.id] = created
            connect.append(created)
    close = [light for light in old.values() if id(light) not in used]
    return LightPlan(lights, connect, close)
