"""Fixture comuni. Nessun test richiede una VM reale: si usano FakeProvider e FakeGuestClient."""

from __future__ import annotations

import pytest

from webcquisition.case import Case
from webcquisition.config import config_from_dict
from webcquisition.fake_guest import FakeGuestClient
from webcquisition.orchestrator import Acquisition
from webcquisition.providers import FakeProvider


class VirtualClock:
    """Orologio simulato: sleep() avanza il tempo senza attese reali."""

    def __init__(self):
        self.t = 1000.0

    def sleep(self, s):
        self.t += s

    def monotonic(self):
        return self.t


def base_config(**overrides) -> dict:
    cfg = {
        "hypervisor": {"provider": "fake", "vm_name": "fake-vm", "snapshot": "clean",
                       "vm_uuid": "00000000-0000-0000-0000-00000000f00d",
                       "expected_nics": {"1": "nat", "2": "hostonly"}},
        "agent": {"expected_agent_id": "fake-agent", "poll_interval_s": 0.01, "ready_timeout_s": 30},
        "capture": {"verify_timeout_s": 5, "stall_warning_s": 60},
        "screenshot": {"control_panel": False},
        "case": {"operator": "Operatore Test"},
    }
    for section, values in overrides.items():
        cfg.setdefault(section, {}).update(values)
    return cfg


@pytest.fixture
def clock():
    return VirtualClock()


@pytest.fixture
def make_acq(tmp_path, clock):
    """Factory: make_acq(guest_options=..., provider_kwargs=..., config=...) -> (acq, provider, guest)."""
    created = []

    def factory(guest_options=None, provider_kwargs=None, config=None, case_id="CASE-2026-001"):
        cfg = config_from_dict(config or base_config())
        case = Case.create(tmp_path / "cases" / case_id, case_id, operator="Operatore Test",
                           config_dict=cfg.to_dict())
        provider = FakeProvider(**(provider_kwargs or {}))
        guest = FakeGuestClient(tmp_path / "guest", options=guest_options)
        acq = Acquisition(case, cfg, provider, guest, sleep=clock.sleep, monotonic=clock.monotonic,
                          out=lambda s: None)
        created.append(acq)
        return acq, provider, guest

    yield factory
    for a in created:
        try:
            a.close()
        except Exception:
            pass
