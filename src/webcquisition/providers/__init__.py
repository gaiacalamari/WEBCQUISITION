"""Registro dei provider hypervisor: VMware Workstation Pro/Fusion e provider simulato."""

from __future__ import annotations

from .base import CommandRunner, HypervisorProvider, NicInfo, ProviderError, VMInfo, VMState, normalize_uuid
from .fake import FakeProvider
from .vmware import GuestAuth, VMwareProvider

REGISTRY: dict[str, type[HypervisorProvider]] = {
    "vmware": VMwareProvider,
    "fake": FakeProvider,
}


def get_provider(name: str, **kwargs) -> HypervisorProvider:
    try:
        cls = REGISTRY[name]
    except KeyError as exc:
        raise ProviderError(f"provider sconosciuto: {name}. Disponibili: {sorted(REGISTRY)}") from exc
    return cls(**kwargs)


def provider_from_config(h) -> HypervisorProvider:
    """Crea il provider dalla sezione ``hypervisor`` della configurazione."""
    if h.provider == "vmware":
        return VMwareProvider(executable=h.executable, host_type=h.vmrun_host_type)
    return get_provider(h.provider)


__all__ = [
    "CommandRunner", "HypervisorProvider", "NicInfo", "ProviderError", "VMInfo", "VMState", "normalize_uuid",
    "FakeProvider", "GuestAuth", "VMwareProvider", "REGISTRY", "get_provider", "provider_from_config",
]
