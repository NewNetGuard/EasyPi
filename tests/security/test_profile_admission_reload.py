from __future__ import annotations

from pathlib import Path

from easypi_netprotection.profiles.manager import (
    ProfileManager,
    trigger_profiles_reload,
)


def test_admission_consumes_binding_reload_before_rejecting_device(
    tmp_path: Path,
) -> None:
    """A DHCP rebind must not remain stuck behind unknown-device admission."""

    data_dir = tmp_path / "profiles"
    running_manager = ProfileManager(data_dir)

    # Model the backend updating files while the DNS process still holds the old
    # in-memory snapshot.  Both identities remain required; the reload must not
    # turn admission into an IP-only or MAC-only check.
    backend_writer = ProfileManager(data_dir)
    profile = backend_writer.create_profile("Managed device")
    backend_writer.create_binding(
        profile.id,
        "mac",
        "02:00:00:00:00:55",
        name="Managed phone",
    )
    backend_writer.create_binding(
        profile.id,
        "ip",
        "192.168.1.55",
        name="Managed phone",
    )
    assert trigger_profiles_reload(str(data_dir)) is True

    assert (
        running_manager.is_known_device(
            "192.168.1.55", "02:00:00:00:00:55"
        )
        is True
    )
    assert running_manager.is_known_device("192.168.1.55") is False
    assert (
        running_manager.is_known_device(
            "192.168.1.55", "02:00:00:00:00:56"
        )
        is False
    )
    assert (
        running_manager.is_known_device(
            "192.168.1.56", "02:00:00:00:00:55"
        )
        is False
    )
