from __future__ import annotations

import ipaddress
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class MobilePrismCommand:
    id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str
    policy: str
    confidence: float
    expires_at: float


@dataclass(frozen=True)
class MobilePrismConfirmation:
    command: MobilePrismCommand
    package_name: str
    confirmed_at: float


class MobilePrismBroker:
    """Short-lived, authenticated hand-off from PRISM to linked phones.

    Commands intentionally live only in memory: exact-flow decisions expire in
    seconds and must never return after a restart as stale firewall policy.
    """

    DEVICE_TTL_SECONDS = 90.0
    COMMAND_TTL_SECONDS = 8.0
    MAX_ADDRESSES_PER_DEVICE = 8
    MAX_COMMANDS_PER_DEVICE = 64

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._addresses: dict[str, tuple[frozenset[str], float]] = {}
        self._queues: dict[str, deque[MobilePrismCommand]] = defaultdict(deque)
        self._claimed: dict[tuple[str, str], MobilePrismCommand] = {}
        self._confirmed: deque[MobilePrismConfirmation] = deque()

    @staticmethod
    def normalize_addresses(values: Iterable[str]) -> frozenset[str]:
        normalized: set[str] = set()
        for value in values:
            address = ipaddress.ip_address(str(value).strip())
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                continue
            normalized.add(str(address))
            if len(normalized) >= MobilePrismBroker.MAX_ADDRESSES_PER_DEVICE:
                break
        return frozenset(normalized)

    def register(self, device_id: str, addresses: Iterable[str], *, now: float | None = None) -> None:
        current = time.time() if now is None else now
        normalized = self.normalize_addresses(addresses)
        with self._lock:
            self._addresses[device_id] = (normalized, current + self.DEVICE_TTL_SECONDS)
            self._purge_locked(current)

    def addresses_for(self, device_id: str, *, now: float | None = None) -> frozenset[str]:
        current = time.time() if now is None else now
        with self._lock:
            self._purge_locked(current)
            registered = self._addresses.get(device_id)
            return registered[0] if registered is not None else frozenset()

    def enqueue_candidate(self, candidate: object, *, now: float | None = None) -> int:
        current = time.time() if now is None else now
        client_ip = str(getattr(candidate, "client_ip"))
        command = MobilePrismCommand(
            id=str(uuid.uuid4()),
            client_ip=client_ip,
            client_port=int(getattr(candidate, "client_port")),
            server_ip=str(ipaddress.ip_address(str(getattr(candidate, "server_ip")))),
            server_port=int(getattr(candidate, "server_port")),
            protocol=str(getattr(candidate, "protocol")).lower(),
            policy=str(getattr(candidate, "policy"))[:64],
            confidence=float(getattr(candidate, "confidence")),
            expires_at=current + self.COMMAND_TTL_SECONDS,
        )
        queued = 0
        with self._lock:
            self._purge_locked(current)
            for device_id, (addresses, expires_at) in self._addresses.items():
                if expires_at <= current or client_ip not in addresses:
                    continue
                queue = self._queues[device_id]
                while len(queue) >= self.MAX_COMMANDS_PER_DEVICE:
                    queue.popleft()
                queue.append(command)
                queued += 1
        return queued

    def claim(self, device_id: str, *, limit: int = 8, now: float | None = None) -> list[MobilePrismCommand]:
        current = time.time() if now is None else now
        claimed: list[MobilePrismCommand] = []
        with self._lock:
            self._purge_locked(current)
            queue = self._queues[device_id]
            while queue and len(claimed) < max(1, min(limit, 16)):
                command = queue.popleft()
                if command.expires_at <= current:
                    continue
                self._claimed[(device_id, command.id)] = command
                claimed.append(command)
        return claimed

    def acknowledge(
        self,
        device_id: str,
        command_id: str,
        *,
        result: str,
        package_name: str | None,
        now: float | None = None,
    ) -> bool:
        current = time.time() if now is None else now
        with self._lock:
            self._purge_locked(current)
            command = self._claimed.pop((device_id, command_id), None)
            if command is None:
                return False
            # A linked phone running the DNS-only home tunnel cannot apply an
            # arbitrary flow rule itself.  It reports "matched" after Android
            # confirms which package owns the exact tuple; the gateway can then
            # make one final, authoritative enforcement attempt.
            if result == "matched" and package_name:
                self._confirmed.append(
                    MobilePrismConfirmation(
                        command=command,
                        package_name=package_name,
                        confirmed_at=current,
                    )
                )
            return True

    def pop_confirmed(
        self, *, limit: int = 16, now: float | None = None
    ) -> list[MobilePrismConfirmation]:
        current = time.time() if now is None else now
        confirmations: list[MobilePrismConfirmation] = []
        with self._lock:
            self._purge_locked(current)
            while self._confirmed and len(confirmations) < max(1, min(limit, 32)):
                confirmation = self._confirmed.popleft()
                if confirmation.command.expires_at > current:
                    confirmations.append(confirmation)
        return confirmations

    def _purge_locked(self, now: float) -> None:
        for device_id, (_addresses, expires_at) in tuple(self._addresses.items()):
            if expires_at <= now:
                self._addresses.pop(device_id, None)
                self._queues.pop(device_id, None)
        for key, command in tuple(self._claimed.items()):
            if command.expires_at <= now:
                self._claimed.pop(key, None)
        while self._confirmed and self._confirmed[0].command.expires_at <= now:
            self._confirmed.popleft()


mobile_prism_broker = MobilePrismBroker()

