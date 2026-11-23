"""
Tailscale Configuration Module

Handles auth key and interface configuration from environment/config.
Fails fast if required configuration is missing.
"""

import os
from dataclasses import dataclass


@dataclass
class TailscaleConfig:
    """Configuration for Tailscale remote access."""
    authkey: str
    interface: str
    
    def validate(self) -> None:
        """Validate configuration. Raises ValueError if invalid."""
        if not self.authkey:
            raise ValueError(
                "Tailscale auth key is required. "
                "Set EASYPI_TAILSCALE_AUTHKEY environment variable."
            )


def get_tailscale_config() -> TailscaleConfig:
    """
    Load Tailscale configuration from environment.
    
    Environment variables:
    - EASYPI_TAILSCALE_AUTHKEY: Required. The Tailscale auth key.
    - EASYPI_TAILSCALE_INTERFACE: Optional. Network interface to use (default: eth0)
    
    Returns TailscaleConfig instance.
    Note: Does NOT fail if authkey is missing - service will handle that gracefully.
    """
    authkey = os.environ.get("EASYPI_TAILSCALE_AUTHKEY", "")
    interface = os.environ.get("EASYPI_TAILSCALE_INTERFACE", "eth0")
    
    return TailscaleConfig(
        authkey=authkey,
        interface=interface
    )


def require_tailscale_config() -> TailscaleConfig:
    """
    Load and validate Tailscale configuration.
    
    Raises ValueError if required configuration is missing.
    Use this when you need to fail fast on missing config.
    """
    config = get_tailscale_config()
    config.validate()
    return config
