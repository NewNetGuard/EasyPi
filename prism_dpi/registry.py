"""Registry of active Prism DPI modules."""

from .modules import mobile_ads, whatsapp
from .signatures import AppSignature, HttpHostSignature, TlsClientHelloSignature


Signature = AppSignature | HttpHostSignature | TlsClientHelloSignature

# Each module may contribute more than one transport signature.
REGISTRY: tuple[Signature, ...] = (
    *whatsapp.SIGNATURES,
    *mobile_ads.google.SIGNATURES,
    *mobile_ads.yandex.SIGNATURES,
)


def get(app: str) -> Signature | None:
    """Return the primary signature for an app, if the module is registered."""
    for signature in REGISTRY:
        if signature.app == app:
            return signature
    return None


def get_all(app: str) -> tuple[Signature, ...]:
    """Return every registered transport signature for an app."""
    return tuple(signature for signature in REGISTRY if signature.app == app)


__all__ = ["REGISTRY", "Signature", "get", "get_all"]
