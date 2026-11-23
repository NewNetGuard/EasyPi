"""Shared Yandex compact-TLS transport observations.

Both the ClientHello shape and a short burst across the two root SNI classes can
occur in ordinary browser traffic. The temporal operator in ``behavior.py``
therefore records transport activity, not an ad verdict. This module does not
authorize packet blocking.
"""

from ....signatures import TlsClientHelloSignature


YANDEX_MOBILE_ADS_SIGNATURE = TlsClientHelloSignature(
    app="mobile_ads_yandex",
    ports=(443,),
    record_length=512,
    server_names=("yandex.com", "yandex.ru"),
    note="compact shared Yandex mobile TLS fallback; shadow observation only",
)

SIGNATURES = (YANDEX_MOBILE_ADS_SIGNATURE,)

__all__ = ["SIGNATURES", "YANDEX_MOBILE_ADS_SIGNATURE"]
