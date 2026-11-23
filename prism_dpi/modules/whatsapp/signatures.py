"""WhatsApp block.

WhatsApp's chat channel (chatd) opens a NON-TLS connection to Meta edge IPs whose
first client bytes are "ED" (0x45 0x44) — its edge routing header, confirmed on
many live edges (57.144.x, 157.240.x, ...). Facebook/Instagram on the SAME Meta
IPs open with a TLS ClientHello (0x16), so dropping the "ED" first packet targets
WhatsApp precisely — no IP/SNI collateral, no MITM.

The generated inline u32 rule drops that packet in-kernel before it is forwarded,
so WhatsApp cannot get a chat connection up and cannot escape by roaming edges.
(WhatsApp over cellular is out of scope — that traffic never reaches the gateway.)
"""

from ...signatures.base import AppSignature, HttpHostSignature

CHATD_SIGNATURE = AppSignature(
    app="whatsapp",
    ports=(443,),
    prefix=b"ED",
    note="chatd non-TLS 'ED' edge header; shares Meta IPs with FB/IG",
)

HTTP_FALLBACK_SIGNATURE = HttpHostSignature(
    app="whatsapp",
    port=80,
    request_line="POST /chat HTTP/1.1",
    host="c.whatsapp.net",
    note="chatd HTTP fallback observed on shared Meta edges",
)

SIGNATURES = (CHATD_SIGNATURE, HTTP_FALLBACK_SIGNATURE)

# Backward-compatible name for callers that expect the primary signature.
SIGNATURE = CHATD_SIGNATURE
