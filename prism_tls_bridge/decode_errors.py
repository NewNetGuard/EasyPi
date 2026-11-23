"""Fixed diagnostic vocabulary. Never serialize exception text or packet data."""

CODES = frozenset({
    "aead.authentication_failed", "aead.key_phase_order", "aead.key_update_unsupported",
    "frame.truncated", "frame.unsupported", "frame.unsupported_version", "frame.internal",
    "stream.malformed", "stream.conflicting_retransmission",
    "qpack.decompression", "qpack.encoder", "qpack.decoder", "qpack.invalid_field",
    "qpack.invalid_reference", "qpack.truncated", "qpack.huffman",
    "reassembly.malformed_header", "reassembly.invalid_length",
    "limits.pending_bytes", "limits.packet_count", "limits.ack_ranges",
    "limits.stream_count", "limits.stream_bytes", "limits.http3_frame",
    "limits.qpack_blocked", "limits.qpack_integer", "limits.qpack_literal",
    "limits.qpack_capacity", "limits.qpack_table_capacity", "limits.qpack_entry_capacity",
    "limits.qpack_encoder", "limits.qpack_encoded",
    "limits.qpack_decoded", "limits.retained_payload", "limits.input_work",
    "timeouts.missing_key", "timeouts.no_authenticated_packet", "timeouts.headers",
    "timeouts.qpack", "timeouts.stream_gap", "timeouts.key_lease", "timeouts.idle",
})


class DecodeError(ValueError):
    def __init__(self, code, *, requested_bytes=None, limit_bytes=None):
        self.code = code if code in CODES else "frame.internal"
        self.measurements = {}
        if self.code in {"limits.qpack_table_capacity", "limits.qpack_entry_capacity"}:
            for name, value in (("requested_bytes", requested_bytes), ("limit_bytes", limit_bytes)):
                if type(value) is int and 0 <= value < 1 << 62:
                    self.measurements[name] = value
        super().__init__(self.code)


def safe_error_code(error, stage):
    if isinstance(error, DecodeError):
        return error.code
    # Exact exception types, never their message (which may contain input).
    from aioquic.buffer import BufferReadError
    from aioquic.quic.crypto import CryptoError
    from hpack.exceptions import HPACKDecodingError
    import pylsqpack
    if isinstance(error, CryptoError):
        return "aead.authentication_failed"
    if isinstance(error, pylsqpack.DecompressionFailed):
        return "qpack.decompression"
    if isinstance(error, pylsqpack.EncoderStreamError):
        return "qpack.encoder"
    if isinstance(error, pylsqpack.DecoderStreamError):
        return "qpack.decoder"
    if isinstance(error, HPACKDecodingError):
        return "qpack.huffman"
    if isinstance(error, BufferReadError):
        return "reassembly.malformed_header" if stage == "packet" else "frame.truncated"
    return {"stream": "stream.malformed", "qpack": "qpack.invalid_field",
            "packet": "reassembly.malformed_header"}.get(stage, "frame.internal")
