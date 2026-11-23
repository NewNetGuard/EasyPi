"""Bounded QPACK allocation allowance inside the existing flow envelope.

See docs/QPACK_64K_BUDGET.md for the audited native allocation assumptions.
This is an admission allowance, not an assertion about process RSS.
"""

TABLE_CAPACITY = 65536
QPACK_RESERVED_BYTES = 512 * 1024


def qpack_reservation(stream_bytes, header_bytes, fields):
    entries = TABLE_CAPACITY // 32
    # Source-audited live allocations and transient reallocations, rounded up
    # by the default 512 KiB allowance. Scale for non-default caller limits.
    estimate = (TABLE_CAPACITY + 6 * stream_bytes + 32 * (entries + 2)
                + 3 * entries * 8 + 16384 + 8 * entries + 512
                + 6 * header_bytes + 128 * fields)
    return max(QPACK_RESERVED_BYTES, estimate)


def quic_envelope(limits):
    # Blocked field blocks replace bytes consumed from stream buffers; they do
    # not add a fourth full copy of every stream. Guard input is separate.
    return (3 * limits.max_streams * limits.stream_bytes
            + limits.decoder_buffer_bytes + limits.header_bytes
            + qpack_reservation(limits.stream_bytes, limits.header_bytes,
                                limits.max_header_fields))
