"""Protocol constants and generated fields only; no browser-derived secrets."""
import json

import pylsqpack
import pytest

from prism_tls_bridge.decode_errors import DecodeError
from prism_tls_bridge.qpack_guard import Guard
from prism_tls_bridge.qpack_static import STATIC_LENGTHS


def prefixed(value, bits, mask=0):
    maximum = (1 << bits) - 1
    if value < maximum:
        return bytes([mask | value])
    result = bytearray([mask | maximum])
    value -= maximum
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def capacity(value):
    return prefixed(value,5,0x20)


def static_insert(index, length):
    return prefixed(index,6,0xc0) + prefixed(length,7) + b"x"*length


def test_all_static_length_constants_match_existing_native_decoder():
    assert len(STATIC_LENGTHS) == 99
    for index, expected in enumerate(STATIC_LENGTHS):
        block = b"\0\0" + prefixed(index,6,0xc0)
        _, headers = pylsqpack.Decoder(0,0).feed_header(index*4,block)
        assert len(headers) == 1
        assert tuple(map(len,headers[0])) == expected


def test_valid_near_capacity_static_name_insert_is_not_falsely_rejected():
    guard = Guard()
    wire = capacity(4096) + static_insert(0,3800)
    # The previous 512-byte name estimate falsely exceeded the same 4096 budget.
    assert 512 + 3800 + 32 > 4096
    assert STATIC_LENGTHS[0][0] + 3800 + 32 <= 4096
    validated = guard.feed_encoder(wire)
    assert validated == wire
    assert guard.entries[0] == (10,3800)
    native = pylsqpack.Decoder(4096,0)
    native.feed_encoder(validated)
    block = b"\x02\x00\x80"
    assert guard.check(block)
    _, headers = native.feed_header(0,block)
    assert tuple(map(len,headers[0])) == (10,3800)


def test_static_field_accounting_is_exact_without_increasing_header_limit():
    guard = Guard()
    block = b"\0\0" + prefixed(72,6,0xc0)*64
    assert guard.check(block)
    _, headers = pylsqpack.Decoder(0,0).feed_header(0,block)
    assert len(headers) == 64
    assert sum(len(k)+len(v)+32 for k,v in headers) < guard.maximum
    with pytest.raises(DecodeError) as result:
        guard.check(block + prefixed(72,6,0xc0))
    assert result.value.code == "limits.qpack_decoded"


def test_requested_table_capacity_is_measured_before_acceptance():
    guard = Guard()
    with pytest.raises(DecodeError) as result:
        guard.feed_encoder(capacity(65536))
    error = result.value
    assert error.code == "limits.qpack_table_capacity"
    assert error.measurements == dict(requested_bytes=65536,limit_bytes=4096)
    assert guard.capacity == 4096 and not guard.entries


def test_oversize_entry_reports_a_different_measurement():
    guard = Guard()
    with pytest.raises(DecodeError) as result:
        guard.feed_encoder(capacity(4096)+static_insert(0,4096))
    assert result.value.code == "limits.qpack_entry_capacity"
    assert result.value.measurements == dict(requested_bytes=4138,limit_bytes=4096)
    assert not guard.entries


def test_split_capacity_instruction_is_not_measured_prematurely():
    guard = Guard()
    wire = capacity(65536)
    assert guard.feed_encoder(wire[:-1]) == b""
    with pytest.raises(DecodeError) as result:
        guard.feed_encoder(wire[-1:])
    assert result.value.measurements["requested_bytes"] == 65536


def test_measurements_only_accept_fixed_bounded_integer_fields():
    for private in ("private-cookie", True, -1, 1<<62):
        error = DecodeError("limits.qpack_table_capacity",requested_bytes=private,limit_bytes=4096)
        assert error.measurements == {"limit_bytes":4096}
        assert "private-cookie" not in json.dumps(error.measurements)
    assert not DecodeError("frame.internal",requested_bytes=123).measurements


def test_invalid_static_index_still_rejected():
    with pytest.raises(DecodeError) as result:
        Guard().check(b"\0\0"+prefixed(99,6,0xc0))
    assert result.value.code == "qpack.invalid_reference"


def test_authenticated_qpack_capacity_event_contains_only_numeric_measurements():
    from test_quic_error_categories import decoder, protected, stream
    value, secret, output = decoder()
    value.feed(protected(secret,stream(2,b"\x02"+capacity(65537))))
    assert value.authenticated_packets == 1
    event = output[-1]
    assert event["error_code"] == "limits.qpack_table_capacity"
    assert event["requested_bytes"] == 65537 and event["limit_bytes"] == 65536
    assert secret.hex() not in json.dumps(event)
