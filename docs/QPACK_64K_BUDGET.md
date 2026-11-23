# QPACK 64 KiB: bounded support and freeze checkpoint

2026-11-03. The earlier live test measured three
authenticated QUIC flows requesting 65,536 bytes against Prism's 4,096-byte
maximum. This change accepts that capacity and rejects anything larger before
it reaches the native decoder. It does not identify or block advertisements.

## Allocation budget

The protocol capacity counts each entry's name, value and 32-byte charge
([RFC 9204 §3.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2)).
It is not a heap limit. The 65,536-byte capacity bounds the live table to 2,048
entries. Prism's length mirror now uses a fixed array of two 32-bit lengths per
slot, 16,384 bytes of data, instead of per-entry dictionaries, tuples and
integers. Absolute indices outside the retained window cannot alias a reused
slot. Rotation takes constant work per insertion.

The estimate below is for the pinned 64-bit `pylsqpack` 1.0.0 implementation
and the existing default stream/header limits. The native source reviewed was
the [1.0.0 source distribution](https://pypi.org/project/pylsqpack/1.0.0/#files),
including its vendored ls-qpack and [Python binding](https://github.com/aiortc/pylsqpack/blob/1.0.0/src/pylsqpack/binding.c).
The source archive and relevant files are hashed in the measurements JSON.

| QPACK allowance component | Bytes per flow |
| --- | ---: |
| Logical table, including the native entry structs (28 bytes each) | 65,536 |
| Huffman allocation slack and overlapping reallocations: 6 × 16,384 | 98,304 |
| Native allocator padding/bookkeeping allowance: 32 × (2,048 + 2) | 65,600 |
| Old and new pointer rings during growth: (2,048 + 4,096) × 8 | 49,152 |
| Fixed native decoder, wrapper and control state allowance | 16,384 |
| Fixed length array and its object overhead allowance | 16,896 |
| Header input, preflight and decode work buffers: 6 × 16,384 | 98,304 |
| Field object allowance: 64 × 128 | 8,192 |
| **Estimated live allocation allowance** | **418,368** |
| **Rounded reservation, including headroom** | **524,288** |

The native insertion paths can allocate based on the encoded Huffman length
and grow the buffer. We allow up to three times the encoder stream byte limit
for this slack and another three times for temporary coexistence during growth.
Duplicates copy decoded bytes, already included in the logical table charge.
The existing 16 KiB stream bound applies to the only client encoder stream;
a second encoder stream is rejected, as required by
[RFC 9204 §4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2).
Only complete, preflighted instructions go to native code. The native blocked
stream limit stays zero; preflight handles pending headers under the existing
Python stream limits. The decoded header limit and the field-count limit stay
16 KiB and 64. The reservation formula scales for non-default caller bounds.

The default QUIC envelope is 999,424 bytes: 393,216 for three copies of eight
streams, 65,536 pending bytes, 16,384 encoder guard bytes, and 524,288 for QPACK.
Pending field blocks replace bytes consumed from a stream buffer, so they fit
in the three-copy stream budget. The bridge charges the QPACK allowance in its
existing 1 MiB per-flow resident check. The original TCP envelope check stays
in place; a caller cannot configure a QUIC envelope smaller than its buffers
and QPACK allowance.

At 16 concurrent flows, QPACK accounts for at most 8 MiB of the reserved flow
budget. Sixteen 1 MiB flow reservations plus 589,824 fixed bytes total
17,367,040 bytes, below the unchanged 32 MiB global admission limit before
other existing external reservations. The seventeenth flow still cannot open.
These figures budget application allocations. They are not an RSS guarantee:
Python, shared libraries and allocator arenas also contribute to process
memory. The existing observer service still has `MemoryMax=268435456` and a
25% CPU quota; it was not started or changed by this task.

## Measurement and verification

The offline probe `tests/acceptance/qpack_memory_probe.py` used generated
instructions in fresh processes on the test Pi (64-bit Python 3.13.5,
`pylsqpack` 1.0.0). It filled and rotated maximum-entry tables, exercised large
and wide Huffman values, then decoded a near-limit field section with all
tables resident. The direct decoder probe intentionally processes more
encoder bytes than one production QUIC stream permits. It measures glibc
allocation deltas via `mallinfo2` with `PYTHONMALLOC=malloc`, which includes
native allocations, and separately reports sampled RSS and process high-water
RSS. Sampling can miss transient allocations; the source allowance includes
reallocation headroom. Tracemalloc alone is not a native memory measurement.

| Concurrent decoders | Sampled malloc increase | Sampled RSS increase |
| ---: | ---: | ---: |
| 1 | 475,824 bytes | 884,736 bytes |
| 16 | 6,037,984 bytes | 6,619,136 bytes |

The actual length array object was 16,464 bytes per flow. The 16-decoder run's
total RSS high-water mark was 24,461,312 bytes, including the interpreter and
probe. Measurements are in `QPACK_64K_MEASUREMENTS.json`.

- Windows: 91 targeted tests passed, six environment-specific tests skipped.
- Pi offline: 40 targeted QPACK/QUIC tests passed. Temporary source was removed.
- Exact-capacity acceptance and one-byte-over rejection were checked through
  the guard and AEAD-authenticated QUIC paths. Native table fill, rotation,
  wrapped Insert Count and expired metadata references were exercised.
- Sixteen Bridge flows remained open while encoder packets and header packets
  were interleaved. All recovered their authenticated HTTP/3 headers from a
  dynamic entry after the capacity instruction. Admission rejected flow 17.
- Missing/wrong key controls emitted zero headers. Existing HTTP/2 recovery and
  HTTP/3 controls passed. Excess decoded header bytes/field counts still fail.
- A supplemental comparison using five test modules from the separate Mobile
  repository against the server package produced the same 14 diagnostic
  contract failures on both the baseline and the candidate (46 passed, one
  skipped in each). Those tests expect Mobile-specific counters, reasons and
  error text; the mismatch predates this change and was left untouched.

This commit is the project freeze checkpoint. No new YouTube playback, live
capture, TLS secret collection, production deployment, or change to Mobile,
Prism services, Chameleon, firewall or routing was performed. The tested fix
removes the measured QPACK barrier in the decoder; live YouTube recovery beyond
that instruction and ad identification remain unverified on this candidate.
Rollback is a Git revert; no migration or runtime rollback is needed.
