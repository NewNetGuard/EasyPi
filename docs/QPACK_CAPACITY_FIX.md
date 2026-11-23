# QPACK capacity accounting fix and numeric diagnostics

Date: 2026-11-03. Follows the live limits.qpack_capacity finding.
No new browser viewing or capture was performed in this task.

## Implemented changes

The former combined capacity code is now split:

- limits.qpack_table_capacity: the encoder requested a dynamic-table capacity
  above the observer's existing maximum.
- limits.qpack_entry_capacity: an individual decoded entry's name/value lengths
  plus the QPACK 32-byte accounting overhead exceed that maximum.

For these two codes only, DecodeError accepts requested_bytes and limit_bytes.
Only non-boolean integers in the range 0 through 2^62-1 are admitted. No extra
arbitrary fields, strings or exception messages are serialized. Bridge preserves
the numbers as decoder_requested_bytes / decoder_limit_bytes in its terminal
Snapshot; Chrome's bounded diagnostics expose them. Tests cover invalid/private
input and the existing IPC response-size ceiling with maximum numeric values.

## Proven accounting defect fixed without increasing limits

The guard previously assigned a 512-byte estimate to any static-table header
name and a 512/512-byte estimate to an indexed static name/value pair. These
conservative estimates could reject valid QPACK even within the configured
memory/header limits.

A reproducible example:

- Static index 0 uses the 10-byte name :authority.
- Generated value length: 3,800 bytes.
- Actual QPACK entry size: 10 + 3,800 + 32 = 3,842 bytes, below 4,096.
- Old estimate: 512 + 3,800 + 32 = 4,344 bytes, falsely over the same limit.

The corrected guard accepts that generated instruction, and the existing native
QPACK decoder independently accepts it and reconstructs the expected lengths.
No browser content was used. A separate regression verifies 64 valid small
static field representations are not rejected due to fictitious 1,024-byte
field sizes, while the 65th still violates the existing field-count maximum.

`qpack_static.py` contains only the byte lengths of all 99 static name/value
pairs. Every pair is regression-checked against an indexed decode using the
existing pylsqpack library. No observed header contents are stored in this table.
The constants describe [RFC 9204 Appendix A](https://www.rfc-editor.org/rfc/rfc9204.html#appendix-A).
The actual entry-size rule is defined in
[RFC 9204 section 3.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.1).

This fixes a demonstrated false positive. It does not prove that the last
YouTube errors came from this branch: the previous code did not record the
branch or requested capacity. In particular 65,536-byte table requests used in
the new tests are generated diagnostic fixtures, NOT measurements from YouTube.

## Bounds and measurements

No configured resource maximum changed:

- Dynamic table / native decoder maximum: 4,096 bytes.
- Decoded header limit: 16,384 bytes; field-count limit: 64.
- Connection envelope: 1 MiB; existing global/CPU/RAM limits unchanged.
- Metadata superset bound at capacity 4,096: 128 retained length pairs.

A Windows tracemalloc experiment after 1,000 synthetic insertions measured
21,336 bytes of current Python allocation delta and 30,608 bytes peak delta,
retaining 128 pairs. The fixed static length tuple and pair objects measured
6,376 bytes process-wide (excluding shared integer object accounting). These
are Python allocation measurements, not total process RSS or native decoder
memory measurements. The native capacity remains fixed and was not enlarged.

Oversized table requests still stop before acceptance. Oversized entries still
stop without an admitted entry. Split capacity instructions wait until complete
before reporting a number. The guard remains in front of the native decoder.

## Executed verification

- Windows: 67 passed, three opt-in Linux capture tests skipped.
- Pi inactive candidate: 70 passed, zero failures.
- All static-table constants checked against the existing native decoder.
- Genuine AEAD-protected QPACK-capacity failure carries only its fixed code and
  numeric measurements, preserved through Bridge closure and key cleanup.
- Existing generated H2/H3 positive/negative cases and buffer tests still pass.
- The maximum diagnostic status, including six large numeric capacity records,
  remains under the existing private IPC response limit.

The previous inactive observer source was backed up before updating its runtime
snapshot. No production backend executable, active service, firewall rule,
route, Chameleon configuration or Mobile APK/setting was replaced or restarted.
The observer stays inactive; no CDN blocking was added. No captured secret,
cookie, private URL or viewing content entered the source or test fixtures.

## Next live acceptance

Run one bounded diagnostic viewing after verifying the phone network, scope,
monitor and lease. Require zero unexplained capture loss and retain numeric
terminal measurements. If a genuine table request exceeds 4,096, preserve its
exact numeric value and calculate an explicit expanded native/metadata budget
before considering another capacity. Do not automatically adopt the peer's size.

If the previous failures were false entry-size estimates, the fixed guard should
allow further authenticated decoding with identical limits. If not, the new
branch and requested/limit numbers identify the remaining barrier. The separate
TCP timeout still requires its own evidence. This candidate is not proof of
advertisement identification or readiness to block shared YouTube connections.

Rollback: revert this task commit and restore the inactive observer snapshot
backup if needed; no schema or persistent configuration migration is involved.
