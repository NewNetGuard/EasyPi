# TLS Bridge key admission and Android lab validation

Date: 2026-10-31. This is an experimental observer, not an inline filtering
requirement. The normal backend binary and Prism/Chameleon services were not
replaced or integrated with the new decoder.

## Bounded admission

Per-flow retention remains eight records. Provisional candidates rotate within
that bound; observed wire identifiers and AEAD-authenticated keys are protected.
An optional authenticated enrollment `key_session_id` rejects other-session NSS
records before they consume slots. It is an admission restriction, never proof
of decryption. Only successful AEAD authentication confirms the key binding.
ECH fallback also requires authentication. Without the endpoint hint, admission
before capture is bounded best effort; arbitrary unknown candidates cannot all
be preserved. A full store no longer permanently excludes later correct groups.
QUIC retries follow candidate revisions, including same-size replacements.

The snapshot diagnostic separates `missing_key`, `matching_keys_timeout`,
`invalid_secret`, `key_store_full` and `capture_loss`; transport/closure reasons
remain available separately. Invalid unverified initial TLS secrets can be
replaced. Authentication failure after a confirmed stream remains a failure.
Counters contain no secret values or NSS identifiers.

## Target infrastructure cause and repair

A read-only rule watcher reproduced the fingerprint transition: the periodic
gateway repair unconditionally reloaded UFW approximately once per minute.
During the reload, UFW chains briefly disappeared and built-in INPUT/FORWARD
policies changed from DROP to ACCEPT. Timer logs correlate with the captured
abort. The earlier run without an exact transient snapshot cannot independently
prove that its abort had the same cause.

The gateway script now checks the required runtime route rule first. A healthy
tick is read-only; a missing rule is added and verified. The unconditional reload
and broad FORWARD ACCEPT fallback were removed. The corrected script was applied
to the authorized test Pi with an owner-private backup and syntax validation.
Eight completed checks after application produced no further watched rule
transitions. Regression tests cover the healthy, missing-rule and failed-repair
paths. No reboot was performed. The separate IPv6 guard startup race is not
fixed by this change.

## Android proof and limits

A separate arm64 EasyPi Mobile Lab APK, with its own app ID and native artifact,
performed four real TLS1.3/HTTP2 GET requests and received four HTTP 200 responses.
An isolated Pi capture reported zero kernel drops. Replaying that scoped capture
through BridgeWorker recovered four authenticated request headers on streams
1, 3, 5 and 7. No-key and corrupted-secret controls recovered zero. Foreign-key
noise with explicit session admission and a separate unhinted prefilled-cache
control each recovered four headers without increasing retention. These modes
reuse the same requests, not additional coverage. Private exports were removed;
no host keylog was written. The installed ordinary Mobile APK was unchanged.

This is offline replay of real owned-client Android packets, not live Android
streaming, full HTTP bodies, HTTP3 or third-party app decryption. Go KeyLogWriter
covers only the explicitly configured Lab client, not Kotlin TLS, the production
DoH client, YouTube, Telegram or WhatsApp. No CA/MITM/pinning bypass was used.
The Mobile experiment directory contains the build/run procedure and validation.

## Acceptance policy

Policy version 2 requires actual capture counters and actual suppressed/corrupted
key-frame counts for negative controls. TCP wrong-secret acceptance requires a
specific authentication-rejection diagnostic; generic decoder_error is not a
pass. Journal collection waits briefly for final observer events before closing,
so initial zero capture counters cannot substitute for the final snapshot.
Older failures and fingerprint snapshots remain preserved privately and are not
rescored. A new duration run has an independent timeline; prior interrupted
runs do not count toward six-hour continuity. Historical HTTP3 UDP-integrity and
key-timeout failures remain evidence, not retroactively resolved cases.

Selected decoder, shadow, admission, acceptance and gateway tests passed locally
(87 passed, one binary-dependent test skipped). The separate gateway regression selection passed 18 tests; the Lab
native client passed three tests and Android lint passed. Target/browser and
long-run evidence remain private under ignored .build; duration completion must
be read from the current report, not inferred from this preparation document.

The new frozen ARM observer passed all six normal target cases: Firefox, Chrome
and Edge with HTTP2 and HTTP3, 24/24 HTTP 200 responses and 24/24 authenticated
request headers. Separate Firefox wrong-key HTTP2 and no-key HTTP3 controls
returned all eight HTTP 200 responses with zero headers. TCP corruption exposed
invalid_secret; missing-key QUIC exposed missing_key/matching_keys_timeout.
Earlier smoke failures caused by premature journal-follower shutdown remain
retained; the successful repeat did not overwrite their private evidence.
