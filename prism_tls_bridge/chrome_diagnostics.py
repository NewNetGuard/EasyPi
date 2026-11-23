"""Opt-in request categories only. No URLs, queries, headers or ad verdicts."""
from urllib.parse import urlsplit
from collections import deque
from .decode_errors import CODES


class FlowDiagnostics:
    """Bounded stage metadata, never randoms, keys, addresses or raw errors."""
    REASONS = frozenset({"idle_timeout", "key_lease_expired", "matching_keys_timeout",
        "tcp_gap_timeout", "quic_or_qpack_gap_timeout", "invalid_secret", "decoder_error",
        "retained_payload_budget", "input_work_budget", "input_size_limit", "caller_closed",
        "bridge_closed", "capture_loss_reported", "quic_missing_initial", "malformed_quic_header",
        "tcp_data_after_fin", "tcp_overlap_conflict", "malformed_packet", "unsupported_request_target"})
    DIAGNOSTICS = frozenset({"missing_key", "matching_keys_timeout", "invalid_secret",
        "key_store_full", "capture_loss", "unrelated_session"})

    def __init__(self):
        self.active = {}
        self.closed = deque(maxlen=6)

    def opened(self, fid, transport):
        self.active[fid] = dict(transport=transport, hello_seen=False,
                                session_key_available=False, other_session_keys_seen=False, key_submissions=0)

    def matched(self, fid, hello=False, matching=False, submitted=False, other=False):
        row = self.active.get(fid)
        if row is not None:
            row["hello_seen"] |= hello
            row["session_key_available"] |= matching
            row["other_session_keys_seen"] |= other
            row["key_submissions"] += int(submitted)

    def retire(self, bridge):
        for fid in list(self.active):
            if fid in bridge.flows:
                continue
            row = self.active.pop(fid)
            snapshot = bridge.closed.get(fid)
            row.update(reason=snapshot.reason if snapshot and snapshot.reason in self.REASONS else "other",
                       diagnostic=snapshot.diagnostic if snapshot and snapshot.diagnostic in self.DIAGNOSTICS else "other",
                       state=snapshot.state.value if snapshot else "Unknown",
                       authenticated_headers=bool(snapshot and snapshot.request_headers_complete))
            code = getattr(snapshot, "decoder_code", "none")
            row["decoder_code"] = code if isinstance(code, str) and code in CODES else "none"
            row["aead_authenticated_packets"] = getattr(snapshot, "quic_authenticated_packets", 0)
            if code in {"limits.qpack_table_capacity", "limits.qpack_entry_capacity"}:
                for field in ("decoder_requested_bytes", "decoder_limit_bytes"):
                    value = getattr(snapshot, field, None)
                    if type(value) is int and 0 <= value < 1 << 62:
                        row[field] = value
            self.closed.append(row)

    def clear(self):
        self.active.clear()
        self.closed.clear()

    def status(self):
        return dict(active_stages=list(self.active.values()), recent_closed=list(self.closed),
                    recent_closed_limit=6, scope_complete=False)


def request_category(request):
    """Accept authenticated Bridge metadata; never return arbitrary input."""
    try:
        host = urlsplit("https://" + request.get("authority", "")).hostname or ""
        path = request.get("path", "").split("?", 1)[0].split("#", 1)[0]
    except (ValueError, TypeError, AttributeError):
        return dict(host_group="other", route="other", protocol="unknown")
    host = host.lower().rstrip(".")

    def under(suffix):
        return host == suffix or host.endswith("." + suffix)

    if under("googlevideo.com"):
        group = "video_cdn"
    elif under("youtube.com") or host == "youtubei.googleapis.com":
        group = "youtube"
    elif any(under(s) for s in ("doubleclick.net", "googlesyndication.com", "googleadservices.com")):
        group = "ad_network"
    elif under("ytimg.com"):
        group = "image_cdn"
    else:
        group = "other"
    # These are endpoint types, NOT proof that a response contains an ad/video.
    route = {
        "/videoplayback": "media_request",
        "/youtubei/v1/player": "player_api",
        "/youtubei/v1/next": "next_api",
        "/youtubei/v1/browse": "browse_api",
        "/api/stats/ads": "ad_telemetry",
        "/api/stats/playback": "playback_telemetry",
        "/api/stats/watchtime": "watchtime_telemetry",
        "/pagead/interaction/": "ad_telemetry",
        "/watch": "watch_page",
    }.get(path, "other")
    protocol = request.get("protocol")
    return dict(host_group=group, route=route,
                protocol=protocol if protocol in ("h2", "h3") else "unknown")
