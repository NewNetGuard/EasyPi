"""
Heuristics API endpoints for NetProtection.

Provides endpoints for:
- Heuristics statistics
- Shadow mode management
- Alerts and notifications
- Signal inspection

© 2025 EasyPi Project
"""

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Any
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

from app.api.deps import require_admin
from app.models.user import User
from app.services.operation_event_service import OperationEventService
from config import ROOT_DIR

logger = logging.getLogger(__name__)

router = APIRouter()
operation_event_service = OperationEventService()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_fromtimestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _record_heuristics_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/guard-security",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record heuristics event %s: %s", action_id, exc)


# ============== Response Models ==============

class HeuristicsStats(BaseModel):
    """Overall heuristics statistics."""
    enabled: bool = True
    total_analyzed: int = 0
    blocked_by_heuristics: int = 0
    observed_domains: int = 0
    dga_detections: int = 0
    homoglyph_detections: int = 0
    first_seen_new: int = 0
    device_anomalies: int = 0
    thresholds: dict = Field(default_factory=lambda: {"observe": 30, "block": 70})
    last_updated: datetime = Field(default_factory=utc_now)


class ShadowDomainEntry(BaseModel):
    """Domain in shadow/observe mode."""
    domain: str
    score: float
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    signals: dict = Field(default_factory=dict)
    status: str = "observing"  # observing, promoted, expired, dismissed
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None


class ShadowModeStats(BaseModel):
    """Shadow mode statistics."""
    total_observing: int = 0
    total_promoted: int = 0
    total_dismissed: int = 0
    total_expired: int = 0
    pending_review: int = 0
    auto_promoted: int = 0


class SignalDetail(BaseModel):
    """Individual heuristic signal."""
    signal_type: str
    score: float
    confidence: float
    reason: str
    timestamp: datetime
    decayed_score: float


class DomainAnalysis(BaseModel):
    """Full analysis of a domain."""
    domain: str
    total_score: float
    verdict: str  # allow, observe, block
    signals: List[SignalDetail] = []
    first_seen: Optional[datetime] = None
    is_new_domain: bool = False
    in_shadow_mode: bool = False
    dga_analysis: Optional[dict] = None
    homoglyph_analysis: Optional[dict] = None


class AlertEntry(BaseModel):
    """Security alert."""
    id: str
    timestamp: datetime
    alert_type: str  # dga_attack, homoglyph_attack, traffic_spike, new_threat
    severity: str  # low, medium, high, critical
    domain: str
    details: dict = Field(default_factory=dict)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None


class ShadowActionRequest(BaseModel):
    """Request to act on shadow domain."""
    action: str  # promote, dismiss, extend
    reason: Optional[str] = None


class HeuristicsDetectorsUpdate(BaseModel):
    dga: Optional[bool] = None
    homoglyph: Optional[bool] = None
    first_seen: Optional[bool] = None
    domain_analysis: Optional[bool] = None
    device_anomaly: Optional[bool] = None
    asn_cluster: Optional[bool] = None
    shadow_mode: Optional[bool] = None


class HeuristicsTuningUpdate(BaseModel):
    dga_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    homoglyph_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    first_seen_days: Optional[int] = Field(default=None, ge=1, le=30)
    shadow_expire_days: Optional[int] = Field(default=None, ge=7, le=90)
    shadow_promote_hits: Optional[int] = Field(default=None, ge=10, le=1000)


class HeuristicsPerformanceUpdate(BaseModel):
    quick_mode_ms: Optional[int] = Field(default=None, ge=1, le=100)
    persist_signals: Optional[bool] = None
    max_signals_per_domain: Optional[int] = Field(default=None, ge=10, le=500)


class HeuristicsConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    observe_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    block_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    detectors: Optional[HeuristicsDetectorsUpdate] = None
    tuning: Optional[HeuristicsTuningUpdate] = None
    performance: Optional[HeuristicsPerformanceUpdate] = None


# ============== Helper Functions ==============

def get_heuristics_engine():
    """Get HeuristicsEngine instance from NetProtection."""
    try:
        import sys
        sys.path.insert(0, str(ROOT_DIR.parent))
        from easypi_netprotection.heuristics import HeuristicsEngine
        return HeuristicsEngine()
    except Exception as e:
        logger.warning(f"Heuristics engine not available: {e}")
        return None


def get_shadow_mode():
    """Get ShadowMode instance with real database."""
    try:
        import sys
        sys.path.insert(0, str(ROOT_DIR.parent))
        from easypi_netprotection.heuristics.shadow_mode import ShadowMode
        db_path = ROOT_DIR / "data" / "netprotection" / "shadow_mode.db"
        return ShadowMode(db_path)
    except Exception as e:
        logger.warning(f"Shadow mode not available: {e}")
        return None


def get_shadow_mode_manager():
    """Get ShadowModeManager instance."""
    try:
        import sys
        sys.path.insert(0, str(ROOT_DIR.parent))
        from easypi_netprotection.heuristics.shadow_mode import ShadowModeManager
        return ShadowModeManager()
    except Exception as e:
        logger.warning(f"Shadow mode manager not available: {e}")
        return None


def _get_netprotection_config_path() -> Path:
    """Resolve the active NetProtection config path."""
    config_path = os.environ.get("NETPROTECTION_CONFIG")
    if config_path:
        return Path(config_path)
    preferred_path = Path("/opt/EasyPi/config/netprotection.toml")
    if preferred_path.exists() or preferred_path.parent.exists():
        return preferred_path
    return Path("config/netprotection.toml")


def _get_netprotection_settings():
    """Load current NetProtection settings module."""
    import sys
    sys.path.insert(0, str(ROOT_DIR.parent))
    from easypi_netprotection.config import get_settings
    return get_settings()


def _netprotection_data_dir() -> Path:
    """Absolute NetProtection data dir.

    ``NETPROTECTION_DATA_DIR`` is RELATIVE (e.g. ``data/netprotection``); the DNS
    engine resolves it against its WorkingDirectory (``/opt/EasyPi``), but the
    backend runs from ``/opt/EasyPi/backend``. Anchoring to the backend CWD would
    point at the wrong (non-existent) directory, so we anchor to the install root
    — the parent of the ``easypi_netprotection`` package — instead.
    """
    settings = _get_netprotection_settings()
    d = Path(settings.NETPROTECTION_DATA_DIR)
    if d.is_absolute():
        return d
    try:
        import easypi_netprotection
        install_root = Path(easypi_netprotection.__file__).resolve().parent.parent
    except Exception:
        install_root = ROOT_DIR
    return install_root / d


def _persist_netprotection_settings(settings) -> None:
    """Persist settings to TOML and reload runtime caches."""
    import sys
    sys.path.insert(0, str(ROOT_DIR.parent))
    from easypi_netprotection.config import reload_settings

    config_path = _get_netprotection_config_path()
    settings.to_toml(config_path)
    reload_settings()


def _refresh_live_heuristics_runtime(settings) -> None:
    """Apply updated settings to long-lived heuristics singletons."""
    try:
        import sys
        sys.path.insert(0, str(ROOT_DIR.parent))
        from easypi_netprotection.heuristics import get_heuristics_engine
        from easypi_netprotection.heuristics.shadow_mode import get_shadow_mode

        get_heuristics_engine().apply_settings(settings.heuristics)
        get_shadow_mode().apply_settings(
            observe_threshold=settings.heuristics.observe_threshold,
            block_threshold=settings.heuristics.block_threshold,
            auto_expire_days=settings.heuristics.shadow_auto_expire_days,
            auto_promote_hits=settings.heuristics.shadow_auto_promote_hits,
        )
    except Exception as exc:
        logger.warning("Failed to refresh live heuristics runtime: %s", exc)


# ============== Endpoints ==============

@router.get("/stats", response_model=HeuristicsStats)
async def get_heuristics_stats(
    current_user: User = Depends(require_admin)
) -> HeuristicsStats:
    """
    Get overall heuristics statistics from Shadow Mode database.
    
    Returns real counts of blocked domains, observations, etc.
    """
    shadow = get_shadow_mode()

    if not shadow:
        return HeuristicsStats(
            enabled=False,
            total_analyzed=0,
            blocked_by_heuristics=0,
            observed_domains=0,
        )

    try:
        import sqlite3

        settings = _get_netprotection_settings().heuristics
        shadow_db = ROOT_DIR / "data" / "netprotection" / "shadow_mode.db"
        signals_db = ROOT_DIR / "data" / "netprotection" / "signals.db"

        observed_domains = 0
        total_hits = 0
        blocked_by_heuristics = 0
        dga_count = 0
        homoglyph_count = 0
        first_seen_new = 0
        device_anomalies = 0

        if shadow_db.exists():
            conn = sqlite3.connect(str(shadow_db))
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM shadow_domains")
            observed_domains = cursor.fetchone()[0] or 0
            cursor.execute("SELECT SUM(hit_count) FROM shadow_domains")
            total_hits = cursor.fetchone()[0] or 0
            # 'blocked_by_heuristics' is derived from flow_log below (real engine
            # blocks). The shadow 'auto_blocked' action was deprecated when shadow
            # auto-blocking was removed, so counting it here always returned 0.
            conn.close()

        if signals_db.exists():
            conn = sqlite3.connect(str(signals_db))
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(DISTINCT domain) FROM signals WHERE signal_type = 'dga'")
            dga_count = cursor.fetchone()[0] or 0
            cursor.execute("SELECT COUNT(DISTINCT domain) FROM signals WHERE signal_type = 'homoglyph'")
            homoglyph_count = cursor.fetchone()[0] or 0
            first_seen_cutoff = time.time() - (settings.first_seen_new_days * 86400)
            cursor.execute(
                "SELECT COUNT(DISTINCT domain) FROM signals WHERE signal_type = 'first_seen' AND timestamp >= ?",
                (first_seen_cutoff,),
            )
            first_seen_new = cursor.fetchone()[0] or 0
            if total_hits == 0:
                cursor.execute("SELECT COUNT(DISTINCT domain) FROM signals")
                total_hits = cursor.fetchone()[0] or 0
            conn.close()

        try:
            import sys
            sys.path.insert(0, str(ROOT_DIR.parent))
            from easypi_netprotection.heuristics.device_anomaly import get_device_anomaly_detector

            anomaly_stats = get_device_anomaly_detector().get_stats()
            device_anomalies = sum((anomaly_stats.get("anomalies_24h") or {}).values())
        except Exception as exc:
            logger.debug("Device anomaly stats unavailable: %s", exc)

        # Real "blocked" + "analyzed" counts from the decision log (flow_log).
        # blocked_by_heuristics = engine blocks BEYOND the static blocklist, i.e. the
        # evidence is a heuristic / behavioural / ML reason, not "domain in blocklist".
        flow_db = ROOT_DIR / "data" / "netprotection" / "flow_log.db"
        if flow_db.exists():
            try:
                conn = sqlite3.connect(f"file:{flow_db}?mode=ro", uri=True, timeout=4)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM flow_log")
                total_hits = cur.fetchone()[0] or total_hits
                cur.execute(
                    "SELECT COUNT(DISTINCT domain) FROM flow_log "
                    "WHERE status = 'blocked' "
                    "AND (evidence_summary IS NULL OR evidence_summary NOT LIKE 'domain in blocklist%')"
                )
                blocked_by_heuristics = cur.fetchone()[0] or 0
                conn.close()
            except Exception as exc:
                logger.debug("flow_log stats unavailable: %s", exc)

        return HeuristicsStats(
            enabled=settings.enabled,
            total_analyzed=total_hits,
            blocked_by_heuristics=blocked_by_heuristics,
            observed_domains=observed_domains,
            dga_detections=dga_count,
            homoglyph_detections=homoglyph_count,
            first_seen_new=first_seen_new,
            device_anomalies=device_anomalies,
            thresholds={
                "observe": settings.observe_threshold,
                "block": settings.block_threshold,
            },
        )

    except Exception as e:
        logger.error(f"Failed to get heuristics stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/shadow", response_model=dict)
async def get_shadow_domains(
    status: Optional[str] = Query(None, description="Filter by status"),
    min_score: Optional[float] = Query(None, ge=0, le=100),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin)
) -> dict:
    """
    Get domains currently in shadow/observe mode.
    
    These are domains with scores between observe (30) and block (70)
    thresholds that need manual review.
    """
    manager = get_shadow_mode_manager()
    
    if not manager:
        return {
            "domains": [],
            "total": 0,
            "stats": ShadowModeStats().model_dump()
        }
    
    try:
        # Get domains from shadow mode
        domains = manager.get_observed_domains(
            status=status,
            min_score=min_score,
            limit=limit,
            offset=offset
        )
        
        total = manager.count_observed(status=status, min_score=min_score)
        stats = manager.get_stats()
        
        return {
            "domains": [
                ShadowDomainEntry(
                    domain=d.domain,
                    score=d.score,
                    first_seen=d.first_seen,
                    last_seen=d.last_seen,
                    hit_count=d.hit_count,
                    signals=d.signals or {},
                    status=d.status,
                    reviewed_by=d.reviewed_by,
                    reviewed_at=d.reviewed_at,
                ).model_dump()
                for d in domains
            ],
            "total": total,
            "stats": ShadowModeStats(
                total_observing=stats.get("observing", 0),
                total_promoted=stats.get("promoted", 0),
                total_dismissed=stats.get("dismissed", 0),
                total_expired=stats.get("expired", 0),
                pending_review=stats.get("pending_review", 0),
                auto_promoted=stats.get("auto_promoted", 0),
            ).model_dump()
        }
    except Exception as e:
        logger.error(f"Failed to get shadow domains: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/shadow/{domain}/action")
async def shadow_domain_action(
    domain: str,
    request: ShadowActionRequest,
    current_user: User = Depends(require_admin)
) -> dict:
    """
    Take action on a shadow mode domain.
    
    Actions:
    - promote: Move to blocklist
    - dismiss: Mark as safe, add to allowlist
    - extend: Extend observation period
    """
    manager = get_shadow_mode_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    if not manager:
        _record_heuristics_event(
            action_id="heuristics.shadow.action",
            title="Review shadow domain",
            subtitle=f"Heuristics - {domain}",
            status="failed",
            message="Shadow mode manager not available",
            started_at=started_at,
        )
        raise HTTPException(status_code=503, detail="Shadow mode manager not available")
    
    try:
        if request.action == "promote":
            result = manager.promote_to_blocklist(
                domain,
                reason=request.reason or "Manual review",
                reviewed_by=current_user.username
            )
        elif request.action == "dismiss":
            result = manager.dismiss_domain(
                domain,
                reason=request.reason or "Deemed safe",
                reviewed_by=current_user.username
            )
        elif request.action == "extend":
            result = manager.extend_observation(
                domain,
                days=30,
                reason=request.reason or "Extended review"
            )
        else:
            _record_heuristics_event(
                action_id="heuristics.shadow.action",
                title="Review shadow domain",
                subtitle=f"Heuristics - {domain}",
                status="failed",
                message=f"Unknown action: {request.action}",
                started_at=started_at,
            )
            raise HTTPException(status_code=400, detail=f"Unknown action: {request.action}")
        _record_heuristics_event(
            action_id="heuristics.shadow.action",
            title="Review shadow domain",
            subtitle=f"Heuristics - {domain}",
            status="success" if result else "failed",
            message=f"Domain {domain} {request.action}d successfully" if result else f"Domain action failed: {request.action}",
            started_at=started_at,
        )
        return {
            "success": result,
            "domain": domain,
            "action": request.action,
            "message": f"Domain {domain} {request.action}d successfully"
        }
    except Exception as e:
        logger.error(f"Shadow action failed for {domain}: {e}")
        _record_heuristics_event(
            action_id="heuristics.shadow.action",
            title="Review shadow domain",
            subtitle=f"Heuristics - {domain}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analyze/{domain}", response_model=DomainAnalysis)
async def analyze_domain(
    domain: str,
    current_user: User = Depends(require_admin)
) -> DomainAnalysis:
    """
    Get full heuristic analysis for a specific domain.
    
    Returns all signals, scores, and verdicts.
    """
    import re
    import sqlite3
    
    # Security: Validate domain format (RFC 1035)
    domain = domain.lower().strip()
    
    # Domain validation
    if not domain or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid domain: length must be 1-253 characters")
    
    # Check for valid domain pattern
    domain_pattern = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    )
    if not domain_pattern.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    
    # Prevent path traversal and injection
    if any(c in domain for c in ['/', '\\', '..', '\x00', ';', "'", '"']):
        raise HTTPException(status_code=400, detail="Invalid characters in domain")
    
    try:
        signals = []
        total_score = 0
        in_shadow = False
        
        # Check Shadow Mode DB for existing data
        db_path = ROOT_DIR / "data" / "netprotection" / "shadow_mode.db"
        if db_path.exists():
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM shadow_domains WHERE domain = ?", (domain,))
            row = cursor.fetchone()
            if row:
                total_score = row['max_score']
                in_shadow = True
            conn.close()
        
        # Analyze domain characteristics
        domain_name = domain.split('.')[0]
        
        # 1. Homoglyph detection (digits that look like letters)
        digit_map = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b'}
        homoglyph_chars = sum(1 for c in domain_name if c in digit_map)
        if homoglyph_chars > 0:
            homo_score = min(homoglyph_chars * 20, 60)
            total_score = max(total_score, homo_score)
            signals.append(SignalDetail(
                signal_type="homoglyph",
                score=homo_score,
                confidence=0.9,
                reason=f"Contains {homoglyph_chars} lookalike character(s) - possible brand impersonation",
                timestamp=utc_now(),
                decayed_score=homo_score,
            ))
        
        # 2. Entropy/DGA detection (low vowels = random)
        vowels = sum(1 for c in domain_name.lower() if c in 'aeiou')
        vowel_ratio = vowels / len(domain_name) if len(domain_name) > 0 else 0
        if vowel_ratio < 0.15 and len(domain_name) > 5:
            dga_score = 50
            total_score = max(total_score, dga_score)
            signals.append(SignalDetail(
                signal_type="dga",
                score=dga_score,
                confidence=0.7,
                reason=f"Low vowel ratio ({vowel_ratio:.1%}) - may be algorithmically generated",
                timestamp=utc_now(),
                decayed_score=dga_score,
            ))
        
        # 3. Length check
        if len(domain_name) > 20:
            len_score = 20
            total_score = max(total_score, len_score)
            signals.append(SignalDetail(
                signal_type="length",
                score=len_score,
                confidence=0.5,
                reason=f"Unusually long domain name ({len(domain_name)} chars)",
                timestamp=utc_now(),
                decayed_score=len_score,
            ))
        
        # 4. Check known brand patterns
        brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'paypal', 'twitter', 'instagram']
        for brand in brands:
            # Check if domain looks like brand but isn't exact
            if brand != domain_name and (
                brand in domain_name or 
                any(domain_name.replace(d, digit_map.get(d, d)) == brand for d in domain_name if d.isdigit())
            ):
                brand_score = 60
                total_score = max(total_score, brand_score)
                signals.append(SignalDetail(
                    signal_type="brand_impersonation",
                    score=brand_score,
                    confidence=0.85,
                    reason=f"Looks like impersonation of '{brand}'",
                    timestamp=utc_now(),
                    decayed_score=brand_score,
                ))
                break
        
        # Determine verdict
        if total_score >= 60:
            verdict = "block"
        elif total_score >= 30:
            verdict = "observe"
        else:
            verdict = "allow"
        
        return DomainAnalysis(
            domain=domain,
            total_score=total_score,
            verdict=verdict,
            signals=signals,
            first_seen=None,
            is_new_domain=not in_shadow,
            in_shadow_mode=in_shadow,
            dga_analysis={"score": total_score, "is_suspicious": total_score >= 30} if signals else None,
            homoglyph_analysis={"is_suspicious": homoglyph_chars > 0, "confidence": 0.9} if homoglyph_chars > 0 else None,
        )
    except Exception as e:
        logger.error(f"Analysis failed for {domain}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts", response_model=dict)
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    alert_type: Optional[str] = Query(None, description="Filter by type"),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_admin)
) -> dict:
    """
    What the heuristic/AI engine actually blocked on its own.

    Reads real engine decisions from flow_log.db — domains the engine blocked
    that are NOT a plain ad-blocklist hit (DGA, homoglyph, suspicious structure,
    behavioral ad/tracker, CNAME cloaking, DNS rebinding, ...). Each entry can be
    allowed (whitelist) or blocked permanently (blacklist) from the UI; both
    apply live in the running resolver.

    state: "blocked" (engine block, pending review) | "allowed" (user whitelisted)
           | "force_blocked" (user blacklisted).
    """
    import re
    import sqlite3
    try:
        np_dir = ROOT_DIR / "data" / "netprotection"
        flow_db = np_dir / "flow_log.db"
        if not flow_db.exists():
            return {"alerts": [], "total": 0, "unacknowledged": 0}

        def _read_list(path) -> set:
            out = set()
            try:
                if path.exists():
                    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        d = line.strip().lower()
                        if d and not d.startswith("#"):
                            out.add(d)
            except Exception:
                pass
            return out

        # Current user decisions (these apply live in the resolver via .lists_reload).
        allowlist = _read_list(np_dir / "allowlist.txt")
        user_blocklist = _read_list(np_dir / "user_blocklist.txt")

        conn = sqlite3.connect(f"file:{flow_db}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # Show only a domain whose current verdict is still an engine block.
        # Policy decisions (parental anti-bypass, unknown-device quarantine,
        # schedules and profile rules) belong to their own UI sections and must
        # never be presented as autonomous AI decisions.
        cursor.execute(
            """
            WITH latest AS (
                SELECT LOWER(domain) AS domain_key, MAX(id) AS latest_id
                FROM flow_log
                GROUP BY LOWER(domain)
            ),
            engine_hits AS (
                SELECT LOWER(domain) AS domain_key,
                       COUNT(*) AS hits,
                       MAX(timestamp) AS last_ts
                FROM flow_log
                WHERE status = 'blocked'
                  AND evidence_summary IS NOT NULL
                  AND (
                       LOWER(evidence_summary) LIKE '%heuristics score:%'
                    OR LOWER(evidence_summary) LIKE '%dga detected:%'
                    OR LOWER(evidence_summary) LIKE '%brand impersonation:%'
                    OR LOWER(evidence_summary) LIKE '%ad-genesis:%'
                    OR LOWER(evidence_summary) LIKE '%dns rebinding:%'
                    OR LOWER(evidence_summary) LIKE '%cname cloaking:%'
                    OR LOWER(evidence_summary) LIKE '%domain is known malicious%'
                  )
                GROUP BY LOWER(domain)
            )
            SELECT f.domain AS domain,
                   f.evidence_summary AS evidence,
                   f.confidence AS confidence,
                   f.categories AS categories,
                   engine_hits.hits AS hits,
                   f.timestamp AS last_ts
            FROM latest
            JOIN flow_log f ON f.id = latest.latest_id
            JOIN engine_hits ON engine_hits.domain_key = latest.domain_key
            WHERE f.status = 'blocked'
              AND f.evidence_summary IS NOT NULL
              AND (
                   LOWER(f.evidence_summary) LIKE '%heuristics score:%'
                OR LOWER(f.evidence_summary) LIKE '%dga detected:%'
                OR LOWER(f.evidence_summary) LIKE '%brand impersonation:%'
                OR LOWER(f.evidence_summary) LIKE '%ad-genesis:%'
                OR LOWER(f.evidence_summary) LIKE '%dns rebinding:%'
                OR LOWER(f.evidence_summary) LIKE '%cname cloaking:%'
                OR LOWER(f.evidence_summary) LIKE '%domain is known malicious%'
              )
            ORDER BY f.id DESC
            LIMIT ?
            """,
            (limit,),
        )

        alerts = []
        seen = set()
        for row in cursor.fetchall():
            domain = (row["domain"] or "").lower().strip()
            if not domain or domain in seen:
                continue
            seen.add(domain)

            evidence = row["evidence"] or "Heuristic detection"
            ev_lower = evidence.lower()

            # Real heuristic score: prefer the number embedded in the evidence text.
            score = 0.0
            match = re.search(r"score:\s*([\d.]+)", ev_lower)
            if match:
                try:
                    score = float(match.group(1))
                except ValueError:
                    score = 0.0
            if score <= 0 and row["confidence"]:
                score = float(row["confidence"])

            if "rebinding" in ev_lower:
                a_type = "dns_rebinding"
            elif "cname cloaking" in ev_lower:
                a_type = "cname_cloak"
            elif "homoglyph" in ev_lower:
                a_type = "homoglyph_attack"
            elif "dga" in ev_lower or "gibberish" in ev_lower:
                a_type = "dga_attack"
            elif "malicious" in ev_lower or "malware" in ev_lower:
                a_type = "malware"
            elif "tracker" in ev_lower or "tracking" in ev_lower or "advertis" in ev_lower or "ad-related" in ev_lower:
                a_type = "ad_tracker"
            elif "new domain" in ev_lower:
                a_type = "new_domain"
            else:
                a_type = "heuristic_block"

            if score >= 70:
                sev = "critical"
            elif score >= 50:
                sev = "high"
            elif score >= 35:
                sev = "medium"
            else:
                sev = "low"

            if domain in allowlist:
                state = "allowed"
            elif domain in user_blocklist:
                state = "force_blocked"
            else:
                state = "blocked"

            if severity and severity != sev:
                continue
            if alert_type and alert_type != a_type:
                continue

            try:
                ts_iso = datetime.fromisoformat(str(row["last_ts"])).isoformat()
            except Exception:
                ts_iso = str(row["last_ts"])

            categories = []
            if row["categories"]:
                categories = [c for c in str(row["categories"]).split(",") if c]

            alerts.append({
                "id": domain,
                "domain": domain,
                "timestamp": ts_iso,
                "alert_type": a_type,
                "severity": sev,
                "score": round(score, 1),
                "hit_count": row["hits"] or 0,
                "reason": evidence,
                "categories": categories,
                "state": state,
                "acknowledged": state != "blocked",
            })

        conn.close()

        pending = len([a for a in alerts if a["state"] == "blocked"])
        return {"alerts": alerts, "total": len(alerts), "unacknowledged": pending}

    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        return {"alerts": [], "total": 0, "unacknowledged": 0, "error": str(e)}


@router.get("/observing", response_model=dict)
async def get_observing(
    limit: int = Query(200, ge=1, le=500),
    current_user: User = Depends(require_admin)
) -> dict:
    """
    Domains the engine is watching — flagged (score in the observe band, between
    the observe and block thresholds) but NOT blocked. Reasons are enriched from
    signals.db so the user can see why each is suspicious. Allow (whitelist) or
    Block (blacklist) apply live in the running resolver.
    """
    import sqlite3
    try:
        np_dir = ROOT_DIR / "data" / "netprotection"
        shadow_db = np_dir / "shadow_mode.db"
        if not shadow_db.exists():
            return {"domains": [], "total": 0}

        def _read_list(path) -> set:
            out = set()
            try:
                if path.exists():
                    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        d = line.strip().lower()
                        if d and not d.startswith("#"):
                            out.add(d)
            except Exception:
                pass
            return out

        allowlist = _read_list(np_dir / "allowlist.txt")
        user_blocklist = _read_list(np_dir / "user_blocklist.txt")

        conn = sqlite3.connect(f"file:{shadow_db}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT domain, max_score, hit_count, last_observed
            FROM shadow_domains
            WHERE action NOT IN ('promoted', 'auto_promoted')
            ORDER BY max_score DESC, last_observed DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()

        # Exclude anything already resolved: currently blocked by the engine, or
        # explicitly allowed/blocked by the user. A domain that is already blocked
        # belongs in "Blocked", not here — "Observing" means watched, no decision
        # yet. (shadow_mode.db is a historical log and is not pruned when a domain
        # later crosses the block threshold or is caught by another stage, so
        # without this filter the same domain would appear in both lists.)
        blocked_now: set = set()
        flow_db = np_dir / "flow_log.db"
        if flow_db.exists():
            try:
                fconn = sqlite3.connect(f"file:{flow_db}?mode=ro", uri=True, timeout=5)
                fcur = fconn.cursor()
                fcur.execute("SELECT DISTINCT lower(domain) FROM flow_log WHERE status = 'blocked'")
                blocked_now = {r[0] for r in fcur.fetchall() if r[0]}
                fconn.close()
            except Exception as exc:
                logger.debug("observing: blocked-set lookup failed: %s", exc)
        resolved = blocked_now | allowlist | user_blocklist

        kept = [
            r for r in rows
            if (r["domain"] or "").lower().strip()
            and (r["domain"] or "").lower().strip() not in resolved
        ]
        domains = [(r["domain"] or "").lower().strip() for r in kept]

        # Enrich reasons from signals.db (latest distinct reasons per domain).
        reasons_map: dict[str, list] = {}
        signals_db = np_dir / "signals.db"
        if signals_db.exists() and domains:
            sconn = sqlite3.connect(f"file:{signals_db}?mode=ro", uri=True, timeout=5)
            sconn.row_factory = sqlite3.Row
            scur = sconn.cursor()
            placeholders = ",".join("?" for _ in domains)
            scur.execute(
                f"""
                SELECT domain, reason, timestamp
                FROM signals
                WHERE lower(domain) IN ({placeholders})
                  AND reason IS NOT NULL AND reason != ''
                ORDER BY timestamp DESC
                """,
                domains,
            )
            for s in scur.fetchall():
                key = (s["domain"] or "").lower()
                bucket = reasons_map.setdefault(key, [])
                if s["reason"] not in bucket and len(bucket) < 3:
                    bucket.append(s["reason"])
            sconn.close()

        result = []
        for r in kept:
            domain = (r["domain"] or "").lower().strip()
            score = float(r["max_score"] or 0.0)
            try:
                ts_iso = datetime.fromtimestamp(float(r["last_observed"])).isoformat()
            except Exception:
                ts_iso = ""
            result.append({
                "domain": domain,
                "score": round(score, 1),
                "hit_count": r["hit_count"] or 0,
                "timestamp": ts_iso,
                "reasons": reasons_map.get(domain, []),
                "state": "observing",
            })

        return {"domains": result, "total": len(result)}

    except Exception as e:
        logger.error(f"Failed to get observing domains: {e}")
        return {"domains": [], "total": 0, "error": str(e)}


@router.get("/config")
async def get_heuristics_config(
    current_user: User = Depends(require_admin)
) -> dict:
    """Get current heuristics configuration."""
    try:
        import sys
        sys.path.insert(0, str(ROOT_DIR.parent))
        from easypi_netprotection.config import get_settings
        
        settings = get_settings()
        h = settings.heuristics
        
        return {
            "enabled": h.enabled,
            "observe_threshold": h.observe_threshold,
            "block_threshold": h.block_threshold,
            "detectors": {
                "dga": h.enable_dga_detection,
                "homoglyph": h.enable_homoglyph_detection,
                "first_seen": h.enable_first_seen_tracking,
                "domain_analysis": h.enable_domain_analysis,
                "device_anomaly": h.enable_device_anomaly,
                "asn_cluster": h.enable_asn_cluster,
                "shadow_mode": h.enable_shadow_mode,
            },
            "tuning": {
                "dga_threshold": h.dga_score_threshold,
                "homoglyph_threshold": h.homoglyph_score_threshold,
                "first_seen_days": h.first_seen_new_days,
                "shadow_expire_days": h.shadow_auto_expire_days,
                "shadow_promote_hits": h.shadow_auto_promote_hits,
            },
            "performance": {
                "quick_mode_ms": h.quick_mode_threshold_ms,
                "persist_signals": h.persist_signals,
                "max_signals_per_domain": h.max_signals_per_domain,
            }
        }
    except Exception as e:
        logger.error(f"Failed to get config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/config")
async def update_heuristics_config(
    config: HeuristicsConfigUpdate,
    current_user: User = Depends(require_admin)
) -> dict:
    """Update heuristics configuration."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        settings = _get_netprotection_settings()
        heuristics = settings.heuristics
        payload = config.model_dump(exclude_none=True)

        if "enabled" in payload:
            heuristics.enabled = payload["enabled"]
        if "observe_threshold" in payload:
            heuristics.observe_threshold = payload["observe_threshold"]
        if "block_threshold" in payload:
            heuristics.block_threshold = payload["block_threshold"]

        detectors = payload.get("detectors") or {}
        detector_map = {
            "dga": "enable_dga_detection",
            "homoglyph": "enable_homoglyph_detection",
            "first_seen": "enable_first_seen_tracking",
            "domain_analysis": "enable_domain_analysis",
            "device_anomaly": "enable_device_anomaly",
            "asn_cluster": "enable_asn_cluster",
            "shadow_mode": "enable_shadow_mode",
        }
        for key, attr in detector_map.items():
            if key in detectors:
                setattr(heuristics, attr, detectors[key])

        tuning = payload.get("tuning") or {}
        tuning_map = {
            "dga_threshold": "dga_score_threshold",
            "homoglyph_threshold": "homoglyph_score_threshold",
            "first_seen_days": "first_seen_new_days",
            "shadow_expire_days": "shadow_auto_expire_days",
            "shadow_promote_hits": "shadow_auto_promote_hits",
        }
        for key, attr in tuning_map.items():
            if key in tuning:
                setattr(heuristics, attr, tuning[key])

        performance = payload.get("performance") or {}
        performance_map = {
            "quick_mode_ms": "quick_mode_threshold_ms",
            "persist_signals": "persist_signals",
            "max_signals_per_domain": "max_signals_per_domain",
        }
        for key, attr in performance_map.items():
            if key in performance:
                setattr(heuristics, attr, performance[key])

        if heuristics.observe_threshold >= heuristics.block_threshold:
            raise HTTPException(status_code=400, detail="Observe threshold must be lower than block threshold")

        _persist_netprotection_settings(settings)
        refreshed_settings = _get_netprotection_settings()
        _refresh_live_heuristics_runtime(refreshed_settings)

        _record_heuristics_event(
            action_id="heuristics.config.update",
            title="Update heuristics config",
            subtitle="Heuristics - Configuration",
            status="success",
            message="Heuristics configuration updated",
            started_at=started_at,
        )
        return {
            "success": True,
            "message": "Heuristics configuration updated",
            "config": {
                "enabled": refreshed_settings.heuristics.enabled,
                "observe_threshold": refreshed_settings.heuristics.observe_threshold,
                "block_threshold": refreshed_settings.heuristics.block_threshold,
                "detectors": {
                    "dga": refreshed_settings.heuristics.enable_dga_detection,
                    "homoglyph": refreshed_settings.heuristics.enable_homoglyph_detection,
                    "first_seen": refreshed_settings.heuristics.enable_first_seen_tracking,
                    "domain_analysis": refreshed_settings.heuristics.enable_domain_analysis,
                    "device_anomaly": refreshed_settings.heuristics.enable_device_anomaly,
                    "asn_cluster": refreshed_settings.heuristics.enable_asn_cluster,
                    "shadow_mode": refreshed_settings.heuristics.enable_shadow_mode,
                },
                "tuning": {
                    "dga_threshold": refreshed_settings.heuristics.dga_score_threshold,
                    "homoglyph_threshold": refreshed_settings.heuristics.homoglyph_score_threshold,
                    "first_seen_days": refreshed_settings.heuristics.first_seen_new_days,
                    "shadow_expire_days": refreshed_settings.heuristics.shadow_auto_expire_days,
                    "shadow_promote_hits": refreshed_settings.heuristics.shadow_auto_promote_hits,
                },
                "performance": {
                    "quick_mode_ms": refreshed_settings.heuristics.quick_mode_threshold_ms,
                    "persist_signals": refreshed_settings.heuristics.persist_signals,
                    "max_signals_per_domain": refreshed_settings.heuristics.max_signals_per_domain,
                },
            },
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to update heuristics config: %s", exc)
        _record_heuristics_event(
            action_id="heuristics.config.update",
            title="Update heuristics config",
            subtitle="Heuristics - Configuration",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(exc))


# ============== Newly-Registered Domain (NRD) blocking ==============

class NrdConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    max_age_days: Optional[int] = None


@router.get("/nrd")
async def get_nrd_status(_admin: User = Depends(require_admin)) -> dict:
    """Current NRD (newly-registered domain) block config + feed state."""
    settings = _get_netprotection_settings()
    h = settings.heuristics
    feed = _netprotection_data_dir() / "nrd_domains.txt"
    domains = 0
    updated = None
    try:
        if feed.exists():
            with open(feed, encoding="utf-8", errors="ignore") as fh:
                domains = sum(1 for _ in fh)
            updated = utc_fromtimestamp(feed.stat().st_mtime).isoformat()
    except Exception:
        pass
    return {
        "enabled": bool(getattr(h, "enable_nrd_block", False)),
        "max_age_days": int(getattr(h, "nrd_max_age_days", 14)),
        "feed_domains": domains,
        "feed_updated_at": updated,
    }


@router.post("/nrd")
async def set_nrd_status(body: NrdConfigUpdate, _admin: User = Depends(require_admin)) -> dict:
    """Enable/disable NRD blocking + set the age window. Restarts NetProtection so
    the DNS engine (a separate process) reloads the new config."""
    settings = _get_netprotection_settings()
    h = settings.heuristics
    changed = False
    if body.enabled is not None:
        h.enable_nrd_block = bool(body.enabled)
        changed = True
    if body.max_age_days is not None:
        if int(body.max_age_days) not in (7, 14, 30):
            raise HTTPException(status_code=400, detail="max_age_days must be 7, 14 or 30")
        h.nrd_max_age_days = int(body.max_age_days)
        changed = True
    if changed:
        _persist_netprotection_settings(settings)
        try:
            from app.services.netprotection_service import netprotection_service
            await netprotection_service.restart_service()
        except Exception as exc:
            logger.warning("NRD: NetProtection restart failed: %s", exc)
    return {"success": True, "enabled": h.enable_nrd_block, "max_age_days": h.nrd_max_age_days}


@router.post("/nrd/refresh")
async def refresh_nrd_feed(_admin: User = Depends(require_admin)) -> dict:
    """Download/refresh the NRD feed for the current age window (via runner)."""
    import asyncio
    import subprocess
    settings = _get_netprotection_settings()
    window = int(getattr(settings.heuristics, "nrd_max_age_days", 14))
    runner = ROOT_DIR / "scripts" / "runner"
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            ["sudo", "-n", str(runner), "settings/update_nrd_list.sh", str(window)],
            capture_output=True, text=True, timeout=300,
        )
        ok = proc.returncode == 0
        msg = (proc.stdout or proc.stderr or "").strip()
        return {"success": ok, "window": window, "message": msg[-300:]}
    except Exception as exc:
        return {"success": False, "window": window, "message": str(exc)}


@router.get("/nrd/blocked")
async def get_nrd_blocked(limit: int = 50, _admin: User = Depends(require_admin)) -> dict:
    """Recent DISTINCT domains blocked specifically by NRD (feed or hybrid)."""
    from app.services.netprotection_service import netprotection_service
    try:
        fetch = max(100, min(int(limit) * 6, 600))
        res = await netprotection_service.get_verdicts(limit=fetch, verdict_type="deny")
    except Exception as exc:
        logger.error("nrd/blocked failed: %s", exc)
        return {"count": 0, "domains": []}
    out = []
    seen = set()
    for v in (res.get("data") or []):
        if v.get("block_source_key") != "nrd":
            continue
        dom = str(v.get("domain") or "").strip()
        if not dom or dom in seen:
            continue
        seen.add(dom)
        out.append({
            "domain": dom,
            "time": v.get("time"),
            "client": v.get("client_name") or v.get("client_ip") or v.get("client_id"),
            "evidence": v.get("evidence_summary"),
        })
        if len(out) >= int(limit):
            break
    return {"count": len(out), "domains": out}


# ============== ML self-learning (domain language model) ==============

def _ml_model_path() -> Path:
    """Path of the live domain language-model file inside the NetProtection data dir."""
    return _netprotection_data_dir() / "ml_domain_model.json"


@router.get("/ml/status")
async def get_ml_status(_admin: User = Depends(require_admin)) -> dict:
    """Live status of the domain language and flow-behaviour learning levels.

    Read-only: reads the model file and scores a held-out sample in-process. The
    model retrains itself automatically (10 min after start, then every 12 h); this
    just reports where it stands and how well it currently separates real domains
    from machine-generated gibberish.
    """
    import asyncio
    import json as _json

    path = _ml_model_path()
    meta: dict = {"available": False}
    try:
        if path.exists():
            data = _json.loads(path.read_text(encoding="utf-8"))
            trained = data.get("trained_at")
            meta = {
                "available": True,
                "trained_at": utc_fromtimestamp(trained).isoformat() if trained else None,
                "n_benign": int(data.get("n_benign", 0)),
                "vocab_size": len(data.get("logp") or {}),
                "gibberish_caught": int(data.get("gibberish_caught", 0)),
                "gibberish_total": int(data.get("gibberish_total", 0)),
                "threshold_logp": round(float(data.get("threshold_logp", 0.0)), 3),
                "benign_mean": round(float(data.get("benign_mean", 0.0)), 3),
                "model_bytes": path.stat().st_size,
            }
    except Exception as exc:
        logger.warning("ml/status read failed: %s", exc)

    quality: dict = {"available": False}
    behavior_model: dict = {"available": False}
    try:
        import sys
        sys.path.insert(0, str(ROOT_DIR.parent))
        from easypi_netprotection.heuristics import ml_trainer
        quality = await asyncio.to_thread(ml_trainer.evaluate, str(path.parent))
    except Exception as exc:
        logger.warning("ml/status evaluate failed: %s", exc)

    try:
        from easypi_netprotection.heuristics.flow_behavior_model import model_status
        behavior_model = await asyncio.to_thread(model_status, str(path.parent))
        updated = behavior_model.get("updated_at")
        behavior_model["updated_at"] = utc_fromtimestamp(updated).isoformat() if updated else None
    except Exception as exc:
        logger.warning("ml/status flow model read failed: %s", exc)

    return {
        "model": meta,
        "quality": quality,
        "behavior_model": behavior_model,
        "auto_retrain": {"enabled": True, "interval_hours": 12},
    }


@router.post("/ml/retrain")
async def retrain_ml(_admin: User = Depends(require_admin)) -> dict:
    """Retrain the domain language model on THIS network's own data, right now.

    Runs via the secure runner (writes into the netprotection-owned data dir). The
    engine hot-reloads the new model on the next request — no restart needed. The
    trainer's false-positive gate means a retrain can only ever improve or keep the
    model, never start blocking real sites.
    """
    import asyncio
    import json as _json
    import subprocess

    runner = ROOT_DIR / "scripts" / "runner"
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            ["sudo", "-n", str(runner), "settings/retrain_ml_model.sh"],
            capture_output=True, text=True, timeout=300,
        )
    except Exception as exc:
        return {"success": False, "message": str(exc)}

    out = (proc.stdout or "").strip()
    result: dict = {}
    # The script prints the trainer's JSON result; take the last JSON-looking line.
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                result = _json.loads(line)
                break
            except Exception:
                continue
    if not result:
        return {"success": False, "message": (proc.stderr or out or "retrain failed")[-300:]}
    return {
        "success": bool(result.get("success")),
        "n_benign": result.get("n_benign"),
        "gibberish_caught": result.get("gibberish_caught"),
        "message": result.get("error") or "retrained on your network's data",
    }


# ============== Ad/Tracker Detection Endpoints ==============

AD_TRACKER_SIGNAL_TYPES = ("ad_tracker", "tracking_pixel", "cookie_sync", "third_party_flood")
TRACKER_REASON_HINTS = ("tracking", "tracker", "telemetry", "beacon", "pixel", "cookie", "analytics")


def _load_behavioral_adtracker_domains(start_ts: float) -> dict[str, dict[str, Any]]:
    """Collect recent behavioral ad/tracker signals keyed by domain."""
    import sqlite3

    signals_db = ROOT_DIR / "data" / "netprotection" / "signals.db"
    summaries: dict[str, dict[str, Any]] = {}
    if not signals_db.exists():
        return summaries

    conn = sqlite3.connect(str(signals_db))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    placeholders = ",".join("?" for _ in AD_TRACKER_SIGNAL_TYPES)
    cursor.execute(
        f"""
        SELECT domain, signal_type, confidence, reason, timestamp
        FROM signals
        WHERE signal_type IN ({placeholders})
        AND timestamp >= ?
        ORDER BY timestamp DESC
        """,
        (*AD_TRACKER_SIGNAL_TYPES, start_ts),
    )

    for row in cursor.fetchall():
        domain = row["domain"].lower()
        summary = summaries.setdefault(
            domain,
            {
                "domain": row["domain"],
                "last_timestamp": row["timestamp"],
                "signal_types": set(),
                "reasons": [],
                "max_confidence": 0.0,
            },
        )
        summary["last_timestamp"] = max(summary["last_timestamp"], row["timestamp"])
        summary["signal_types"].add(row["signal_type"])
        if row["reason"] and row["reason"] not in summary["reasons"]:
            summary["reasons"].append(row["reason"])
        summary["max_confidence"] = max(summary["max_confidence"], float(row["confidence"] or 0.0))

    conn.close()
    return summaries


def _estimate_false_positive_rate(start_ts: float) -> float:
    """Estimate false-positive rate from shadow-mode review outcomes."""
    import sqlite3

    shadow_db = ROOT_DIR / "data" / "netprotection" / "shadow_mode.db"
    if not shadow_db.exists():
        return 0.0

    conn = sqlite3.connect(str(shadow_db))
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            SUM(CASE WHEN action = 'dismissed' THEN 1 ELSE 0 END) AS dismissed,
            SUM(CASE WHEN action IN ('promoted', 'auto_blocked') THEN 1 ELSE 0 END) AS confirmed
        FROM shadow_history
        WHERE timestamp >= ?
        """,
        (start_ts,),
    )
    row = cursor.fetchone() or (0, 0)
    conn.close()
    dismissed = row[0] or 0
    confirmed = row[1] or 0
    total = dismissed + confirmed
    return round(dismissed / total, 4) if total else 0.0

@router.get("/ad-tracker/stats")
async def get_ad_tracker_stats(
    range: str = Query("today", pattern="^(today|week)$"),
    current_user: User = Depends(require_admin)
) -> dict:
    """
    Get Ad/Tracker detection statistics.
    
    Returns combined stats from blocklist + behavioral detection.
    """
    from datetime import timedelta

    try:
        now = utc_now()
        if range == "today":
            start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:  # week
            start_time = now - timedelta(days=7)

        start_ts = start_time.timestamp()
        start_datetime = start_time.isoformat()
        behavioral = _load_behavioral_adtracker_domains(start_ts)

        # Detection methods reflect what the DNS-only engine actually emits.
        # (tracking_pixel / cookie_sync / third_party_flood require HTTP-level
        # request context that a DNS resolver never sees, so they are not shown.)
        ad_keyword_domains = set()
        entropy_domains = set()
        tracking_subdomain_domains = set()
        known_ad_network_domains = set()
        known_tracker_domains = set()
        ads_detected_domains = set()
        trackers_detected_domains = set()

        for domain, summary in behavioral.items():
            signal_types = summary["signal_types"]
            reasons = " ".join(summary["reasons"]).lower()
            if "ad_tracker" in signal_types:
                ads_detected_domains.add(domain)
            if "keyword" in reasons or "ad-related" in reasons:
                ad_keyword_domains.add(domain)
            if "entropy" in reasons:
                entropy_domains.add(domain)
            if "tracking-like subdomain" in reasons:
                tracking_subdomain_domains.add(domain)
            if "known third-party ad network" in reasons:
                known_ad_network_domains.add(domain)
                ads_detected_domains.add(domain)
            if "known tracking/telemetry" in reasons:
                known_tracker_domains.add(domain)
                trackers_detected_domains.add(domain)
            if any(hint in reasons or hint in domain for hint in TRACKER_REASON_HINTS):
                trackers_detected_domains.add(domain)

        top_blocked = []
        blocked_total = 0
        flow_log_db = ROOT_DIR / "data" / "netprotection" / "flow_log.db"
        if flow_log_db.exists() and behavioral:
            import sqlite3

            conn = sqlite3.connect(str(flow_log_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            domain_list = list(behavioral.keys())
            placeholders = ",".join("?" for _ in domain_list)
            cursor.execute(
                f"""
                SELECT domain, COUNT(*) as count
                FROM flow_log
                WHERE verdict = 'deny'
                AND datetime(timestamp) > datetime(?)
                AND lower(domain) IN ({placeholders})
                GROUP BY domain
                ORDER BY count DESC
                """,
                (start_datetime, *domain_list),
            )
            for row in cursor.fetchall():
                blocked_total += row["count"] or 0
                summary = behavioral.get(row["domain"].lower()) or {}
                top_blocked.append(
                    {
                        "domain": row["domain"],
                        "count": row["count"],
                        "reasons": (summary.get("reasons") or ["Behavioral ad/tracker detection"])[:3],
                        "confidence": min(1.0, float(summary.get("max_confidence") or 0.5)),
                    }
                )
            conn.close()

        if not top_blocked:
            top_blocked = [
                {
                    "domain": summary["domain"],
                    "count": len(summary["signal_types"]),
                    "reasons": (summary["reasons"] or ["Behavioral ad/tracker detection"])[:3],
                    "confidence": min(1.0, float(summary["max_confidence"] or 0.5)),
                }
                for summary in sorted(
                    behavioral.values(),
                    key=lambda item: (item["max_confidence"], item["last_timestamp"]),
                    reverse=True,
                )[:10]
            ]

        blocked_total = blocked_total or len(top_blocked)
        bandwidth_saved_mb = round(blocked_total * 0.05, 2)

        return {
            "success": True,
            "data": {
                "total_analyzed": len(behavioral),
                "ads_detected": len(ads_detected_domains),
                "trackers_detected": len(trackers_detected_domains),
                "blocked_today": blocked_total if range == "today" else 0,
                "blocked_this_week": blocked_total if range == "week" else 0,
                "top_blocked": top_blocked,
                "detection_methods": {
                    "ad_keywords": len(ad_keyword_domains),
                    "high_entropy": len(entropy_domains),
                    "tracking_subdomain": len(tracking_subdomain_domains),
                    "known_ad_network": len(known_ad_network_domains),
                    "known_tracker": len(known_tracker_domains),
                },
                "bandwidth_saved_mb": bandwidth_saved_mb,
                "false_positive_rate": _estimate_false_positive_rate(start_ts),
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get ad tracker stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ad-tracker/recent")
async def get_recent_ad_tracker_detections(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_admin)
) -> dict:
    """Recent ad/tracker behavioral detections, with the score the engine assigned.

    Domains come from persisted ad/tracker signals (signals.db); the score and
    verdict are the engine's actual decision pulled from flow_log — the same
    source as the Blocked list — so the numbers are consistent across the UI.
    (The old code recomputed the score from the live aggregator, which under the
    backend process pointed at an empty DB and always returned 0.)
    """
    import re
    import sqlite3
    try:
        behavioral = _load_behavioral_adtracker_domains(time.time() - (30 * 86400))
        ordered = sorted(
            behavioral.values(),
            key=lambda item: item["last_timestamp"],
            reverse=True,
        )[:limit]
        if not ordered:
            return {"success": True, "data": []}

        # Pull each domain's latest engine decision (score + verdict) from flow_log.
        flow_info: dict[str, dict] = {}
        flow_log_db = ROOT_DIR / "data" / "netprotection" / "flow_log.db"
        if flow_log_db.exists():
            domain_list = [item["domain"].lower() for item in ordered]
            placeholders = ",".join("?" for _ in domain_list)
            conn = sqlite3.connect(f"file:{flow_log_db}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT f.domain AS domain, f.evidence_summary AS evidence,
                       f.confidence AS confidence, f.status AS status, f.verdict AS verdict
                FROM flow_log f
                JOIN (
                    SELECT lower(domain) AS d, MAX(timestamp) AS last_ts
                    FROM flow_log
                    WHERE lower(domain) IN ({placeholders})
                    GROUP BY lower(domain)
                ) agg ON lower(f.domain) = agg.d AND f.timestamp = agg.last_ts
                """,
                tuple(domain_list),
            )
            for row in cursor.fetchall():
                d = (row["domain"] or "").lower()
                if d in flow_info:
                    continue
                evidence = row["evidence"] or ""
                score = 0.0
                m = re.search(r"score:\s*([\d.]+)", evidence.lower())
                if m:
                    try:
                        score = float(m.group(1))
                    except ValueError:
                        score = 0.0
                if score <= 0 and row["confidence"]:
                    score = float(row["confidence"])
                flow_info[d] = {
                    "score": score,
                    "status": row["status"] or "",
                    "verdict": row["verdict"] or "",
                }
            conn.close()

        recent = []
        for item in ordered:
            fi = flow_info.get(item["domain"].lower(), {})
            score = fi.get("score", 0.0)
            if score <= 0:
                # No engine score logged yet — fall back to the signal confidence.
                score = min(1.0, float(item["max_confidence"] or 0.0)) * 100
            status = fi.get("status", "")
            verdict_raw = fi.get("verdict", "")
            if status == "blocked" or verdict_raw == "deny":
                verdict = "blocked"
            elif verdict_raw == "observe":
                verdict = "observed"
            else:
                verdict = "allowed"
            indicators = {}
            for signal_type in item["signal_types"]:
                indicators[signal_type] = indicators.get(signal_type, 0) + 1
            recent.append(
                {
                    "domain": item["domain"],
                    "timestamp": utc_fromtimestamp(item["last_timestamp"]).isoformat(),
                    "score": round(score, 1),
                    "verdict": verdict,
                    "reasons": item["reasons"][:3] or ["Behavioral ad/tracker detection"],
                    "confidence": min(1.0, float(item["max_confidence"] or 0.5)),
                    "indicators": indicators,
                }
            )

        return {"success": True, "data": recent}

    except Exception as e:
        logger.error(f"Failed to get recent detections: {e}")
        raise HTTPException(status_code=500, detail=str(e))
