from fastapi import APIRouter

from .endpoints.auth import router as auth_router
from .endpoints.action_preview import router as action_preview_router
from .endpoints.backup import router as backup_router
from .endpoints.cameras import router as cameras_router
from .endpoints.devices import router as devices_router
from .endpoints.files import router as files_router
from .endpoints.monitoring import router as monitoring_router
from .endpoints.security import router as security_router
from .endpoints.services import router as services_router
from .endpoints.tasks import router as tasks_router
from .endpoints.wireguard import router as wireguard_router
from .endpoints.ai import router as ai_router
from .endpoints.network_activity import router as network_activity_router
from .endpoints.remote_access import router as remote_access_router
from .endpoints.rollback import router as rollback_router
from .endpoints.dns import router as dns_router
from .endpoints.users import router as users_router
from .endpoints.notifications import router as notifications_router
from .endpoints.rewrites import router as rewrites_router
from .endpoints.profiles import router as profiles_router
from .endpoints.heuristics import router as heuristics_router
from .endpoints.inbox import router as inbox_router
from .endpoints.jobs import router as jobs_router
from .endpoints.picloud import router as picloud_router
from .endpoints.mobile import router as mobile_router


router = APIRouter(prefix="/api/v1")

router.include_router(auth_router, tags=["auth"])
router.include_router(action_preview_router, tags=["action-preview"])
router.include_router(backup_router, prefix="/backup", tags=["backup"])
router.include_router(cameras_router, tags=["cameras"])
router.include_router(devices_router, tags=["devices"])
router.include_router(files_router, tags=["files"])
router.include_router(monitoring_router, tags=["monitoring"])
router.include_router(security_router, prefix="/security", tags=["security"])
router.include_router(services_router, tags=["services"])
router.include_router(tasks_router, tags=["tasks"])
router.include_router(wireguard_router, prefix="/wireguard", tags=["wireguard"])
router.include_router(ai_router, prefix="/ai", tags=["ai"])
router.include_router(network_activity_router, prefix="/network-activity", tags=["network"])
router.include_router(remote_access_router, prefix="/remote-access", tags=["tailscale"])
router.include_router(rollback_router, tags=["rollback"])
router.include_router(dns_router, prefix="/dns", tags=["piguard"])
router.include_router(rewrites_router, prefix="/dns", tags=["dns-rewrites"])
router.include_router(profiles_router, prefix="/dns", tags=["device-profiles"])
router.include_router(heuristics_router, prefix="/dns/heuristics", tags=["heuristics"])
router.include_router(inbox_router, tags=["inbox"])
router.include_router(jobs_router, tags=["jobs"])
router.include_router(users_router, tags=["users"])
router.include_router(notifications_router, tags=["notifications"])
router.include_router(picloud_router, prefix="/picloud", tags=["picloud"])
router.include_router(mobile_router, prefix="/mobile", tags=["mobile"])


@router.get("/healthz_v1")
async def healthz_v1() -> dict[str, str]:
    return {"status": "ok", "version": "v1"}
