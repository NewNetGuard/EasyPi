from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, status, Depends

from app.api.deps import require_admin
from app.core.service_manager import ServiceManager
from app.schemas.service import ServiceInstallRequest, ServiceResponse, ServiceStatus
from app.services.operation_event_service import OperationEventService

router = APIRouter(prefix="/services", tags=["services"])
manager = ServiceManager()
operation_event_service = OperationEventService()


def _record_service_event(
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
            route="/dashboard",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        pass


@router.get("/", response_model=list[ServiceResponse])
def list_services(_admin: dict = Depends(require_admin)) -> list[ServiceResponse]:
    return manager.get_available_services()


@router.get("/statuses")
def services_statuses(
    names: list[str] | None = Query(default=None),
    _admin: dict = Depends(require_admin),
) -> dict[str, ServiceStatus | None]:
    """Return statuses for multiple services in parallel.

    Query param `names` can be repeated: /services/statuses?names=a&names=b
    If not provided, statuses for all services are returned.
    """
    try:
        statuses = manager.get_all_statuses(names)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    return statuses


@router.get("/{name}", response_model=ServiceResponse)
def service_detail(name: str, _admin: dict = Depends(require_admin)) -> ServiceResponse:
    try:
        return manager.get_service(name)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None


@router.get("/{name}/status", response_model=ServiceStatus)
def service_status(name: str, _admin: dict = Depends(require_admin)) -> ServiceStatus:
    try:
        return manager.get_service_status(name)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None


@router.post("/{name}/install")
def install_service(name: str, payload: ServiceInstallRequest | None = None, _admin: dict = Depends(require_admin)) -> dict[str, str]:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        log = manager.install_service(name, (payload or ServiceInstallRequest()).options)
    except FileNotFoundError:
        _record_service_event(
            action_id="services.install",
            title="Install service",
            subtitle=f"Services - {name}",
            status="failed",
            message="Service not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None
    except RuntimeError as exc:
        _record_service_event(
            action_id="services.install",
            title="Install service",
            subtitle=f"Services - {name}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _record_service_event(
        action_id="services.install",
        title="Install service",
        subtitle=f"Services - {name}",
        status="success",
        message=f"Installed service: {name}",
        started_at=started_at,
    )
    return {"status": "ok", "log": log}


@router.delete("/{name}/uninstall")
def uninstall_service(name: str, _admin: dict = Depends(require_admin)) -> dict[str, str]:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        log = manager.uninstall_service(name)
    except FileNotFoundError:
        _record_service_event(
            action_id="services.uninstall",
            title="Uninstall service",
            subtitle=f"Services - {name}",
            status="failed",
            message="Service not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None
    except RuntimeError as exc:
        _record_service_event(
            action_id="services.uninstall",
            title="Uninstall service",
            subtitle=f"Services - {name}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _record_service_event(
        action_id="services.uninstall",
        title="Uninstall service",
        subtitle=f"Services - {name}",
        status="success",
        message=f"Uninstalled service: {name}",
        started_at=started_at,
    )
    return {"status": "ok", "log": log}


@router.post("/{name}/restart")
def restart_service(name: str, _admin: dict = Depends(require_admin)) -> dict[str, str]:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        manager.restart_service(name)
    except FileNotFoundError:
        _record_service_event(
            action_id="services.restart",
            title="Restart service",
            subtitle=f"Services - {name}",
            status="failed",
            message="Service not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None
    except RuntimeError as exc:
        _record_service_event(
            action_id="services.restart",
            title="Restart service",
            subtitle=f"Services - {name}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _record_service_event(
        action_id="services.restart",
        title="Restart service",
        subtitle=f"Services - {name}",
        status="success",
        message=f"Restarted service: {name}",
        started_at=started_at,
    )
    return {"status": "ok"}


@router.post("/{name}/start")
def start_service(name: str, _admin: dict = Depends(require_admin)) -> dict[str, str]:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        manager.start_service(name)
    except FileNotFoundError:
        _record_service_event(
            action_id="services.start",
            title="Start service",
            subtitle=f"Services - {name}",
            status="failed",
            message="Service not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None
    except RuntimeError as exc:
        _record_service_event(
            action_id="services.start",
            title="Start service",
            subtitle=f"Services - {name}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _record_service_event(
        action_id="services.start",
        title="Start service",
        subtitle=f"Services - {name}",
        status="success",
        message=f"Started service: {name}",
        started_at=started_at,
    )
    return {"status": "ok"}


@router.post("/{name}/stop")
def stop_service(name: str, _admin: dict = Depends(require_admin)) -> dict[str, str]:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        manager.stop_service(name)
    except FileNotFoundError:
        _record_service_event(
            action_id="services.stop",
            title="Stop service",
            subtitle=f"Services - {name}",
            status="failed",
            message="Service not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None
    except RuntimeError as exc:
        _record_service_event(
            action_id="services.stop",
            title="Stop service",
            subtitle=f"Services - {name}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    _record_service_event(
        action_id="services.stop",
        title="Stop service",
        subtitle=f"Services - {name}",
        status="success",
        message=f"Stopped service: {name}",
        started_at=started_at,
    )
    return {"status": "ok"}


@router.get("/{name}/logs")
def service_logs(name: str, tail: int = Query(default=200, ge=10, le=1000), _admin: dict = Depends(require_admin)) -> dict[str, str]:
    try:
        logs = manager.get_service_logs(name, tail)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Service not found") from None
    return {"logs": logs}


__all__ = ["router"]
