from __future__ import annotations

import os
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from typing import List

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.encryption import decrypt_password
from app.core.rate_limit import check_rate_limit, reset_rate_limit
from app.core.security import verify_password
from app.core.totp import verify_totp
from app.db.session import get_db
from app.schemas.backup import (
    BackupCreate,
    BackupResponse,
    BackupRestoreStatusResponse,
    RecoveryKeyExportRequest,
)
from app.services.backup_service import BACKUP_ARCHIVE_NAME_RE, BackupService
from app.services.operation_event_service import OperationEventService

router = APIRouter(tags=["backup"])
backup_service = BackupService()
operation_event_service = OperationEventService()
MAX_RECOVERY_KEY_PACKAGE_BYTES = 4096
MAX_BACKUP_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024


def _record_backup_event(
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
            route="/backup",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        pass


@router.get("/list", response_model=List[BackupResponse])
def list_backups(db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    """Get all backups"""
    return backup_service.get_all_backups(db)


@router.get("/restore-status", response_model=BackupRestoreStatusResponse)
def get_restore_status(admin: dict = Depends(require_admin)):
    """Return the last detached restore state without exposing its status file."""

    return backup_service.get_restore_status()


@router.post("/create")
async def create_backup(
    payload: BackupCreate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Create a new backup"""
    return await backup_service.create_backup(
        backup_type=payload.type, name=payload.name, db=db
    )


@router.post("/restore/{backup_id}")
async def restore_backup(
    backup_id: int, db: Session = Depends(get_db), admin: dict = Depends(require_admin)
):
    """Restore from backup"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await backup_service.restore_backup(backup_id, db)
        _record_backup_event(
            action_id="backup.restore",
            title="Restore backup",
            subtitle=f"System Backup - #{backup_id}",
            status="success",
            message=result.get("message", "Backup restore started"),
            started_at=started_at,
        )
        return result
    except HTTPException as exc:
        _record_backup_event(
            action_id="backup.restore",
            title="Restore backup",
            subtitle=f"System Backup - #{backup_id}",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.get("/download/{backup_id}")
def download_backup(
    backup_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Download backup file"""
    started_at = datetime.now(timezone.utc).isoformat()
    from app.models.backup import BackupJob, BackupStatus

    backup_job = db.query(BackupJob).filter(BackupJob.id == backup_id).first()

    if not backup_job:
        _record_backup_event(
            action_id="backup.download",
            title="Download backup",
            subtitle=f"System Backup - #{backup_id}",
            status="failed",
            message="Backup not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Backup not found")

    if backup_job.status != BackupStatus.COMPLETED:
        _record_backup_event(
            action_id="backup.download",
            title="Download backup",
            subtitle=f"System Backup - {backup_job.name}",
            status="failed",
            message="Backup is not completed",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Backup is not completed")

    if not backup_job.file_path:
        _record_backup_event(
            action_id="backup.download",
            title="Download backup",
            subtitle=f"System Backup - {backup_job.name}",
            status="failed",
            message="Backup file path not set",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Backup file path not set")

    try:
        trusted_backup_path = backup_service.resolve_backup_archive_path(
            backup_job.file_path
        )
    except FileNotFoundError:
        _record_backup_event(
            action_id="backup.download",
            title="Download backup",
            subtitle=f"System Backup - {backup_job.name}",
            status="failed",
            message="Backup file not found on disk",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Backup file not found on disk")
    except ValueError as exc:
        _record_backup_event(
            action_id="backup.download",
            title="Download backup",
            subtitle=f"System Backup - {backup_job.name}",
            status="failed",
            message="Backup file path failed security validation",
            started_at=started_at,
        )
        raise HTTPException(status_code=403, detail="Invalid backup file path") from exc

    # Copy file to temp directory with read permissions for current user
    temp_file: str | None = None
    try:
        filename = trusted_backup_path.name
        suffix = f"_{filename}" if filename else ".tar.gz"
        with tempfile.NamedTemporaryFile(
            prefix=f"backup_{backup_id}_", suffix=suffix, delete=False
        ) as target:
            temp_file = target.name
            source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                source_flags |= os.O_NOFOLLOW
            source_fd = os.open(trusted_backup_path, source_flags)
            with os.fdopen(source_fd, "rb") as source:
                source_info = os.fstat(source.fileno())
                if not stat.S_ISREG(source_info.st_mode) or (
                    os.name == "posix"
                    and (source_info.st_uid != 0 or source_info.st_mode & 0o022)
                ):
                    raise HTTPException(
                        status_code=403,
                        detail="Backup file changed during security validation",
                    )
                shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        # FileResponse runs in this same backend process; no world-readable
        # permission is needed for a backup containing configuration and DB data.
        os.chmod(temp_file, 0o600)

        # Schedule cleanup after file is sent
        background_tasks.add_task(cleanup_temp_file, temp_file)
        _record_backup_event(
            action_id="backup.download",
            title="Download backup",
            subtitle=f"System Backup - {backup_job.name}",
            status="success",
            message=f"Prepared backup download: {filename}",
            started_at=started_at,
        )

        # Return file
        return FileResponse(
            path=temp_file,
            filename=filename,
            media_type=(
                "application/octet-stream"
                if filename.endswith(".epibak")
                else "application/gzip"
            ),
        )
    except Exception as exc:
        if temp_file:
            cleanup_temp_file(temp_file)
        _record_backup_event(
            action_id="backup.download",
            title="Download backup",
            subtitle=f"System Backup - {backup_job.name}",
            status="failed",
            message="Failed to prepare backup download",
            started_at=started_at,
        )
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail="Failed to prepare backup file") from exc


def cleanup_temp_file(file_path: str):
    """Clean up temporary file"""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass


def _verify_recovery_key_reauthentication(
    request: Request,
    admin,
    *,
    current_password: str,
    totp_code: str | None,
) -> None:
    check_rate_limit(request, "backup_recovery_key")
    password_valid = verify_password(current_password, admin.password_hash)
    totp_valid = True
    if admin.totp_enabled:
        secret = decrypt_password(admin.totp_secret or "")
        totp_valid = bool(totp_code and secret and verify_totp(secret, totp_code))
    if not password_valid or not totp_valid:
        raise HTTPException(status_code=403, detail="Reauthentication failed")
    reset_rate_limit(request, "backup_recovery_key")


@router.post("/import")
async def import_backup_archive(
    request: Request,
    archive: UploadFile = File(...),
    current_password: str = Form(..., min_length=1, max_length=256),
    totp_code: str | None = Form(default=None, min_length=6, max_length=16),
    db: Session = Depends(get_db),
    admin=Depends(require_admin),
):
    """Validate and register an encrypted EasyPi backup from another host."""

    from app.models.backup import BackupJob, BackupStatus, BackupType

    started_at = datetime.now(timezone.utc).isoformat()
    import_path = None
    archive_name = str(archive.filename or "")
    imported_path = None
    try:
        _verify_recovery_key_reauthentication(
            request,
            admin,
            current_password=current_password,
            totp_code=totp_code,
        )
        if (
            os.path.basename(archive_name) != archive_name
            or not archive_name.endswith(".epibak")
            or not BACKUP_ARCHIVE_NAME_RE.fullmatch(archive_name)
        ):
            raise HTTPException(status_code=400, detail="Invalid backup archive name")

        import_path = backup_service.new_backup_import_path()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        size = 0
        prefix = b""
        fd = os.open(import_path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                while chunk := await archive.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_BACKUP_ARCHIVE_BYTES:
                        raise HTTPException(status_code=413, detail="Backup archive is too large")
                    if len(prefix) < 9:
                        prefix = (prefix + chunk)[:9]
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            await archive.close()
        if size < 37 or prefix != b"EASYPIBK1":
            raise HTTPException(status_code=400, detail="Invalid encrypted backup archive")

        imported_path = await backup_service.import_backup_archive(
            import_path.name,
            archive_name,
        )
        backup_type = (
            BackupType.CONFIG
            if archive_name.startswith("config-")
            else BackupType.FULL
        )
        existing = db.query(BackupJob).filter(BackupJob.file_path == str(imported_path)).first()
        if existing is None:
            existing = BackupJob(
                name=f"Imported {archive_name}",
                type=backup_type,
                status=BackupStatus.COMPLETED,
                file_path=str(imported_path),
                size_bytes=imported_path.stat().st_size,
            )
            db.add(existing)
            db.commit()
            db.refresh(existing)
        _record_backup_event(
            action_id="backup.import",
            title="Import encrypted backup",
            subtitle="System Backup - Recovery",
            status="success",
            message=f"Imported backup archive {archive_name}",
            started_at=started_at,
        )
        return {
            "status": "imported",
            "message": "Backup archive imported and validated",
            "id": existing.id,
        }
    except Exception as exc:
        _record_backup_event(
            action_id="backup.import",
            title="Import encrypted backup",
            subtitle="System Backup - Recovery",
            status="failed",
            message="Backup archive import failed",
            started_at=started_at,
        )
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail="Backup archive import failed") from exc
    finally:
        if import_path is not None:
            cleanup_temp_file(str(import_path))


@router.post("/recovery-key/export")
async def export_recovery_key(
    payload: RecoveryKeyExportRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    admin=Depends(require_admin),
):
    """Export the host backup key in a passphrase-protected recovery package."""

    started_at = datetime.now(timezone.utc).isoformat()
    recovery_file = None
    try:
        _verify_recovery_key_reauthentication(
            request,
            admin,
            current_password=payload.current_password.get_secret_value(),
            totp_code=payload.totp_code,
        )
        recovery_file = await backup_service.export_recovery_key(
            payload.package_passphrase.get_secret_value()
        )
        background_tasks.add_task(
            backup_service.cleanup_recovery_export,
            recovery_file.name,
        )
        _record_backup_event(
            action_id="backup.recovery-key.export",
            title="Export backup recovery key",
            subtitle="System Backup - Recovery",
            status="success",
            message="Prepared a passphrase-protected recovery-key package",
            started_at=started_at,
        )
        return FileResponse(
            path=recovery_file,
            filename="easypi-recovery-key-v1.epikey",
            media_type="application/octet-stream",
            headers={"Cache-Control": "no-store"},
        )
    except Exception as exc:
        if recovery_file is not None:
            await backup_service.cleanup_recovery_export(recovery_file.name)
        _record_backup_event(
            action_id="backup.recovery-key.export",
            title="Export backup recovery key",
            subtitle="System Backup - Recovery",
            status="failed",
            message="Recovery-key export failed",
            started_at=started_at,
        )
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail="Recovery-key export failed") from exc


@router.post("/recovery-key/import")
async def import_recovery_key(
    request: Request,
    package: UploadFile = File(...),
    current_password: str = Form(..., min_length=1, max_length=256),
    package_passphrase: str = Form(..., min_length=12, max_length=1024),
    totp_code: str | None = Form(default=None, min_length=6, max_length=16),
    admin=Depends(require_admin),
):
    """Import a protected key without replacing this host's active backup key."""

    started_at = datetime.now(timezone.utc).isoformat()
    import_path = None
    try:
        _verify_recovery_key_reauthentication(
            request,
            admin,
            current_password=current_password,
            totp_code=totp_code,
        )
        try:
            payload = await package.read(MAX_RECOVERY_KEY_PACKAGE_BYTES + 1)
        finally:
            await package.close()
        if (
            len(payload) > MAX_RECOVERY_KEY_PACKAGE_BYTES
            or not payload.startswith(b"EASYPIKEY1")
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid recovery-key package",
            )

        import_path = backup_service.new_recovery_import_path()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(import_path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        fingerprint, imported = await backup_service.import_recovery_key(
            import_path.name,
            package_passphrase,
        )
        _record_backup_event(
            action_id="backup.recovery-key.import",
            title="Import backup recovery key",
            subtitle="System Backup - Recovery",
            status="success",
            message=(
                "Imported an additional backup decryption key"
                if imported
                else "Backup decryption key was already available"
            ),
            started_at=started_at,
        )
        return {
            "status": "imported" if imported else "already_present",
            "message": (
                "Recovery key imported. Existing backups from that host can now be restored."
                if imported
                else "This recovery key is already available."
            ),
            "fingerprint": fingerprint,
        }
    except Exception as exc:
        _record_backup_event(
            action_id="backup.recovery-key.import",
            title="Import backup recovery key",
            subtitle="System Backup - Recovery",
            status="failed",
            message="Recovery-key import failed",
            started_at=started_at,
        )
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail="Recovery-key import failed") from exc
    finally:
        if import_path is not None:
            cleanup_temp_file(str(import_path))


@router.delete("/{backup_id}")
def delete_backup(
    backup_id: int, db: Session = Depends(get_db), admin: dict = Depends(require_admin)
):
    """Delete backup"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = backup_service.delete_backup(backup_id, db)
        _record_backup_event(
            action_id="backup.delete",
            title="Delete backup",
            subtitle=f"System Backup - #{backup_id}",
            status="success",
            message=result.get("message", "Backup deleted"),
            started_at=started_at,
        )
        return result
    except HTTPException as exc:
        _record_backup_event(
            action_id="backup.delete",
            title="Delete backup",
            subtitle=f"System Backup - #{backup_id}",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.get("/status/{backup_id}")
def get_backup_status(
    backup_id: int, db: Session = Depends(get_db), admin: dict = Depends(require_admin)
):
    """Get backup status"""
    return backup_service.get_backup_status(backup_id, db)


@router.post("/cancel/{backup_id}")
async def cancel_backup(
    backup_id: int, db: Session = Depends(get_db), admin: dict = Depends(require_admin)
):
    """Cancel a running backup"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await backup_service.cancel_backup(backup_id, db)
        _record_backup_event(
            action_id="backup.cancel",
            title="Cancel backup",
            subtitle=f"System Backup - #{backup_id}",
            status="success",
            message=result.get("message", "Backup cancelled"),
            started_at=started_at,
        )
        return result
    except HTTPException as exc:
        _record_backup_event(
            action_id="backup.cancel",
            title="Cancel backup",
            subtitle=f"System Backup - #{backup_id}",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


__all__ = ["router"]
