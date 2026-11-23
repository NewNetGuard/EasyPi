import mimetypes
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.api.cloud_file_responses import (
    THUMBNAIL_SECURITY_HEADERS,
    cloud_download_response as _download_response,
    cloud_thumbnail_response as _thumbnail_response,
    opened_cloud_download_response as _opened_download_response,
)
from app.core.rate_limit import check_rate_limit
from app.schemas.picloud import (
    FileListResponse,
    PiCloudFile,
    ShareLink,
    StorageStats,
    UploadResponse,
    UsageByType,
    Metadata,
    TrashItem,
    Folder,
    FolderTreeItem,
    TelegramBotConfig,
    TelegramBotStatus,
    TelegramUpload,
    ActivityItem,
    BulkOperationRequest,
    BulkOperationResult,
    DuplicateFile,
    ColorLabel,
    FileCategory,
)
from app.services.picloud_service import pi_cloud_service
from app.api.deps import get_db, require_admin
from app.services.operation_event_service import OperationEventService

router = APIRouter(tags=["picloud"])
logger = logging.getLogger(__name__)
operation_event_service = OperationEventService()

class ShareCreateRequest(BaseModel):
    file_id: str = Field(min_length=1, max_length=1024)
    hours: int | None = Field(default=None, ge=1, le=8760)
    password: str | None = Field(default=None, min_length=8, max_length=72)


class ShareAccessRequest(BaseModel):
    password: str = Field(min_length=8, max_length=72)


def _record_cloud_event(
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
            route="/cloud",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record cloud event %s: %s", action_id, exc)


@router.get("/files", response_model=FileListResponse)
def list_files(
    path: str = Query(default="/"),
    category: FileCategory | None = None,
    favorite_only: bool = False,
    sort_by: str = "name",
    sort_order: str = "asc",
    offset: int = 0,
    limit: int = 100,
    search: str | None = None,
    _admin = Depends(require_admin),
):
    return pi_cloud_service.list_files(
        path, category=category, favorite_only=favorite_only, 
        sort_by=sort_by, sort_order=sort_order, offset=offset, limit=limit,
        search=search
    )


@router.post("/upload", response_model=UploadResponse)
async def upload_files(
    path: str = Form(default="/"), 
    auto_sort: bool = Form(default=True),
    files: List[UploadFile] = File(...), 
    _admin = Depends(require_admin)
):
    """Upload files with optional auto-sorting.
    
    If auto_sort=True and path="/", files are automatically sorted:
    - Photos → /Photos
    - Videos → /Videos  
    - Documents → /Documents
    - Music → /Music
    - Encrypted → /Encrypted
    - APKs, archives, and unknown formats stay in the selected Files folder
    """
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await pi_cloud_service.upload_files(files, path, auto_sort=auto_sort)
        uploaded = len(getattr(result, "files", []) or [])
        _record_cloud_event(
            action_id="cloud.files.upload",
            title="Upload files",
            subtitle="Cloud - Files",
            status="success",
            message=f"Uploaded {uploaded} file(s) to {path}",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.files.upload",
            title="Upload files",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.delete("/file/{file_id:path}")
def delete_file(file_id: str, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.delete_file(file_id)
        _record_cloud_event(
            action_id="cloud.files.delete",
            title="Delete file",
            subtitle="Cloud - Files",
            status="success",
            message=f"Deleted {file_id}",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.files.delete",
            title="Delete file",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise

@router.delete("/file")
def delete_file_by_query(
    file_id: str = Query(...),
    permanent: bool = Query(False),
    _admin = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        if permanent:
            pi_cloud_service.delete_file_permanently(file_id)
        else:
            pi_cloud_service.delete_file(file_id)
        _record_cloud_event(
            action_id="cloud.files.permanent-delete" if permanent else "cloud.files.delete",
            title="Permanently delete file" if permanent else "Delete file",
            subtitle="Cloud - Files",
            status="success",
            message="Permanently deleted verified encryption source" if permanent else f"Deleted {file_id}",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.files.permanent-delete" if permanent else "cloud.files.delete",
            title="Permanently delete file" if permanent else "Delete file",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.put("/file/{file_id:path}", response_model=PiCloudFile)
def rename_or_move(
    file_id: str,
    new_path: str = Query(..., min_length=1, max_length=1024),
    _admin = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.rename_or_move(file_id, new_path)
        _record_cloud_event(
            action_id="cloud.files.rename-move",
            title="Move or rename file",
            subtitle="Cloud - Files",
            status="success",
            message=f"Moved {file_id} to {new_path}",
            started_at=started_at,
        )
        return result
    except FileNotFoundError:
        _record_cloud_event(
            action_id="cloud.files.rename-move",
            title="Move or rename file",
            subtitle="Cloud - Files",
            status="failed",
            message="Source file not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Source file not found")
    except FileExistsError:
        _record_cloud_event(
            action_id="cloud.files.rename-move",
            title="Move or rename file",
            subtitle="Cloud - Files",
            status="failed",
            message="Destination already exists",
            started_at=started_at,
        )
        raise HTTPException(status_code=409, detail="Destination already exists")
    except ValueError:
        _record_cloud_event(
            action_id="cloud.files.rename-move",
            title="Move or rename file",
            subtitle="Cloud - Files",
            status="failed",
            message="Invalid path",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid path")


@router.post("/copy/{file_id:path}", response_model=PiCloudFile)
def copy_file(
    file_id: str,
    new_path: str = Query(..., min_length=1, max_length=1024),
    _admin = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.copy_file(file_id, new_path)
        _record_cloud_event(
            action_id="cloud.files.copy",
            title="Copy file",
            subtitle="Cloud - Files",
            status="success",
            message=f"Copied {file_id} to {new_path}",
            started_at=started_at,
        )
        return result
    except FileNotFoundError:
        detail = "Source file not found"
        status_code = 404
    except FileExistsError:
        detail = "Destination already exists"
        status_code = 409
    except ValueError:
        detail = "Invalid path"
        status_code = 400

    _record_cloud_event(
        action_id="cloud.files.copy",
        title="Copy file",
        subtitle="Cloud - Files",
        status="failed",
        message=detail,
        started_at=started_at,
    )
    raise HTTPException(status_code=status_code, detail=detail)

@router.get("/search", response_model=list[PiCloudFile])
def search_files(
    q: str,
    category: FileCategory | None = None,
    tags: List[str] = Query(default=[]),
    favorite_only: bool = False,
    sort_by: str = "name",
    sort_order: str = "asc",
    offset: int = 0,
    limit: int = 100,
    _admin = Depends(require_admin),
):
    return pi_cloud_service.search(
        q, category=category, tags=tags, favorite_only=favorite_only,
        sort_by=sort_by, sort_order=sort_order, offset=offset, limit=limit
    )


@router.post("/folder", response_model=PiCloudFile)
def create_folder(path: str, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.create_folder(path)
        _record_cloud_event(
            action_id="cloud.folder.create",
            title="Create folder",
            subtitle="Cloud - Files",
            status="success",
            message=f"Created folder {path}",
            started_at=started_at,
        )
        return result
    except ValueError:
        _record_cloud_event(
            action_id="cloud.folder.create",
            title="Create folder",
            subtitle="Cloud - Files",
            status="failed",
            message="Invalid path",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid path")


@router.get("/storage/stats", response_model=StorageStats)
def storage_stats(_admin = Depends(require_admin)):
    return pi_cloud_service.storage_stats()


@router.get("/storage/usage", response_model=UsageByType)
def usage_by_type(_admin = Depends(require_admin)):
    return pi_cloud_service.usage_by_type()


@router.get("/recent", response_model=list[PiCloudFile])
def recent_files(limit: int = 20, _admin = Depends(require_admin)):
    return pi_cloud_service.recent_files(limit)


@router.get("/favorites", response_model=list[PiCloudFile])
def favorites(_admin = Depends(require_admin)):
    return pi_cloud_service.favorites()


@router.post("/favorite/{file_id:path}")
def toggle_favorite(file_id: str, value: bool = Query(True), _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.toggle_favorite(file_id, value)
        _record_cloud_event(
            action_id="cloud.favorite.toggle",
            title="Update favorite",
            subtitle="Cloud - Files",
            status="success",
            message=f"{'Favorited' if value else 'Unfavorited'} {file_id}",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.favorite.toggle",
            title="Update favorite",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.post("/share/{file_id:path}", response_model=ShareLink)
def create_share(file_id: str, hours: int | None = None, password: str | None = None, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.create_share(file_id, hours, password)
        _record_cloud_event(
            action_id="cloud.share.create",
            title="Create share link",
            subtitle="Cloud - Shares",
            status="success",
            message=f"Created a share link for {file_id}",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.share.create",
            title="Create share link",
            subtitle="Cloud - Shares",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise

@router.post("/share", response_model=ShareLink)
def create_share_by_query(
    body: ShareCreateRequest,
    _admin = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.create_share(body.file_id, body.hours, body.password)
        _record_cloud_event(
            action_id="cloud.share.create",
            title="Create share link",
            subtitle="Cloud - Shares",
            status="success",
            message=f"Created a share link for {body.file_id}",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.share.create",
            title="Create share link",
            subtitle="Cloud - Shares",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.get("/share/{token}")
def resolve_share(token: str):
    opened = pi_cloud_service.open_share(token, None)
    if not opened:
        raise HTTPException(status_code=404, detail="Share link expired or invalid")
    return _opened_download_response(*opened)


@router.post("/share-access/{token}")
def access_protected_share(
    token: str,
    body: ShareAccessRequest,
    request: Request,
):
    check_rate_limit(request, "share_access")
    opened = pi_cloud_service.open_share(token, body.password)
    if not opened:
        raise HTTPException(status_code=404, detail="Share link expired or invalid")
    return _opened_download_response(*opened)


@router.get("/file/{file_id:path}/download")
def download_file(file_id: str, _admin = Depends(require_admin)):
    try:
        path = pi_cloud_service.resolve_file(file_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return _download_response(path)


def _authorize_video(request: Request, db=Depends(get_db, scope="function")):
    # Release the database connection before sending the requested byte range.
    require_admin(request, None, db)


@router.get("/video/{file_id:path}", dependencies=[Depends(_authorize_video)])
def play_video(file_id: str):
    try:
        path = pi_cloud_service.resolve_file(file_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found") from None
    mime, _ = mimetypes.guess_type(path.name)
    if not path.is_file() or not mime or not mime.startswith("video/"):
        raise HTTPException(status_code=404, detail="Video not found")
    return FileResponse(
        path, media_type=mime,
        headers={**THUMBNAIL_SECURITY_HEADERS, "X-Accel-Buffering": "no"},
    )


@router.get("/thumbnail/{file_id:path}")
def thumbnail(file_id: str, _admin = Depends(require_admin)):
    try:
        path = pi_cloud_service.resolve_file(file_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    mime, _ = mimetypes.guess_type(path.name)
    if pi_cloud_service._get_file_category(mime, path.name) == "other":
        raise HTTPException(status_code=404, detail="Preview is not available for Files")
    thumb = pi_cloud_service._find_thumbnail_path(file_id, path.name)
    if thumb:
        return _thumbnail_response(thumb)
    # Try to generate thumbnail on-the-fly if it doesn't exist
    pi_cloud_service._generate_thumbnail(path, file_id)
    thumb = pi_cloud_service._find_thumbnail_path(file_id, path.name)
    if thumb:
        return _thumbnail_response(thumb)
    raise HTTPException(status_code=404, detail="Thumbnail not found")


@router.post("/regenerate-thumbnails")
def regenerate_thumbnails(_admin = Depends(require_admin)):
    """Regenerate all missing thumbnails for images and videos."""
    result = pi_cloud_service.regenerate_all_thumbnails()
    return result


@router.get("/metadata/{file_id:path}", response_model=Metadata)
def metadata(file_id: str, _admin = Depends(require_admin)):
    try:
        return pi_cloud_service.metadata(file_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")

@router.get("/trash", response_model=list[TrashItem])
def list_trash(_admin = Depends(require_admin)):
    return pi_cloud_service.list_trash()


@router.delete("/trash/empty")
def empty_trash(_admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.empty_trash()
        _record_cloud_event(
            action_id="cloud.trash.empty",
            title="Empty trash",
            subtitle="Cloud - Trash",
            status="success",
            message="Trash emptied",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.trash.empty",
            title="Empty trash",
            subtitle="Cloud - Trash",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.post("/trash/{trash_id}/restore")
def restore_trash(trash_id: str, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.restore_trash(trash_id)
        _record_cloud_event(
            action_id="cloud.trash.restore",
            title="Restore from trash",
            subtitle="Cloud - Trash",
            status="success",
            message=f"Restored {trash_id} from trash",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.trash.restore",
            title="Restore from trash",
            subtitle="Cloud - Trash",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.delete("/trash/{trash_id}")
def delete_from_trash(trash_id: str, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.delete_from_trash(trash_id)
        _record_cloud_event(
            action_id="cloud.trash.delete",
            title="Delete from trash",
            subtitle="Cloud - Trash",
            status="success",
            message=f"Deleted {trash_id} from trash",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.trash.delete",
            title="Delete from trash",
            subtitle="Cloud - Trash",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


# Новые endpoints
@router.get("/tags/{file_id:path}", response_model=list[str])
def get_file_tags(file_id: str, _admin = Depends(require_admin)):
    try:
        return pi_cloud_service.get_tags(file_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Cloud file not found") from exc


@router.post("/tags/{file_id:path}", response_model=list[str])
def set_file_tags(
    file_id: str,
    tags: list[str] = Body(...),
    _admin = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        normalized_tags = pi_cloud_service.set_tags(file_id, tags)
        _record_cloud_event(
            action_id="cloud.tags.set",
            title="Update file tags",
            subtitle="Cloud - Files",
            status="success",
            message=f"Updated tags for {file_id}",
            started_at=started_at,
        )
        return normalized_tags
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Cloud file not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/color-label/{file_id:path}")
def set_color_label(file_id: str, color: ColorLabel, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.set_color_label(file_id, color)
        _record_cloud_event(
            action_id="cloud.color-label.set",
            title="Set color label",
            subtitle="Cloud - Files",
            status="success",
            message=f"Set color label for {file_id}",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.color-label.set",
            title="Set color label",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.get("/folders", response_model=list[Folder])
def list_folders(path: str = Query(default="/"), _admin = Depends(require_admin)):
    return pi_cloud_service.list_folders(path)


@router.get("/folder-tree", response_model=list[FolderTreeItem])
def get_folder_tree(_admin = Depends(require_admin)):
    return pi_cloud_service.get_folder_tree()


@router.get("/activity", response_model=list[ActivityItem])
def get_activity(limit: int = 50, _admin = Depends(require_admin)):
    return pi_cloud_service.get_activity(limit)


@router.get("/duplicates", response_model=list[DuplicateFile])
def find_duplicates(_admin = Depends(require_admin)):
    return pi_cloud_service.find_duplicates()


@router.post("/bulk/delete", response_model=BulkOperationResult)
def bulk_delete(request: BulkOperationRequest, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.bulk_delete(request.file_ids)
        _record_cloud_event(
            action_id="cloud.bulk.delete",
            title="Delete files in bulk",
            subtitle="Cloud - Files",
            status="success",
            message=f"Processed {len(request.file_ids)} file(s) for deletion",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.bulk.delete",
            title="Delete files in bulk",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.post("/bulk/move", response_model=BulkOperationResult)
def bulk_move(file_ids: List[str] = Body(...), target_path: str = Body(...), _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.bulk_move(file_ids, target_path)
        _record_cloud_event(
            action_id="cloud.bulk.move",
            title="Move files in bulk",
            subtitle="Cloud - Files",
            status="success",
            message=f"Processed {len(file_ids)} file(s) for move to {target_path}",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.bulk.move",
            title="Move files in bulk",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.post("/bulk/copy", response_model=BulkOperationResult)
def bulk_copy(file_ids: List[str] = Body(...), target_path: str = Body(...), _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.bulk_copy(file_ids, target_path)
        _record_cloud_event(
            action_id="cloud.bulk.copy",
            title="Copy files in bulk",
            subtitle="Cloud - Files",
            status="success",
            message=f"Processed {len(file_ids)} file(s) for copy to {target_path}",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.bulk.copy",
            title="Copy files in bulk",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.post("/bulk/favorite", response_model=BulkOperationResult)
def bulk_favorite(file_ids: List[str] = Body(...), value: bool = Body(...), _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.bulk_favorite(file_ids, value)
        _record_cloud_event(
            action_id="cloud.bulk.favorite",
            title="Update favorites in bulk",
            subtitle="Cloud - Files",
            status="success",
            message=f"Processed {len(file_ids)} file(s) for favorite update",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.bulk.favorite",
            title="Update favorites in bulk",
            subtitle="Cloud - Files",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.get("/share/{share_id}/info", response_model=ShareLink)
def get_share_info(share_id: str, _admin = Depends(require_admin)):
    info = pi_cloud_service.get_share_info(share_id)
    if not info:
        raise HTTPException(status_code=404, detail="Share not found")
    return info


@router.delete("/share/{share_id}")
def delete_share(share_id: str, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.delete_share(share_id)
        _record_cloud_event(
            action_id="cloud.share.delete",
            title="Delete share link",
            subtitle="Cloud - Shares",
            status="success",
            message=f"Deleted share {share_id}",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.share.delete",
            title="Delete share link",
            subtitle="Cloud - Shares",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.get("/shares", response_model=list[ShareLink])
def list_shares(_admin = Depends(require_admin)):
    return pi_cloud_service.list_shares()


# Telegram Bot endpoints
@router.get("/telegram/config")
def get_telegram_config(_admin = Depends(require_admin)):
    """Get current Telegram bot configuration."""
    config = pi_cloud_service.get_telegram_config()
    return config.model_dump(by_alias=True)


@router.post("/telegram/config", response_model=TelegramBotStatus)
def telegram_config(config: TelegramBotConfig, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.configure_telegram_bot(config)
        _record_cloud_event(
            action_id="cloud.telegram.config",
            title="Update Telegram bot configuration",
            subtitle="Cloud - Telegram integration",
            status="success",
            message="Telegram bot configuration updated",
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.telegram.config",
            title="Update Telegram bot configuration",
            subtitle="Cloud - Telegram integration",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.get("/telegram/status")
def telegram_status(_admin = Depends(require_admin)):
    status = pi_cloud_service.get_telegram_status()
    return status.model_dump(by_alias=True)


@router.post("/telegram/start", response_model=TelegramBotStatus)
def start_telegram_bot(_admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.start_telegram_bot()
        status_payload = pi_cloud_service.get_telegram_status()
        enabled = bool(getattr(status_payload, "enabled", False))
        message = (
            "Telegram bot is running"
            if enabled
            else str(getattr(status_payload, "message", None) or "Telegram bot start was not confirmed")
        )
        _record_cloud_event(
            action_id="cloud.telegram.start",
            title="Start Telegram bot",
            subtitle="Cloud · Telegram integration",
            status="success" if enabled else "failed",
            message=message,
            started_at=started_at,
        )
        return status_payload.model_dump(by_alias=True)
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.telegram.start",
            title="Start Telegram bot",
            subtitle="Cloud · Telegram integration",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.post("/telegram/stop", response_model=TelegramBotStatus)
def stop_telegram_bot(_admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.stop_telegram_bot()
        status_payload = pi_cloud_service.get_telegram_status()
        _record_cloud_event(
            action_id="cloud.telegram.stop",
            title="Stop Telegram bot",
            subtitle="Cloud · Telegram integration",
            status="success",
            message="Telegram bot stopped",
            started_at=started_at,
        )
        return status_payload.model_dump(by_alias=True)
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.telegram.stop",
            title="Stop Telegram bot",
            subtitle="Cloud · Telegram integration",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.post("/telegram/test")
def test_telegram_bot(_admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = pi_cloud_service.test_telegram_bot()
        _record_cloud_event(
            action_id="cloud.telegram.test",
            title="Send Telegram test message",
            subtitle="Cloud · Telegram integration",
            status="success" if result.get("success", False) else "failed",
            message=result.get("message", "Telegram bot test completed"),
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.telegram.test",
            title="Send Telegram test message",
            subtitle="Cloud · Telegram integration",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.get("/telegram/uploads", response_model=list[TelegramUpload])
def telegram_uploads(limit: int = 20, _admin = Depends(require_admin)):
    return pi_cloud_service.get_telegram_uploads(limit)


@router.delete("/telegram/user/{user_id}")
def remove_telegram_user(user_id: int, _admin = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        pi_cloud_service.remove_telegram_user(user_id)
        _record_cloud_event(
            action_id="cloud.telegram.user.delete",
            title="Remove Telegram user",
            subtitle="Cloud - Telegram integration",
            status="success",
            message=f"Removed Telegram user {user_id}",
            started_at=started_at,
        )
        return {"status": "ok"}
    except Exception as exc:
        _record_cloud_event(
            action_id="cloud.telegram.user.delete",
            title="Remove Telegram user",
            subtitle="Cloud - Telegram integration",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


__all__ = ["router"]
