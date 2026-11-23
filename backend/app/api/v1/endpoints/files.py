from __future__ import annotations

import logging
from datetime import datetime, timezone
import mimetypes
import os
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query, Depends
from fastapi.responses import StreamingResponse
from typing import List, Dict, Any

from app.api.deps import require_admin
from app.models.user import User
from app.services.files_service import FilesService
from app.services.operation_event_service import OperationEventService

router = APIRouter(prefix="/files", tags=["files"])

files_service = FilesService()
logger = logging.getLogger(__name__)
operation_event_service = OperationEventService()

_SAFE_INLINE_IMAGE_TYPES = {
    "image/avif",
    "image/bmp",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/x-icon",
}
_IMAGE_SECURITY_HEADERS = {
    "Cache-Control": "private, no-store",
    "Content-Security-Policy": "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
}


def _record_file_event(
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
            route="/files",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record file event %s: %s", action_id, exc)


@router.get("/list")
def list_directory(
    path: str = Query(default="/home"),
    _admin: User = Depends(require_admin)
) -> List[Dict[str, Any]]:
    """List directory contents. Requires admin."""
    return files_service.list_directory(path)


@router.get("/search")
def search_files(
    query: str = Query(..., min_length=1, description="Search query"),
    path: str = Query(default="/home", description="Root path to search in"),
    limit: int = Query(default=50, ge=1, le=200, description="Max results"),
    _admin: User = Depends(require_admin)
) -> List[Dict[str, Any]]:
    """
    Live search for files and folders.
    Returns matching items as user types.
    Requires admin.
    """
    return files_service.search_files(query, path, limit)


@router.get("/read")
def read_file(
    path: str = Query(...),
    _admin: User = Depends(require_admin)
) -> Dict[str, Any]:
    """Read file contents. Requires admin."""
    return files_service.read_file(path)


@router.get("/image")
def get_image(
    path: str = Query(...),
    _admin: User = Depends(require_admin)
):
    """Get image file for preview. Requires admin."""
    source, file_stat, resolved = files_service.open_binary_file(path)
    mime_type, _ = mimetypes.guess_type(resolved)
    if mime_type not in _SAFE_INLINE_IMAGE_TYPES:
        source.close()
        raise HTTPException(status_code=400, detail="File is not an image")

    def stream_file():
        with source:
            while chunk := source.read(1024 * 1024):
                yield chunk

    headers = dict(_IMAGE_SECURITY_HEADERS)
    headers["Content-Length"] = str(file_stat.st_size)
    return StreamingResponse(
        stream_file(),
        media_type=mime_type,
        headers=headers,
    )


@router.get("/type")
def get_file_type(
    path: str = Query(...),
    _admin: User = Depends(require_admin)
) -> Dict[str, Any]:
    """Get file type information. Requires admin."""
    _, resolved = files_service.inspect_path(path)
    mime_type, _ = mimetypes.guess_type(resolved)
    
    # Determine file category
    if mime_type:
        if mime_type.startswith('image/'):
            category = 'image'
        elif mime_type.startswith('video/'):
            category = 'video'
        elif mime_type.startswith('audio/'):
            category = 'audio'
        elif mime_type.startswith('text/') or mime_type in ['application/json', 'application/javascript', 'application/xml']:
            category = 'text'
        else:
            category = 'binary'
    else:
        # Try to determine by extension
        ext = os.path.splitext(resolved)[1].lower()
        if ext in ['.txt', '.py', '.js', '.ts', '.json', '.xml', '.html', '.css', '.md', '.sh', '.yml', '.yaml', '.conf', '.cfg', '.ini']:
            category = 'text'
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico']:
            category = 'image'
        else:
            category = 'binary'
    
    return {
        "mime_type": mime_type or "application/octet-stream",
        "category": category
    }


@router.post("/write")
def write_file(
    payload: Dict[str, str],
    _admin: User = Depends(require_admin)
) -> Dict[str, str]:
    """Write content to file. Requires admin."""
    started_at = datetime.now(timezone.utc).isoformat()
    path = payload.get("path")
    content = payload.get("content", "")
    
    if not path:
        detail = "Path is required"
        _record_file_event(
            action_id="files.write",
            title="Write file",
            subtitle="Files · Missing path",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=detail)

    try:
        result = files_service.write_file(path, content)
    except Exception as exc:
        _record_file_event(action_id="files.write", title="Write file", subtitle=f"Files · {path}", status="failed", message=f"{type(exc).__name__}: {exc}", started_at=started_at)
        raise
    _record_file_event(
        action_id="files.write",
        title="Write file",
        subtitle=f"Files · {path}",
        status="success",
        message=result.get("message", f"File saved: {path}"),
        started_at=started_at,
    )
    return result


@router.post("/create-file")
def create_file(
    payload: Dict[str, str],
    _admin: User = Depends(require_admin)
) -> Dict[str, str]:
    """Create empty file. Requires admin."""
    started_at = datetime.now(timezone.utc).isoformat()
    path = payload.get("path")
    
    if not path:
        detail = "Path is required"
        _record_file_event(
            action_id="files.create-file",
            title="Create file",
            subtitle="Files · Missing path",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=detail)

    try:
        result = files_service.create_file(path)
    except Exception as exc:
        _record_file_event(action_id="files.create-file", title="Create file", subtitle=f"Files · {path}", status="failed", message=f"{type(exc).__name__}: {exc}", started_at=started_at)
        raise
    _record_file_event(
        action_id="files.create-file",
        title="Create file",
        subtitle=f"Files · {path}",
        status="success",
        message=result.get("message", f"File created: {path}"),
        started_at=started_at,
    )
    return result


@router.post("/create-folder")
def create_folder(
    payload: Dict[str, str],
    _admin: User = Depends(require_admin)
) -> Dict[str, str]:
    """Create directory. Requires admin."""
    started_at = datetime.now(timezone.utc).isoformat()
    path = payload.get("path")
    
    if not path:
        detail = "Path is required"
        _record_file_event(
            action_id="files.create-folder",
            title="Create folder",
            subtitle="Files · Missing path",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=detail)

    try:
        result = files_service.create_folder(path)
    except Exception as exc:
        _record_file_event(action_id="files.create-folder", title="Create folder", subtitle=f"Files · {path}", status="failed", message=f"{type(exc).__name__}: {exc}", started_at=started_at)
        raise
    _record_file_event(
        action_id="files.create-folder",
        title="Create folder",
        subtitle=f"Files · {path}",
        status="success",
        message=result.get("message", f"Folder created: {path}"),
        started_at=started_at,
    )
    return result


@router.delete("/delete")
def delete_path(
    payload: Dict[str, str],
    _admin: User = Depends(require_admin)
) -> Dict[str, str]:
    """Delete file or directory. Requires admin."""
    started_at = datetime.now(timezone.utc).isoformat()
    path = payload.get("path")
    
    if not path:
        detail = "Path is required"
        _record_file_event(
            action_id="files.delete",
            title="Delete path",
            subtitle="Files · Missing path",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=detail)

    try:
        result = files_service.delete(path)
    except Exception as exc:
        _record_file_event(action_id="files.delete", title="Delete path", subtitle=f"Files · {path}", status="failed", message=f"{type(exc).__name__}: {exc}", started_at=started_at)
        raise
    _record_file_event(
        action_id="files.delete",
        title="Delete path",
        subtitle=f"Files · {path}",
        status="success",
        message=result.get("message", f"Deleted: {path}"),
        started_at=started_at,
    )
    return result


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    path: str = Form(...),
    _admin: User = Depends(require_admin)
) -> Dict[str, Any]:
    """Upload file to specified path. Requires admin."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await files_service.upload_file(file, path)
    except Exception as exc:
        filename = getattr(file, "filename", None) or "uploaded file"
        _record_file_event(action_id="files.upload", title="Upload file", subtitle=f"Files · {filename}", status="failed", message=f"{type(exc).__name__}: {exc}", started_at=started_at)
        raise
    filename = getattr(file, "filename", None) or "uploaded file"
    _record_file_event(
        action_id="files.upload",
        title="Upload file",
        subtitle=f"Files · {filename}",
        status="success",
        message=result.get("message", f"Uploaded {filename} to {path}"),
        started_at=started_at,
    )
    return result


__all__ = ["router"]
