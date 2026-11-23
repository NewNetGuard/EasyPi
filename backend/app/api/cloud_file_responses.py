from pathlib import Path
from urllib.parse import quote

from fastapi.responses import FileResponse, StreamingResponse


DOWNLOAD_SECURITY_HEADERS = {
    "Cache-Control": "private, no-store",
    "Content-Security-Policy": "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Download-Options": "noopen",
}
THUMBNAIL_SECURITY_HEADERS = {
    "Cache-Control": "private, no-store",
    "Content-Security-Policy": "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
}


def cloud_download_response(path: Path) -> FileResponse:
    """Return stored user content without allowing same-origin execution."""
    return FileResponse(
        path=path,
        filename=path.name,
        media_type="application/octet-stream",
        content_disposition_type="attachment",
        headers=DOWNLOAD_SECURITY_HEADERS,
    )


def opened_cloud_download_response(opened_file, path: Path, size: int) -> StreamingResponse:
    """Stream an already validated descriptor so path replacement cannot race it."""

    def body():
        try:
            while chunk := opened_file.read(1024 * 1024):
                yield chunk
        finally:
            opened_file.close()

    headers = {
        **DOWNLOAD_SECURITY_HEADERS,
        "Content-Disposition": f"attachment; filename*=utf-8''{quote(path.name, safe='')}",
        "Content-Length": str(size),
    }
    return StreamingResponse(body(), media_type="application/octet-stream", headers=headers)


def cloud_thumbnail_response(path: Path) -> FileResponse:
    """Serve a generated JPEG thumbnail as passive same-origin content."""
    return FileResponse(path=path, media_type="image/jpeg", headers=THUMBNAIL_SECURITY_HEADERS)
