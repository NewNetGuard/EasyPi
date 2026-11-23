from __future__ import annotations

from pydantic import BaseModel, Field


class FileNode(BaseModel):
    name: str
    path: str = Field(..., min_length=1)
    is_dir: bool
    size: int | None = None
    modified: float | None = None


class FileContent(BaseModel):
    path: str = Field(..., min_length=1)
    content: str


class FileUploadResponse(BaseModel):
    path: str = Field(..., min_length=1)
    size: int


class PathPayload(BaseModel):
    path: str = Field(..., min_length=1)


class FileWriteRequest(BaseModel):
    path: str = Field(..., min_length=1)
    content: str


__all__ = [
    "FileNode",
    "FileContent",
    "FileUploadResponse",
    "PathPayload",
    "FileWriteRequest",
]
