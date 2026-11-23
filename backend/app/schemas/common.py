from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

DEFAULT_PAGE_SIZE = 20

T = TypeVar("T")


class StatusResponse(BaseModel):
    status: str = "ok"


class ErrorResponse(BaseModel):
    message: str
    code: int | None = None


class Paginated(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int
