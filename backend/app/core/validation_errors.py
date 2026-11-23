"""Safe HTTP responses for request validation failures."""
from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def sanitized_validation_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Return useful Pydantic errors without reflecting any submitted values."""
    sanitized: list[dict[str, Any]] = []
    for raw_error in exc.errors():
        error = dict(raw_error)
        # Fail closed: field names evolve and secrets are not limited to words
        # such as "password" or "token" (for example authkey and psk_key).
        # The UI only needs type, location and message to explain the error.
        error.pop("input", None)
        error.pop("ctx", None)
        sanitized.append(error)
    return sanitized


async def request_validation_exception_handler(
    _request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Match FastAPI's 422 shape while never echoing credential values."""
    return JSONResponse(
        status_code=422,
        content=jsonable_encoder({"detail": sanitized_validation_errors(exc)}),
    )
