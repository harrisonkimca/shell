"""The central HTTP error contract. Exception messages never enter responses."""

from http import HTTPStatus
from typing import Literal
from uuid import uuid4

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from shell_api.shared.domain.errors import Conflict, ProviderUnavailable


class ProblemDetails(BaseModel):
    type: str
    title: str
    status: int
    code: Literal[
        "request.conflict",
        "provider.unavailable",
        "request.not_found",
        "request.method_not_allowed",
        "request.validation_failed",
        "internal.unexpected",
    ]
    correlation_id: str


class CorrelationMiddleware:
    """Generate a Shell-owned ID, including for errors handled outside middleware."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope.setdefault("state", {})["correlation_id"] = str(uuid4())
        await self.app(scope, receive, send)


async def problem_details(request: Request, error: Exception) -> JSONResponse:
    status = 500
    code = "internal.unexpected"
    headers: dict[str, str] = {}
    if isinstance(error, Conflict):
        status, code = 409, "request.conflict"
    elif isinstance(error, ProviderUnavailable):
        status, code = 503, "provider.unavailable"
        headers["Retry-After"] = "1"
    elif isinstance(error, RequestValidationError):
        status, code = 422, "request.validation_failed"
        headers["Retry-After"] = "1"
    elif isinstance(error, HTTPException) and error.status_code in (404, 405):
        status = error.status_code
        code = {404: "request.not_found", 405: "request.method_not_allowed"}[status]
        headers = dict(error.headers or {})
    # JSONResponse owns the representation headers, even for HTTPException.
    headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in ("content-type", "content-length")
    }
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:shell:error:{code}",
            "title": HTTPStatus(status).phrase,
            "status": status,
            "code": code,
            "correlation_id": request.state.correlation_id,
        },
        headers=headers,
        media_type="application/problem+json",
    )
