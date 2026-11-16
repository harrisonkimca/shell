"""The central HTTP error contract. Exception messages never enter responses."""

from http import HTTPStatus
from uuid import uuid4

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, JsonValue
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from shell_api.shared.domain.errors import Conflict, ProviderUnavailable

EXCEPTION_ERRORS: dict[type[Exception], tuple[int, str]] = {
    Conflict: (409, "request.conflict"),
    ProviderUnavailable: (503, "provider.unavailable"),
    RequestValidationError: (422, "request.validation_failed"),
    Exception: (500, "internal.unexpected"),
}
HTTP_ERRORS = {
    400: "request.bad_request",
    404: "request.not_found",
    405: "request.method_not_allowed",
}


ERROR_CODE_SCHEMA: dict[str, JsonValue] = {
    "enum": [
        code
        for code in sorted(
            {code for _, code in EXCEPTION_ERRORS.values()} | set(HTTP_ERRORS.values())
        )
    ]
}


class ProblemDetails(BaseModel):
    type: str
    title: str
    status: int
    code: str = Field(json_schema_extra=ERROR_CODE_SCHEMA)
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
    status, code = next(
        mapping for kind, mapping in EXCEPTION_ERRORS.items() if isinstance(error, kind)
    )
    headers: dict[str, str] = {}
    if isinstance(error, HTTPException) and error.status_code in HTTP_ERRORS:
        status = error.status_code
        code = HTTP_ERRORS[status]
        headers = dict(error.headers or {})
    if status in (429, 503):
        headers.setdefault("Retry-After", "1")
    # JSONResponse owns the representation headers, even for HTTPException.
    headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in ("content-type", "content-length")
    }
    return JSONResponse(
        status_code=status,
        content=ProblemDetails(
            type=f"urn:shell:error:{code}",
            title=HTTPStatus(status).phrase,
            status=status,
            code=code,
            correlation_id=request.state.correlation_id,
        ).model_dump(),
        headers=headers,
        media_type="application/problem+json",
    )
