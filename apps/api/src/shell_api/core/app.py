"""Composition root for the API. No application routes exist in Stage 0 yet."""

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException

from shell_api.core.settings import load_settings
from shell_api.shared.domain.errors import Conflict, ProviderUnavailable
from shell_api.shared.presentation.errors import (
    CorrelationMiddleware,
    ProblemDetails,
    problem_details,
)


def create_app() -> FastAPI:
    load_settings()
    error_response = {
        "description": "Shell error (stable codes translated by clients)",
        "content": {
            "application/problem+json": {"schema": ProblemDetails.model_json_schema()}
        },
    }
    app = FastAPI(
        debug=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        responses={"default": error_response, 422: error_response},
    )
    app.add_middleware(CorrelationMiddleware)
    for error in (
        Conflict,
        ProviderUnavailable,
        RequestValidationError,
        HTTPException,
        Exception,
    ):
        app.add_exception_handler(error, problem_details)
    return app
