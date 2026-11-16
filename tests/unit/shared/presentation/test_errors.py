"""AUTH-ERROR-001: exercise the real handler through test-only routes."""

from uuid import UUID

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from pydantic import BaseModel
from shell_api.main import create_app
from shell_api.shared.domain.errors import Conflict, ProviderUnavailable

pytestmark = pytest.mark.req("AUTH-ERROR-001", kind="unit test", part="problem-details")

SENSITIVE = "SELECT secret FROM users; token=synthetic-secret traceback sentinel"


class Payload(BaseModel):
    count: int


@pytest.fixture
def app() -> FastAPI:
    app = create_app()

    @app.get("/conflict")
    def conflict() -> None:
        raise Conflict(SENSITIVE)

    @app.get("/provider")
    def provider() -> None:
        raise ProviderUnavailable(SENSITIVE)

    @app.get("/unexpected")
    def unexpected() -> None:
        raise RuntimeError(SENSITIVE)

    @app.get("/http-error")
    def http_error() -> None:
        raise HTTPException(404, detail=SENSITIVE, headers={"X-Test": "preserved"})

    @app.post("/validate")
    def validate(payload: Payload) -> Payload:
        return payload

    @app.get("/ok")
    def ok() -> dict[str, str]:
        return {"correlation_id": "success"}

    return app


@pytest.mark.parametrize(
    ("method", "path", "status", "code", "title"),
    [
        ("GET", "/conflict", 409, "request.conflict", "Conflict"),
        ("GET", "/provider", 503, "provider.unavailable", "Service Unavailable"),
        ("GET", "/unexpected", 500, "internal.unexpected", "Internal Server Error"),
        ("GET", "/missing", 404, "request.not_found", "Not Found"),
        ("GET", "/validate", 405, "request.method_not_allowed", "Method Not Allowed"),
        (
            "POST",
            "/validate",
            422,
            "request.validation_failed",
            "Unprocessable Content",
        ),
        ("GET", "/http-error", 404, "request.not_found", "Not Found"),
    ],
)
def test_problem_details(
    app: FastAPI, method: str, path: str, status: int, code: str, title: str
) -> None:
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.request(method, path, json={"count": SENSITIVE})
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body == {
        "type": f"urn:shell:error:{code}",
        "title": title,
        "status": status,
        "code": code,
        "correlation_id": body["correlation_id"],
    }
    assert UUID(body["correlation_id"]).version == 4
    assert SENSITIVE not in response.text
    if status == 405:
        assert response.headers["allow"] == "POST"
    if status in (422, 503):
        assert response.headers["retry-after"] == "1"
    if path == "/http-error":
        assert response.headers["x-test"] == "preserved"


def test_correlation_is_generated_for_every_request(app: FastAPI) -> None:
    seen: list[str] = []

    @app.get("/correlation")
    def correlation(request: Request) -> dict[str, str]:
        return {"correlation_id": request.state.correlation_id}

    with TestClient(app, raise_server_exceptions=False) as client:
        for path in ("/correlation", "/missing", "/unexpected", "/provider") * 2:
            response = client.get(path, headers={"X-Request-ID": "forged-id"})
            value = response.json()["correlation_id"]
            assert UUID(value).version == 4
            seen.append(value)
    assert len(set(seen)) == len(seen)


def test_factory_has_no_public_or_fixture_routes() -> None:
    assert create_app().routes == []


def test_codes_are_listed_in_openapi(app: FastAPI) -> None:
    schema = app.openapi()
    assert set(
        schema["components"]["schemas"]["ProblemDetails"]["properties"]["code"]["enum"]
    ) == {
        "request.conflict",
        "provider.unavailable",
        "internal.unexpected",
        "request.not_found",
        "request.method_not_allowed",
        "request.validation_failed",
    }


def test_unmapped_http_errors_are_bare_internal_errors(app: FastAPI) -> None:
    @app.get("/unmapped")
    def unmapped() -> None:
        raise HTTPException(502, detail=SENSITIVE)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/unmapped")
    assert response.status_code == 500
    assert response.json()["code"] == "internal.unexpected"
    assert SENSITIVE not in response.text


@pytest.mark.parametrize("body", ["{", '{"count": "synthetic-secret"}'])
def test_invalid_json_and_input_are_not_returned(app: FastAPI, body: str) -> None:
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/validate", content=body, headers={"Content-Type": "application/json"}
        )
    assert response.status_code == 422
    assert response.json()["code"] == "request.validation_failed"
    assert "synthetic-secret" not in response.text
