"""AUTH-ERROR-001: exercise the real handler through test-only routes."""

from unittest.mock import Mock
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
def selected_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHELL_ENV", "production")


@pytest.fixture
def app(selected_environment: None) -> FastAPI:
    app = create_app()

    def conflict() -> None:
        raise Conflict(SENSITIVE)

    def provider() -> None:
        raise ProviderUnavailable(SENSITIVE)

    def unexpected() -> None:
        raise RuntimeError(SENSITIVE)

    def http_error() -> None:
        raise HTTPException(404, detail=SENSITIVE, headers={"X-Test": "preserved"})

    def bad_request() -> None:
        raise HTTPException(400, detail=SENSITIVE)

    def validate(payload: Payload) -> Payload:
        return payload

    def ok() -> dict[str, str]:
        return {"correlation_id": "success"}

    app.add_api_route("/bad-request", bad_request, methods=["GET"])
    app.add_api_route("/conflict", conflict, methods=["GET"])
    app.add_api_route("/provider", provider, methods=["GET"])
    app.add_api_route("/unexpected", unexpected, methods=["GET"])
    app.add_api_route("/http-error", http_error, methods=["GET"])
    app.add_api_route("/validate", validate, methods=["POST"])
    app.add_api_route("/ok", ok, methods=["GET"])
    return app


@pytest.mark.parametrize(
    ("method", "path", "status", "code", "title"),
    [
        ("GET", "/bad-request", 400, "request.bad_request", "Bad Request"),
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
    if status == 503:
        assert response.headers["retry-after"] == "1"
    else:
        assert "retry-after" not in response.headers
    if path == "/http-error":
        assert response.headers["x-test"] == "preserved"


def test_correlation_is_generated_for_every_request(app: FastAPI) -> None:
    seen: list[str] = []

    def correlation(request: Request) -> dict[str, str]:
        return {"correlation_id": request.state.correlation_id}

    app.add_api_route("/correlation", correlation, methods=["GET"])

    with TestClient(app, raise_server_exceptions=False) as client:
        for path in ("/correlation", "/missing", "/unexpected", "/provider") * 2:
            response = client.get(path, headers={"X-Request-ID": "forged-id"})
            value = response.json()["correlation_id"]
            assert UUID(value).version == 4
            seen.append(value)
    assert len(set(seen)) == len(seen)


def test_factory_has_no_public_or_fixture_routes(selected_environment: None) -> None:
    assert create_app().routes == []


def test_codes_are_listed_in_openapi(app: FastAPI) -> None:
    responses = app.openapi()["paths"]["/validate"]["post"]["responses"]
    for status in ("default", "422"):
        content = responses[status]["content"]
        assert set(content) == {"application/problem+json"}
        documented = set(
            content["application/problem+json"]["schema"]["properties"]["code"]["enum"]
        )
        emitted: set[str] = set()
        with TestClient(app, raise_server_exceptions=False) as client:
            for path in (
                "/conflict",
                "/provider",
                "/unexpected",
                "/missing",
                "/validate",
                "/http-error",
                "/bad-request",
            ):
                emitted.add(client.get(path).json()["code"])
            emitted.add(
                client.post("/validate", json={"count": SENSITIVE}).json()["code"]
            )
        assert documented == emitted


def test_unmapped_http_errors_are_bare_internal_errors(app: FastAPI) -> None:
    def unmapped() -> None:
        raise HTTPException(502, detail=SENSITIVE)

    app.add_api_route("/unmapped", unmapped, methods=["GET"])

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


def test_builtin_telemetry_is_disabled(
    selected_environment: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FASTAPI_OTEL_AUTO_CONFIGURE", "true")
    factory = Mock(wraps=FastAPI)
    monkeypatch.setattr("shell_api.core.app.FastAPI", factory)
    create_app()
    assert factory.call_args.kwargs["telemetry"] == {
        "tracing": False,
        "metrics": False,
        "logs": False,
        "auto_configure": False,
    }
