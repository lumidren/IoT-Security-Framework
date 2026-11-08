"""RFC 9457 problem details for every error response."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_CONTENT_TYPE = "application/problem+json"
TYPE_BASE = "https://ironmesh.dev/problems/"

log = structlog.get_logger("app.problems")


class ProblemError(Exception):
    """Raise anywhere in the app to produce a problem-details response."""

    def __init__(
        self,
        status: int,
        detail: str | None = None,
        *,
        title: str | None = None,
        type_: str | None = None,
        errors: Sequence[Mapping[str, Any]] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status = status
        self.title = title or HTTPStatus(status).phrase
        self.detail = detail
        self.type = type_ or TYPE_BASE + self.title.lower().replace(" ", "-")
        self.errors = list(errors) if errors else []
        self.headers = dict(headers or {})
        super().__init__(f"{status} {self.title}: {detail}")


def not_found(what: str) -> ProblemError:
    return ProblemError(404, f"{what} not found")


def conflict(detail: str) -> ProblemError:
    return ProblemError(409, detail)


def forbidden(detail: str = "insufficient role") -> ProblemError:
    return ProblemError(403, detail)


def unauthorized(detail: str = "authentication required") -> ProblemError:
    return ProblemError(401, detail, headers={"WWW-Authenticate": 'Bearer realm="ironmesh"'})


def unprocessable(detail: str, errors: Sequence[Mapping[str, Any]] | None = None) -> ProblemError:
    return ProblemError(422, detail, errors=errors)


def problem_response(
    request: Request,
    status: int,
    *,
    title: str | None = None,
    detail: str | None = None,
    type_: str | None = None,
    errors: Sequence[Mapping[str, Any]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    phrase = title or HTTPStatus(status).phrase
    body: dict[str, Any] = {
        "type": type_ or TYPE_BASE + phrase.lower().replace(" ", "-"),
        "title": phrase,
        "status": status,
        "detail": detail,
        "instance": request.url.path,
        "errors": list(errors or []),
    }
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        body["request_id"] = request_id
    return JSONResponse(
        body, status_code=status, headers=dict(headers or {}), media_type=PROBLEM_CONTENT_TYPE
    )


def install_problem_handlers(app: FastAPI) -> None:
    async def on_problem(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, ProblemError)
        return problem_response(
            request,
            exc.status,
            title=exc.title,
            detail=exc.detail,
            type_=exc.type,
            errors=exc.errors,
            headers=exc.headers,
        )

    async def on_http(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, StarletteHTTPException)
        return problem_response(
            request,
            exc.status_code,
            detail=str(exc.detail) if exc.detail else None,
            headers=exc.headers,
        )

    async def on_validation(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, RequestValidationError)
        errors = [
            {
                "loc": list(err.get("loc", ())),
                "msg": str(err.get("msg", "")),
                "type": str(err.get("type", "")),
            }
            for err in exc.errors()
        ]
        return problem_response(request, 422, detail="request validation failed", errors=errors)

    async def on_unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled_error", path=request.url.path, error=repr(exc))
        return problem_response(request, 500, detail="internal error")

    app.add_exception_handler(ProblemError, on_problem)
    app.add_exception_handler(StarletteHTTPException, on_http)
    app.add_exception_handler(RequestValidationError, on_validation)
    app.add_exception_handler(Exception, on_unhandled)
