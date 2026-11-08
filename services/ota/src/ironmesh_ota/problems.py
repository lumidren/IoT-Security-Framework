"""RFC 9457 problem details (``application/problem+json``) and the exception handlers."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_JSON = "application/problem+json"

_TITLES = {
    400: "Bad request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not found",
    409: "Conflict",
    413: "Payload too large",
    415: "Unsupported media type",
    422: "Validation failed",
    500: "Internal server error",
    503: "Service unavailable",
}


class Problem(Exception):
    def __init__(
        self,
        status: int,
        detail: str | None = None,
        *,
        title: str | None = None,
        errors: list[dict[str, Any]] | None = None,
        type_: str = "about:blank",
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail or title or str(status))
        self.status = status
        self.detail = detail
        self.title = title or _TITLES.get(status, "Error")
        self.errors = errors
        self.type = type_
        self.headers = headers


def not_found(what: str) -> Problem:
    return Problem(404, f"{what} not found", title=f"{what} not found")


def conflict(detail: str) -> Problem:
    return Problem(409, detail)


def validation(errors: list[dict[str, Any]], detail: str | None = None) -> Problem:
    return Problem(422, detail, errors=errors)


def problem_response(request: Request, problem: Problem) -> JSONResponse:
    body: dict[str, Any] = {
        "type": problem.type,
        "title": problem.title,
        "status": problem.status,
        "instance": request.url.path,
    }
    if problem.detail is not None:
        body["detail"] = problem.detail
    if problem.errors is not None:
        body["errors"] = problem.errors
    return JSONResponse(
        body, status_code=problem.status, media_type=PROBLEM_JSON, headers=problem.headers
    )


def install(app: FastAPI) -> None:
    async def on_problem(request: Request, exc: Exception) -> JSONResponse:
        if not isinstance(exc, Problem):  # pragma: no cover - registered per type
            raise exc
        return problem_response(request, exc)

    async def on_validation(request: Request, exc: Exception) -> JSONResponse:
        if not isinstance(exc, RequestValidationError):  # pragma: no cover - registered per type
            raise exc
        errors = []
        for err in exc.errors():
            loc = [str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path")]
            errors.append(
                {"field": ".".join(loc) or None, "message": err.get("msg", ""), "loc": loc}
            )
        return problem_response(request, Problem(422, errors=errors))

    async def on_http(request: Request, exc: Exception) -> JSONResponse:
        if not isinstance(exc, StarletteHTTPException):  # pragma: no cover - registered per type
            raise exc
        return problem_response(
            request,
            Problem(
                exc.status_code,
                str(exc.detail),
                headers=dict(exc.headers) if exc.headers else None,
            ),
        )

    app.add_exception_handler(Problem, on_problem)
    app.add_exception_handler(RequestValidationError, on_validation)
    app.add_exception_handler(StarletteHTTPException, on_http)
