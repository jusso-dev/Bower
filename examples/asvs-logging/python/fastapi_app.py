"""FastAPI with request IDs, trusted-proxy client IP and Bower security events.

    BOWER_COLLECTOR_URL=... BOWER_INGEST_TOKEN=... TRUSTED_PROXIES=10.0.0.0/8 uvicorn fastapi_app:app --no-proxy-headers
Uvicorn trusts X-Forwarded-For from 127.0.0.1 by default and rewrites request.client before
the app sees it. --no-proxy-headers keeps the real peer so client_ip can apply TRUSTED_PROXIES.
"""
import hmac
import logging.config
import os
import uuid

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

import bower_events
from logging_config import LOGGING

logging.config.dictConfig(LOGGING)
app = FastAPI()
bower = bower_events.BowerClient()
APP = {"name": "fastapi-example", "environment": os.environ.get("APP_ENV", "development"), "version": "1.0.0"}
TRUSTED = [item.strip() for item in os.environ.get("TRUSTED_PROXIES", "").split(",") if item.strip()]


@app.middleware("http")
async def context(request: Request, call_next):
    traceparent = request.headers.get("traceparent", "")
    request.state.request_id = traceparent[3:35] if len(traceparent) == 55 else str(uuid.uuid4())
    peer = request.client.host if request.client else ""
    request.state.client_ip = bower_events.client_ip(peer, request.headers.get("x-forwarded-for"), TRUSTED)
    response = await call_next(request)
    response.headers["x-request-id"] = request.state.request_id
    return response


def event(request: Request, spec: dict) -> dict:
    route = request.scope.get("route")
    return bower_events.build_event(APP, {
        **spec, "sourceIp": request.state.client_ip, "userAgent": request.headers.get("user-agent"),
        "route": getattr(route, "path", request.url.path),
        "request": {"correlationId": request.state.request_id, "method": request.method, "path": request.url.path}})


@app.post("/login", status_code=204)
async def login(request: Request, tasks: BackgroundTasks, body: dict):
    username, password = str(body.get("username", "")), str(body.get("password", ""))
    if not hmac.compare_digest(f"{username}:{password}", "demo:demo-password"):
        tasks.add_task(bower.send, event(request, {"eventCategory": "authentication", "eventType": "authentication_failure",
            "eventAction": "authentication.attempt", "eventResult": "failure", "eventSeverity": "low",
            "reason": "InvalidCredentials", "actor": {"username": username}}))
        return JSONResponse({"error": "invalid credentials"}, status_code=401, background=tasks)
    tasks.add_task(bower.send, event(request, {"eventCategory": "authentication", "eventType": "authentication_success",
        "eventAction": "authentication.login", "eventResult": "success", "actor": {"userId": "user-demo", "username": username},
        "labels": {"authMethod": "password"}}))
    return Response(status_code=204, background=tasks)


@app.get("/admin/users")
async def admin_users(request: Request, tasks: BackgroundTasks):
    tasks.add_task(bower.send, event(request, {"eventCategory": "authorisation", "eventType": "authorisation_failure",
        "eventAction": "authz.function", "eventResult": "denied", "eventSeverity": "medium",
        "actor": {"userId": "user-demo", "role": "member"}, "target": {"type": "function", "id": "admin.users.list"}}))
    return JSONResponse({"error": "forbidden"}, status_code=403, background=tasks)


@app.exception_handler(RequestValidationError)
async def invalid(request: Request, _error: RequestValidationError):
    bower.send_async(event(request, {"eventCategory": "application-security", "eventType": "input_validation_failure",
        "eventAction": "validation.reject", "eventResult": "failure", "eventSeverity": "low", "reason": "RequestValidation"}))
    return JSONResponse({"error": "bad request", "requestId": request.state.request_id}, status_code=400)


@app.exception_handler(Exception)
async def last_resort(request: Request, error: Exception):
    bower.send_async(event(request, {"eventCategory": "application-security", "eventType": "application_error",
        "eventAction": "error.unhandled", "eventResult": "failure", "eventSeverity": "medium", "reason": "UnhandledException",
        "labels": {"errorType": type(error).__name__}}))
    return JSONResponse({"error": "internal error", "requestId": request.state.request_id}, status_code=500)
