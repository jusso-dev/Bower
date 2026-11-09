"""Flask with request IDs, trusted-proxy client IP and Bower security events.

    BOWER_COLLECTOR_URL=... BOWER_INGEST_TOKEN=... TRUSTED_PROXIES=10.0.0.0/8 flask --app flask_app run
"""
import hmac
import logging.config
import os
import uuid

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import BadRequest, HTTPException

import bower_events
from logging_config import LOGGING

logging.config.dictConfig(LOGGING)
log = logging.getLogger("flask_example")
app = Flask(__name__)
bower = bower_events.BowerClient()
APP = {"name": "flask-example", "environment": os.environ.get("APP_ENV", "development"), "version": "1.0.0"}
# Don't use werkzeug's ProxyFix with a fixed hop count: clientIp checks the peer against this list.
TRUSTED = [item.strip() for item in os.environ.get("TRUSTED_PROXIES", "").split(",") if item.strip()]


@app.before_request
def context() -> None:
    traceparent = request.headers.get("traceparent", "")
    g.request_id = traceparent[3:35] if len(traceparent) == 55 else str(uuid.uuid4())
    g.client_ip = bower_events.client_ip(request.remote_addr or "", request.headers.get("X-Forwarded-For"), TRUSTED)


@app.after_request
def request_id_header(response):
    response.headers["X-Request-Id"] = g.request_id
    return response


def security(spec: dict) -> None:
    spec = {**spec, "sourceIp": g.client_ip, "userAgent": request.user_agent.string,
            "route": request.url_rule.rule if request.url_rule else request.path,
            "request": {"correlationId": g.request_id, "method": request.method, "path": request.full_path}}
    bower.send_async(bower_events.build_event(APP, spec))


@app.post("/login")
def login():
    body = request.get_json(silent=False) or {}
    username, password = str(body.get("username", "")), str(body.get("password", ""))
    if not hmac.compare_digest(f"{username}:{password}", "demo:demo-password"):
        security({"eventCategory": "authentication", "eventType": "authentication_failure", "eventAction": "authentication.attempt",
                  "eventResult": "failure", "eventSeverity": "low", "reason": "InvalidCredentials", "actor": {"username": username}})
        return jsonify(error="invalid credentials"), 401
    security({"eventCategory": "authentication", "eventType": "authentication_success", "eventAction": "authentication.login",
              "eventResult": "success", "actor": {"userId": "user-demo", "username": username}, "labels": {"authMethod": "password"}})
    return "", 204


@app.get("/admin/users")
def admin_users():
    security({"eventCategory": "authorisation", "eventType": "authorisation_failure", "eventAction": "authz.function",
              "eventResult": "denied", "eventSeverity": "medium", "actor": {"userId": "user-demo", "role": "member"},
              "target": {"type": "function", "id": "admin.users.list"}, "labels": {"requiredPermission": "users.read"}})
    return jsonify(error="forbidden"), 403


@app.errorhandler(Exception)
def last_resort(error):
    # ASVS 5.0 V16.5.1, V16.5.4: generic message out, event to Bower, no stack trace in either.
    if isinstance(error, BadRequest):
        security({"eventCategory": "application-security", "eventType": "input_validation_failure", "eventAction": "validation.reject",
                  "eventResult": "failure", "eventSeverity": "low", "reason": "MalformedJson"})
        return jsonify(error="bad request", requestId=g.request_id), 400
    if isinstance(error, HTTPException):
        return error
    log.error("unhandled error", extra={"fields": {"requestId": g.request_id, "errorType": type(error).__name__}})
    security({"eventCategory": "application-security", "eventType": "application_error", "eventAction": "error.unhandled",
              "eventResult": "failure", "eventSeverity": "medium", "reason": "UnhandledException",
              "labels": {"errorType": type(error).__name__}})
    return jsonify(error="internal error", requestId=g.request_id), 500
