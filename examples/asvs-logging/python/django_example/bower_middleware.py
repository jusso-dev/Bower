"""Django middleware: request ID, trusted-proxy client IP, last-resort event, and auth signals.

Add "django_example.bower_middleware.BowerSecurityMiddleware" near the top of MIDDLEWARE and
import this module from an AppConfig.ready() so the signal receivers connect.
"""
import os
import uuid

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.http import JsonResponse

import bower_events

APP = {"name": "django-example", "environment": os.environ.get("APP_ENV", "development"), "version": "1.0.0"}
TRUSTED = [item.strip() for item in os.environ.get("TRUSTED_PROXIES", "").split(",") if item.strip()]
bower = bower_events.BowerClient()


def security(request, spec: dict) -> None:
    match = getattr(request, "resolver_match", None)
    spec = {**spec, "sourceIp": getattr(request, "bower_client_ip", None),
            "userAgent": request.META.get("HTTP_USER_AGENT"),
            "route": "/" + match.route if match and match.route else request.path,
            "request": {"correlationId": getattr(request, "bower_request_id", None), "method": request.method, "path": request.path}}
    bower.send_async(bower_events.build_event(APP, spec))


class BowerSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        traceparent = request.META.get("HTTP_TRACEPARENT", "")
        request.bower_request_id = traceparent[3:35] if len(traceparent) == 55 else str(uuid.uuid4())
        request.bower_client_ip = bower_events.client_ip(request.META.get("REMOTE_ADDR", ""),
                                                         request.META.get("HTTP_X_FORWARDED_FOR"), TRUSTED)
        response = self.get_response(request)
        response["X-Request-Id"] = request.bower_request_id
        return response

    def process_exception(self, request, exception):
        security(request, {"eventCategory": "application-security", "eventType": "application_error", "eventAction": "error.unhandled",
                           "eventResult": "failure", "eventSeverity": "medium", "reason": "UnhandledException",
                           "labels": {"errorType": type(exception).__name__}})
        return JsonResponse({"error": "internal error", "requestId": request.bower_request_id}, status=500)


@receiver(user_logged_in)
def logged_in(sender, request, user, **kwargs):
    security(request, {"eventCategory": "authentication", "eventType": "authentication_success", "eventAction": "authentication.login",
                       "eventResult": "success", "actor": {"userId": str(user.pk), "username": user.get_username()},
                       "labels": {"authMethod": "password"}})


@receiver(user_login_failed)
def login_failed(sender, credentials, request=None, **kwargs):
    # Django already masks the password in `credentials`; only the username is used.
    if request is not None:
        security(request, {"eventCategory": "authentication", "eventType": "authentication_failure", "eventAction": "authentication.attempt",
                           "eventResult": "failure", "eventSeverity": "low", "reason": "InvalidCredentials",
                           "actor": {"username": str(credentials.get("username", ""))}})


@receiver(user_logged_out)
def logged_out(sender, request, user, **kwargs):
    if user is not None:
        security(request, {"eventCategory": "authentication", "eventType": "session_terminated", "eventAction": "session.logout",
                           "eventResult": "success", "actor": {"userId": str(user.pk)}})
