import json

from django.contrib.auth import authenticate, login
from django.http import HttpResponse, JsonResponse
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .bower_middleware import security


@csrf_exempt  # Example API only; keep CSRF protection on browser forms.
def login_view(request):
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        security(request, {"eventCategory": "application-security", "eventType": "input_validation_failure",
                           "eventAction": "validation.reject", "eventResult": "failure", "eventSeverity": "low", "reason": "MalformedJson"})
        return JsonResponse({"error": "bad request"}, status=400)
    user = authenticate(request, username=str(body.get("username", "")), password=str(body.get("password", "")))
    if user is None:  # user_login_failed has already fired
        return JsonResponse({"error": "invalid credentials"}, status=401)
    login(request, user)  # fires user_logged_in
    return HttpResponse(status=204)


def admin_users(request):
    security(request, {"eventCategory": "authorisation", "eventType": "authorisation_failure", "eventAction": "authz.function",
                       "eventResult": "denied", "eventSeverity": "medium", "actor": {"userId": "user-demo", "role": "member"},
                       "target": {"type": "function", "id": "admin.users.list"}})
    return JsonResponse({"error": "forbidden"}, status=403)


urlpatterns = [path("login", login_view), path("admin/users", admin_users)]
