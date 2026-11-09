"""Minimal Django settings for the Bower example. Not for production."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logging_config import LOGGING  # noqa: E402,F401

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "example-only-not-a-secret")
DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions", "django_example.apps.ExampleConfig"]
MIDDLEWARE = [
    "django_example.bower_middleware.BowerSecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
ROOT_URLCONF = "django_example.urls"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": os.environ.get("DJANGO_DB", ":memory:")}}
USE_TZ = True  # UTC timestamps
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
