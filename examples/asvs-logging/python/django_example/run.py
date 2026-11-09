"""Run the Django example on 127.0.0.1:${PORT:-8000} with an in-memory demo user (demo / demo-password)."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_example.settings")

import django  # noqa: E402

django.setup()
from django.contrib.auth.models import User  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.core.servers.basehttp import run  # noqa: E402
from django.core.wsgi import get_wsgi_application  # noqa: E402

call_command("migrate", verbosity=0)
User.objects.create_user("demo", password="demo-password")
run("127.0.0.1", int(os.environ.get("PORT", "8000")), get_wsgi_application(), threading=False)
