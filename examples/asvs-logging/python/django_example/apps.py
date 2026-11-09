from django.apps import AppConfig


class ExampleConfig(AppConfig):
    name = "django_example"

    def ready(self):
        from . import bower_middleware  # noqa: F401  connects the auth signal receivers
