from django.apps import AppConfig




class BackendConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'backend'

    def ready(self):
        from .signals import new_order, handle_new_order

