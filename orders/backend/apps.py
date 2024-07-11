from django.apps import AppConfig



class BackendConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'backend'

    def ready(self):
        from .signals import new_user_registered, new_order, \
            new_user_registered_signal, new_order_signal
        new_user_registered.connect(new_user_registered_signal)
        new_order.connect(new_order_signal)
