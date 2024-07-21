from typing import Type

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver, Signal
from django_rest_passwordreset.signals import reset_password_token_created

from .views import SendConfirmationOrder
from .models import ConfirmEmailToken, User, Order

new_order = Signal()
handle_new_order = Signal()


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, **kwargs):

    # send an e-mail to the user

    msg = EmailMultiAlternatives(
        # title:
        f"Password Reset Token for {reset_password_token.user}",
        # message:
        reset_password_token.key,
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [reset_password_token.user.email]
    )
    msg.send()

@receiver(post_save, sender=Order)
def new_order_signal(instance: Type[Order], created: bool, **kwargs):
    """
    отправяем письмо при изменении статуса заказа
    """

    # send an e-mail to the user
    user = User.objects.get(id=instance.user.id)
    superuser = User.objects.get(email='admin@mail.ru')

    msg = EmailMultiAlternatives(
        # title:
        f"Обновление статуса заказа № {instance.pk}",
        # message:
        f'Заказ № {instance.pk} сформирован',
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [user.email, superuser.email]
    )
    msg.send()


@receiver(new_order)
def handle_new_order_signal(sender=Order, **kwargs):
    send_confirmation_order_instance = SendConfirmationOrder()
    send_confirmation_order_instance.post(request=kwargs['request'])
