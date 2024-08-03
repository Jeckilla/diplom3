from typing import Type

from celery import shared_task
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django_rest_passwordreset.signals import reset_password_token_created


from .utils import send_confirmation_email, send_confirm_order
from .models import ConfirmEmailToken, User, Order

@shared_task
def password_reset_token_created_task(reset_password_token_created, **kwargs):

    # send an e-mail to the user to confirm the reset of the password

    msg = EmailMultiAlternatives(
        # title:
        f"Password Reset Token for {reset_password_token_created.user}",
        # message:
        reset_password_token_created.key,
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [reset_password_token_created.user.email]
    )
    msg.send()


@shared_task
def send_confirmation_order_task(instance, **kwargs):

    """task for sending email to confirm order"""

    order = Order.objects.get(id=instance)
    token = ConfirmEmailToken.objects.create(user=order.user)
    send_confirm_order(email=order.user.email,
                            token_id=token.pk,
                            token_key=token.key,
                            order_id=order.id,
                            auth_token=order.user.auth_token,
                            user_id=order.user.id)

@shared_task
def send_confirmation_email_task(instance, **kwargs):

    """task for sending email to confirm email"""

    user = User.objects.get(id=instance)
    token = ConfirmEmailToken.objects.create(user=user)
    send_confirmation_email(email=user.email,
                            token_id=token.pk,
                            token_key=token.key,
                            user_id=user.id,
                            auth_token=user.auth_token)
