from typing import Type

from celery import shared_task
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django_rest_passwordreset.signals import reset_password_token_created


from .utils import send_confirmation_email
from .models import ConfirmEmailToken, User, Order

@shared_task
def password_reset_token_created_task(reset_password_token_created, **kwargs):

    # send an e-mail to the user

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
def new_order_created_task(instance: Type[Order], created: bool, **kwargs):
    """
    отправяем письмо при изменении статуса заказа
    """

    # send an e-mail to the users
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

@shared_task
def handle_new_order_task(sender=Order, **kwargs):
    from .views import SendConfirmationOrder
    send_confirmation_order_instance = SendConfirmationOrder()
    send_confirmation_order_instance.post(request=kwargs['request'])

@shared_task
def send_confirmation_order_task(instance, confirmation_link, **kwargs):
    order = Order.objects.get(id=instance)
    msg = EmailMultiAlternatives(
        f'Confirm Your Order № {order.id}',
        f'Click the link to confirm your order {order.id}: {confirmation_link}',
        'netology.diplom@mail.ru',
        [order.user.email],
    )
    msg.send()



@shared_task
def send_confirmation_email_task(instance, **kwargs):
    user = User.objects.get(id=instance)
    token = ConfirmEmailToken.objects.create(user=user)
    send_confirmation_email(email=user.email,
                            token_id=token.pk,
                            token_key=token.key,
                            user_id=user.id,
                            auth_token=user.auth_token)
