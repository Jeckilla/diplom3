from django.core.mail import send_mail
from django.template.loader import get_template
from .models import User


def send_confirmation_email(email, token_id, token_key, user_id, auth_token):

    """Function for sending confirmation email for user that registered"""

    data = {
        'token_id': str(token_id),
        'user_id': str(user_id),
        'token_key': str(token_key),
        'Token': str(auth_token.key),
    }
    message = get_template('confirmation_email.txt').render(data)
    send_mail(subject='Please confirm email',
              message=message,
              from_email='netology.diplom@mail.ru',
              recipient_list=[email],
              fail_silently=True)

def send_confirm_order(email, token_id, token_key, auth_token, order_id, user_id):

    """Function for sending mail for confirmation of order that user made"""

    data = {
        'email': str(email),
        'token_id': str(token_id),
        'token_key': str(token_key),
        'Token': str(auth_token.key),
        'order_id': str(order_id),
        'user_id': str(user_id),
    }
    message = get_template('confirmation_order.txt').render(data)
    send_mail(subject=f'Please confirm your order {order_id}',
              message=message,
              from_email='netology.diplom@mail.ru',
              recipient_list=[email],
              fail_silently=True)