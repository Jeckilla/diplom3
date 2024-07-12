from django.core.mail import send_mail
from django.template.loader import get_template
from .models import User



def send_confirmation_email(email, token_id, token_key, user_id, auth_token):
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