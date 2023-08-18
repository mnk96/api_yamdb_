"""Вспомогательные функции."""
from django.core.mail import EmailMessage


class EmailUtils:
    """Вспомогательные функции"""
    @staticmethod
    def send_email(data):
        """Отправка e-mail письма."""
        email = EmailMessage(
            subject=data['email_subject'],
            body=data['email_body'],
            to=[data['to_email']])
        email.send()
