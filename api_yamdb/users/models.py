"""Модели приложения users."""
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class YaMDbUser(AbstractUser):
    """Модель пользователя."""
    class Roles(models.TextChoices):
        """Роли пользователей."""
        USER = 'user', 'user'
        MODERATOR = 'moderator', 'moderator'
        ADMIN = 'admin', 'admin'

    bio = models.TextField('biography', blank=True)
    email = models.EmailField(
        'email address',
        max_length=254,
        unique=True,
        help_text='Required. 254 characters or fewer.',
        error_messages={
            'unique': "A user with that email already exists.",
        },)
    role = models.CharField(max_length=9, choices=Roles.choices, blank=True,
                            null=True, default=Roles.USER)
    confirmation_code = models.CharField(max_length=settings.CONFIRM_CODE_LEN,
                                         null=True,
                                         blank=True)

    def __str__(self):
        return self.username

    class Meta:
        ordering = ('username',)
