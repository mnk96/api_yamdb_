"""Главный файл приложения reviews."""
from django.apps import AppConfig


class ReviewsConfig(AppConfig):
    """Конфигурация приложения."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'reviews'
