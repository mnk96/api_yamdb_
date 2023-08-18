"""Разрешения для YaMDb API."""
from rest_framework.permissions import BasePermission, SAFE_METHODS

from users.models import YaMDbUser


class IsAdmin(BasePermission):
    """Разрешение на чтение и редактирование только администратору."""
    def has_permission(self, request, view):
        return (request.user.role == YaMDbUser.Roles.ADMIN
                or request.user.is_superuser)


class ReadOnly(BasePermission):
    """Разрешение только на чтение."""
    def has_permission(self, request, view):
        return request.method in SAFE_METHODS


class IsAdminOrReadOnly(BasePermission):
    """Разрешение на редактирование только администратору."""
    def has_permission(self, request, view):
        is_admin = (request.user.role == YaMDbUser.Roles.ADMIN
                    or request.user.is_superuser)
        return request.method in SAFE_METHODS or is_admin


class IsManagerOrReadOnly(BasePermission):
    """Разрешение на редактирование менеджеру контента."""
    def has_object_permission(self, request, view, obj):
        return (request.method in SAFE_METHODS
                or request.user.role != YaMDbUser.Roles.USER)


class IsAuthorOrReadOnly(BasePermission):
    """Разрешение на редактирование автору контента."""
    def has_object_permission(self, request, view, obj):
        return request.method in SAFE_METHODS or obj.author == request.user
