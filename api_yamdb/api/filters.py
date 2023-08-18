"""Фильтры проекта api."""
import django_filters

from reviews.models import Title


class TitleFilter(django_filters.FilterSet):
    """Фильтр для модели Title."""
    name = django_filters.CharFilter(field_name='name',
                                     lookup_expr='icontains')
    genre = django_filters.CharFilter(field_name='genre__slug')
    category = django_filters.CharFilter(field_name='category__slug')

    class Meta:
        model = Title
        fields = ('name', 'genre', 'category', 'year')
