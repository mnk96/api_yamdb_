"""Сериализаторы для YaMDb API."""
from django.conf import settings
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db.models import Q
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from reviews import models
from users import models as user_models


class QQ(Q):
    """Комбинатор фильтров с поддержкой XOR."""
    def __xor__(self, other):
        not_self = ~self
        not_other = ~other
        x = self & not_other
        y = not_self & other

        return x | y


class ChoiceField(serializers.ChoiceField):
    """Кастомное поле выбора.
    Переводит репрезентативные значения в внутренние."""
    def to_representation(self, obj):
        if obj == '' and self.allow_blank:
            return obj

        choice = self._choices.get(obj)
        if choice:
            return choice
        self.fail('invalid_choice', input=obj)

    def to_internal_value(self, data):
        if data == '' and self.allow_blank:
            return ''

        for key, val in self._choices.items():
            if val == data:
                return key
        self.fail('invalid_choice', input=data)


class UserSerializer(serializers.ModelSerializer):
    """Сериализатор для модели YaMDbUser."""
    role = ChoiceField(choices=user_models.YaMDbUser.Roles.choices,
                       required=False)

    class Meta:
        fields = ('username', 'email', 'first_name',
                  'last_name', 'bio', 'role')
        model = user_models.YaMDbUser

    def validate(self, attrs):
        username = attrs.get('username')
        if username == 'me':
            raise ValidationError("Имя 'me' зарезервированно.")
        return super().validate(attrs)


class OwnUserSerializer(UserSerializer):
    """Сериализатор для модели YaMDbUser.
    Вариант для обработки своего пользователя."""
    role = ChoiceField(choices=user_models.YaMDbUser.Roles.choices,
                       required=False,
                       read_only=True)


class SignUpSerializer(serializers.Serializer):
    """Сериализатор для модели YaMDbUser.
    Вариант для регистрации нового пользователя."""
    username_validator = UnicodeUsernameValidator()

    username = serializers.CharField(max_length=150,
                                     validators=[username_validator])
    email = serializers.EmailField(max_length=254)

    def validate(self, attrs):
        username = attrs.get('username', '')
        if username == 'me':
            raise ValidationError("Имя 'me' зарезервированно.")

        email = attrs.get('email', '')
        users = user_models.YaMDbUser.objects.filter(
            QQ(username=username) ^ QQ(email=email)).all()
        if users:
            if users.first().username == username:
                raise ValidationError("Имя уже используются.")
            raise ValidationError("Почта уже используются.")
        return super().validate(attrs)


class RefreshTokenSerializer(serializers.Serializer):
    """Сериализатор для параметров генерации токена."""
    username = serializers.CharField(max_length=128)
    confirmation_code = serializers.CharField(
        max_length=settings.CONFIRM_CODE_LEN)


class CategoriesSerializer(serializers.ModelSerializer):
    """Сериализатор для модели Category."""

    class Meta:
        model = models.Category
        fields = ('name', 'slug')


class GenresSerializer(serializers.ModelSerializer):
    """Сериализатор для модели Genre."""

    class Meta:
        model = models.Genre
        fields = ('name', 'slug')


class TitleWriteSerializer(serializers.ModelSerializer):
    """Сериализатор для модели Title."""
    genre = serializers.SlugRelatedField(
        many=True, slug_field='slug', queryset=models.Genre.objects.all()
    )
    category = serializers.SlugRelatedField(
        slug_field='slug', queryset=models.Category.objects.all()
    )

    class Meta:
        model = models.Title
        fields = ('id', 'name', 'year', 'description', 'genre', 'category')

    def validate_year(self, value):
        if value > timezone.now().year:
            raise serializers.ValidationError(
                'Нельзя указать год больше текущего.')
        return value


class TitleViewSerializer(serializers.ModelSerializer):
    """Сериализатор для модели Title (только для чтения)."""
    genre = GenresSerializer(many=True)
    category = CategoriesSerializer()
    rating = serializers.FloatField(read_only=True)

    class Meta:
        model = models.Title
        fields = '__all__'


class CommentSerializer(serializers.ModelSerializer):
    """Сериализатор для модели Comment."""
    author = serializers.SlugRelatedField(read_only=True,
                                          slug_field='username')

    class Meta:
        fields = '__all__'
        model = models.Comment
        read_only_fields = ('review',)


class ReviewsSerializer(serializers.ModelSerializer):
    """Сериализатор для модели Review."""
    author = serializers.SlugRelatedField(read_only=True,
                                          slug_field='username')

    class Meta:
        fields = '__all__'
        model = models.Review
        read_only_fields = ('title',)

    def validate(self, data):
        request = self.context['request']
        if request.method == 'POST':
            title = self.context['view'].kwargs['title_id']
            reviews = request.user.reviews_author.filter(title=title)
            if reviews.exists():
                raise serializers.ValidationError(
                    'К одному произведению можно оставлять только один отзыв.'
                )
        return data
