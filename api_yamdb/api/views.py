"""Вьюсеты приложения api."""
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.db.models import Avg
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, response, status
from rest_framework.decorators import action
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import (AllowAny,
                                        IsAuthenticated,
                                        IsAuthenticatedOrReadOnly,
                                        SAFE_METHODS)
from rest_framework.viewsets import GenericViewSet, mixins, ModelViewSet
from rest_framework_simplejwt.tokens import RefreshToken

from api import serializers
from api.filters import TitleFilter
from api.permissions import (ReadOnly,
                             IsAdmin,
                             IsAuthorOrReadOnly,
                             IsManagerOrReadOnly)
from api.utils import EmailUtils
from reviews import models
from users import models as user_models


class UserViewSet(ModelViewSet):
    """Вьюсет для модели пользователя."""
    queryset = user_models.YaMDbUser.objects.all()
    serializer_class = serializers.UserSerializer
    permission_classes = (IsAuthenticated & IsAdmin,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('username',)
    lookup_field = 'username'
    http_method_names = ('get', 'post', 'delete', 'patch', 'head', 'options')

    def get_object(self):
        lookup = self.kwargs.get(UserViewSet.lookup_field)

        if lookup == "me":
            return self.request.user

        return super().get_object()

    @action(detail=False, methods=['get', 'patch'],
            permission_classes=[IsAuthenticated])
    def me(self, request):
        serializer_class = serializers.OwnUserSerializer
        if request.method == 'PATCH':
            serializer = serializer_class(self.request.user,
                                          data=request.data,
                                          partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return response.Response(serializer.validated_data,
                                     status=status.HTTP_200_OK)
        serializer = serializer_class(self.request.user)
        return response.Response(serializer.data, status=status.HTTP_200_OK)


class SignUpView(GenericAPIView):
    """Вью для регистрации пользователя."""
    serializer_class = serializers.SignUpSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_email, _ = user_models.YaMDbUser.objects.get_or_create(
            username=serializer.validated_data['username'],
            email=serializer.validated_data['email'])

        user_email.confirmation_code = get_random_string(
            length=settings.CONFIRM_CODE_LEN)
        user_email.save()

        email_template = 'confirmation_code_email.html'
        email_body = render_to_string(email_template, {'user': user_email})
        data = {'email_body': email_body, 'to_email': user_email.email,
                'email_subject': 'Verify your email'}

        EmailUtils.send_email(data=data)

        return response.Response(
            {'email': user_email.email, 'username': user_email.username},
            status=status.HTTP_200_OK)


class RefreshTokenView(GenericAPIView):
    """Вью для получения токена."""
    serializer_class = serializers.RefreshTokenSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        credentials_data = serializer.data

        user = get_object_or_404(user_models.YaMDbUser,
                                 username=credentials_data['username'])
        if user.confirmation_code != credentials_data['confirmation_code']:
            return response.Response({'confirmation_code':
                                      'Wrong confirmation code'},
                                     status=status.HTTP_400_BAD_REQUEST)

        token = RefreshToken.for_user(user).access_token
        return response.Response({'token': str(token)},
                                 status=status.HTTP_200_OK)


class BaseCategoriesViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    GenericViewSet
):
    """Базовый вьюсет для категорий и жанров."""
    permission_classes = (ReadOnly | (IsAuthenticated & IsAdmin),)
    lookup_field = 'slug'
    filter_backends = (filters.SearchFilter,)
    search_fields = ('name',)


class CategoriesViewSet(BaseCategoriesViewSet):
    """Вьюсет для категорий."""
    queryset = models.Category.objects.all()
    serializer_class = serializers.CategoriesSerializer


class GenresViewSet(BaseCategoriesViewSet):
    """Вьюсет для жанров."""
    queryset = models.Genre.objects.all()
    serializer_class = serializers.GenresSerializer


class TitlesViewSet(ModelViewSet):
    """Вьюсет для произведений."""
    queryset = models.Title.objects.annotate(
        rating=Avg('reviews_title__score'))
    permission_classes = (ReadOnly | (IsAuthenticated & IsAdmin),)
    filterset_class = TitleFilter
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ('category', 'genre', 'name', 'year')

    def get_serializer_class(self):
        if self.request.method in SAFE_METHODS:
            return serializers.TitleViewSerializer
        return serializers.TitleWriteSerializer


class ReviewsViewSet(ModelViewSet):
    """Вьюсет для отзывов."""
    serializer_class = serializers.ReviewsSerializer
    permission_classes = (IsAuthenticatedOrReadOnly
                          & (IsAuthorOrReadOnly | IsManagerOrReadOnly),)

    def get_title_or_404(self):
        title_id = self.kwargs.get('title_id')
        return get_object_or_404(models.Title, id=title_id)

    def get_queryset(self):
        title = self.get_title_or_404()
        return title.reviews_title.all()

    def perform_create(self, serializer):
        serializer.save(author=self.request.user,
                        title=self.get_title_or_404())


class CommentViewSet(ModelViewSet):
    """Вьюсет для комментариев."""
    serializer_class = serializers.CommentSerializer
    permission_classes = (IsAuthenticatedOrReadOnly
                          & (IsAuthorOrReadOnly | IsManagerOrReadOnly),)

    def get_review_or_404(self):
        review_id = self.kwargs.get('review_id')
        return get_object_or_404(models.Review, id=review_id)

    def get_queryset(self):
        review = self.get_review_or_404()
        return review.comments_review.all()

    def perform_create(self, serializer):
        serializer.save(author=self.request.user,
                        review=self.get_review_or_404())
