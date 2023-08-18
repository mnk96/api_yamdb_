"""Эндпоинты приложения api."""
from django.urls import include, path
from rest_framework import routers

from api import views


router = routers.DefaultRouter()

router.register(r'users', views.UserViewSet)
router.register(r'categories', views.CategoriesViewSet, basename='categories')
router.register(r'genres', views.GenresViewSet, basename='genres')
router.register(r'titles', views.TitlesViewSet, basename='titles')
router.register(r'titles/(?P<title_id>\d+)/reviews',
                views.ReviewsViewSet, basename='review')
router.register(
    r'titles/(?P<title_id>\d+)/reviews/(?P<review_id>\d+)/comments',
    views.CommentViewSet, basename='comment')

urlpatterns = [
    path('v1/', include(router.urls)),
    path('v1/auth/signup/', views.SignUpView.as_view(), name='signup'),
    path('v1/auth/token/', views.RefreshTokenView.as_view(), name='token'),
]
