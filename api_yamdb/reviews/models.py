"""Модели приложения reviews."""
from django.contrib.auth import get_user_model
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


User = get_user_model()


class Category(models.Model):
    """Модель категорий произведений."""
    name = models.CharField("Category name", max_length=256)
    slug = models.SlugField(max_length=50, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('name',)


class Genre(models.Model):
    """Модель жанров произведений."""
    name = models.CharField("Genre name", max_length=256)
    slug = models.SlugField(max_length=50, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('name',)


class Title(models.Model):
    """Модель произведений."""
    name = models.CharField("Title name", max_length=256)
    year = models.PositiveIntegerField(verbose_name="Title year")
    description = models.TextField(blank=True,
                                   verbose_name="Description titles")
    genre = models.ManyToManyField(
        Genre, blank=True,
        related_name='titles')
    category = models.ForeignKey(
        Category, blank=True, null=True,
        on_delete=models.SET_NULL,
        related_name='titles')

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('-id',)


class Review(models.Model):
    """Модель отзывов."""
    title = models.ForeignKey(Title,
                              on_delete=models.CASCADE,
                              related_name='reviews_title')
    text = models.TextField("Review text")
    pub_date = models.DateTimeField(auto_now_add=True)
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='reviews_author')
    score = models.PositiveSmallIntegerField(
        validators=(MinValueValidator(1), MaxValueValidator(10))
    )

    class Meta:
        ordering = ('-pub_date',)
        constraints = (
            models.UniqueConstraint(
                fields=('title', 'author'),
                name='unique_title_author'
            ),
        )


class Comment(models.Model):
    """Модель комментариев к отзывам."""
    review = models.ForeignKey(
        Review,
        on_delete=models.CASCADE,
        related_name='comments_review')
    text = models.TextField("Comment text")
    pub_date = models.DateTimeField(auto_now_add=True)
    author = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='comments_author')

    class Meta:
        ordering = ('-pub_date',)
