# Generated by Django 3.2 on 2023-06-22 21:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='yamdbuser',
            name='password',
            field=models.CharField(default='passpass123321123', max_length=128, verbose_name='password'),
            preserve_default=False,
        ),
    ]
