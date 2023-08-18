# Generated by Django 3.2 on 2023-06-15 17:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reviews', '0002_auto_20230614_2037'),
    ]

    operations = [
        migrations.AddField(
            model_name='yamdbuser',
            name='role',
            field=models.CharField(choices=[('U', 'user'), ('M', 'moderator'), ('A', 'admin')], default='U', max_length=1),
        ),
    ]
