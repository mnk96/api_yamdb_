# Generated by Django 3.2 on 2023-06-18 12:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reviews', '0004_auto_20230617_0106'),
    ]

    operations = [
        migrations.AlterField(
            model_name='yamdbuser',
            name='role',
            field=models.CharField(blank=True, choices=[('U', 'user'), ('M', 'moderator'), ('A', 'admin')], default='U', max_length=1),
        ),
    ]