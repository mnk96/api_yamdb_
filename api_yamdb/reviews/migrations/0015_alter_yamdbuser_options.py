# Generated by Django 3.2 on 2023-06-21 19:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('reviews', '0014_auto_20230621_2158'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='yamdbuser',
            options={'ordering': ['username']},
        ),
    ]
