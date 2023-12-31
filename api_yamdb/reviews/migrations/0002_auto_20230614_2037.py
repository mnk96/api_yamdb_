# Generated by Django 3.2 on 2023-06-14 17:37

from django.db import migrations, models


def apply_default_groups(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.bulk_create([
        Group(name=u'moderator'),
        Group(name=u'admin'),
    ])


def revert_default_groups(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(
        name__in=[
            u'moderator',
            u'admin',
        ]
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('reviews', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='yamdbuser',
            name='bio',
            field=models.TextField(blank=True, verbose_name='biography'),
        ),
        migrations.AlterField(
            model_name='yamdbuser',
            name='email',
            field=models.EmailField(error_messages={'unique': 'A user with that email already exists.'}, help_text='Required. 254 characters or fewer.', max_length=254, unique=True, verbose_name='email address'),
        ),
        migrations.RunPython(apply_default_groups, revert_default_groups),
    ]
