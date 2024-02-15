# Generated by Django 5.0.1 on 2024-02-14 14:18

from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('post', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RenameField(
            model_name='post',
            old_name='post_body',
            new_name='body',
        ),
        migrations.AlterUniqueTogether(
            name='post',
            unique_together={('user', 'created_at')},
        ),
    ]
