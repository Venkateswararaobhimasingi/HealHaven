# Generated by Django 5.1.4 on 2025-01-01 08:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0012_message'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='message',
            name='seen_by',
        ),
    ]
