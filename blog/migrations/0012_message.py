# Generated by Django 5.1.4 on 2025-01-01 07:03

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0011_post_role'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sender_email', models.EmailField(max_length=254)),
                ('receiver_email', models.EmailField(max_length=254)),
                ('sender_role', models.CharField(max_length=50)),
                ('receiver_role', models.CharField(max_length=50)),
                ('subject', models.CharField(max_length=100)),
                ('roll_number', models.CharField(blank=True, max_length=50, null=True)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('content', models.TextField()),
                ('status', models.CharField(default='unread', max_length=20)),
                ('seen_by', models.BooleanField(default=False)),
                ('receiver_author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='received_messages', to=settings.AUTH_USER_MODEL)),
                ('sender_author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_messages', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
