# Generated by Django 5.1.4 on 2025-01-02 16:25

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0016_emergencymessage'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RenameField(
            model_name='emergencymessage',
            old_name='response',
            new_name='reply',
        ),
        migrations.RemoveField(
            model_name='emergencymessage',
            name='accepted_by',
        ),
        migrations.RemoveField(
            model_name='emergencymessage',
            name='department',
        ),
        migrations.RemoveField(
            model_name='emergencymessage',
            name='receiver_role',
        ),
        migrations.RemoveField(
            model_name='emergencymessage',
            name='rejected_by',
        ),
        migrations.AddField(
            model_name='emergencymessage',
            name='sender_department',
            field=models.CharField(default='Unknown', max_length=100),
        ),
        migrations.AddField(
            model_name='emergencymessage',
            name='sender_phone_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
        migrations.AddField(
            model_name='emergencymessage',
            name='sender_roll_number',
            field=models.CharField(default='000000', max_length=50),
        ),
        migrations.AddField(
            model_name='emergencymessage',
            name='sent_to_role',
            field=models.CharField(default='student', max_length=50),
        ),
        migrations.AddField(
            model_name='emergencymessage',
            name='sent_to_user',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='emergency_received', to=settings.AUTH_USER_MODEL),
        ),
    ]
