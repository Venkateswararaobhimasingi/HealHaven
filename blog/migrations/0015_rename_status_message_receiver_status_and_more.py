# Generated by Django 5.1.4 on 2025-01-01 08:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0014_remove_message_roll_number'),
    ]

    operations = [
        migrations.RenameField(
            model_name='message',
            old_name='status',
            new_name='receiver_status',
        ),
        migrations.AddField(
            model_name='message',
            name='sender_status',
            field=models.CharField(default='unread', max_length=20),
        ),
    ]
