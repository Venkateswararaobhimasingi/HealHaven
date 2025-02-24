# Generated by Django 5.1.4 on 2024-12-20 17:14

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0002_otp'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='StudentProfileDetails',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('roll_number', models.CharField(max_length=20, unique=True)),
                ('studying_year', models.IntegerField(default=1)),
                ('department', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('phone_number', models.CharField(max_length=15)),
                ('parents_number', models.CharField(max_length=15)),
                ('role', models.CharField(default='student', max_length=20)),
                ('image', models.ImageField(default='default.jpg', upload_to='profile_pics')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='student_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='TeacherProfileDetails',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('roll_number', models.CharField(max_length=20, unique=True)),
                ('department', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254)),
                ('phone_number', models.CharField(blank=True, max_length=15, null=True)),
                ('role', models.CharField(default='teacher', max_length=20)),
                ('image', models.ImageField(default='default.jpg', upload_to='profile_pics')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='teacher_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.DeleteModel(
            name='Profile',
        ),
    ]
