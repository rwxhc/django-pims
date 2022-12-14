# Generated by Django 3.2 on 2022-07-03 09:01

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserPassword',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('simple_password', models.CharField(max_length=512)),
                ('prompt_simple_password', models.CharField(max_length=512)),
                ('private_password', models.CharField(max_length=512)),
                ('prompt_private_password', models.CharField(max_length=512)),
                ('recover_password', models.CharField(max_length=512)),
                ('prompt_recover_password', models.CharField(max_length=512)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserData',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('data_level', models.IntegerField(default=0)),
                ('date_desc', models.CharField(max_length=512)),
                ('date_content', models.CharField(max_length=8192)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
