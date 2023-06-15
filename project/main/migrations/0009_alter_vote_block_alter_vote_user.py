# Generated by Django 4.2.2 on 2023-06-14 01:46

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('main', '0008_block_validated'),
    ]

    operations = [
        migrations.AlterField(
            model_name='vote',
            name='block',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.block'),
        ),
        migrations.AlterField(
            model_name='vote',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]