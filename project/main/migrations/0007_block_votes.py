# Generated by Django 4.2.2 on 2023-06-14 01:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0006_vote_delete_wallet'),
    ]

    operations = [
        migrations.AddField(
            model_name='block',
            name='votes',
            field=models.IntegerField(default=1),
            preserve_default=False,
        ),
    ]
