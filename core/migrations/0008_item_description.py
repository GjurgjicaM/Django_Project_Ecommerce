# Generated by Django 5.0.7 on 2024-09-23 21:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_item_image_url'),
    ]

    operations = [
        migrations.AddField(
            model_name='item',
            name='description',
            field=models.TextField(default=' '),
            preserve_default=False,
        ),
    ]