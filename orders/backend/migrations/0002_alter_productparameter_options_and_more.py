# Generated by Django 5.0.4 on 2024-04-22 19:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='productparameter',
            options={'verbose_name': 'Параметры товара', 'verbose_name_plural': 'Список параметров товара'},
        ),
        migrations.AlterField(
            model_name='productinfo',
            name='price',
            field=models.PositiveIntegerField(verbose_name='Цена'),
        ),
        migrations.AlterField(
            model_name='productinfo',
            name='price_rrc',
            field=models.PositiveIntegerField(verbose_name='Цена_ррц'),
        ),
    ]
