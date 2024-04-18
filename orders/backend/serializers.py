from rest_framework import serializers
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User)


class UserSerializer(serializers.ModelSerializer):
    """Сериализатор пользователя"""
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'username', 'company', 'position', 'type']


class ShopSerializer(serializers.ModelSerializer):
    """Сериализатор магазина"""
    filename = serializers.FileField(use_url=True, allow_empty_file=True)

    class Meta:
        model = Shop
        fields = ['name', 'url', 'filename']
