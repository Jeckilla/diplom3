from rest_framework import serializers
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User)
from rest_framework.authtoken.models import Token


class UserSerializer(serializers.ModelSerializer):
    """Сериализатор пользователя"""
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'username', 'company', 'position', 'type']


class SignUpSerializer(serializers.ModelSerializer):
    """Сериализатор для входа в систему"""
    email = serializers.EmailField(max_length=80)
    username = serializers.CharField(max_length=80)
    password = serializers.CharField(min_length=6, max_length=20, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = super().create(validated_data)
        user.set_password(password)
        Token.objects.create(user=user)
        user.save()
        return user


class ShopSerializer(serializers.ModelSerializer):
    """Сериализатор магазина"""
    filename = serializers.FileField(use_url=True, allow_empty_file=True)

    class Meta:
        model = Shop
        fields = ['name', 'url', 'filename']
