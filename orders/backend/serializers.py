from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User, Contact)
from rest_framework.authtoken.models import Token
from rest_framework.validators import ValidationError


class UserSerializer(serializers.ModelSerializer):
    """Сериализатор пользователя"""
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'username', 'company', 'position', 'type']


class SignUpSerializer(serializers.ModelSerializer):
    """Сериализатор для входа в систему"""
    first_name = serializers.CharField(max_length=100, style={'placeholder': 'Имя'})
    last_name = serializers.CharField(max_length=100, style={'placeholder': 'Фамилия'})
    email = serializers.EmailField(max_length=80, style={'placeholder': 'Email', 'autofocus': True})
    username = serializers.CharField(max_length=80, style={'placeholder': 'Username', 'autofocus': True})
    password = serializers.CharField(min_length=6, style={'input_type': 'password', 'placeholder': 'Password'}, max_length=20, write_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password']

    def validate(self, attrs):
        email_exists = User.objects.filter(email=attrs['email']).exists()

        if email_exists:
            raise ValidationError("Email is already been used.")
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = super().create(validated_data)
        user.set_password(password)
        Token.objects.create(user=user)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(
        max_length=100,
        style={'placeholder': 'Email', 'autofocus': True}
    )
    password = serializers.CharField(
        max_length=100,
        style={'input_type': 'password', 'placeholder': 'Password'}
    )



class ShopSerializer(serializers.ModelSerializer):
    """Сериализатор магазина"""
    url = serializers.URLField(max_length=300,
                               style={'placeholder': 'Email'},
                               allow_blank=True)
    filename = serializers.FileField(use_url=True, allow_empty_file=True)

    class Meta:
        model = Shop
        fields = ['name', 'url', 'filename']


class UpdatePartnerSerializer(serializers.ModelSerializer):
    """Сериализатор для обновления информации о товарах магазина"""
    url = serializers.URLField(max_length=300,
                               style={'placeholder': 'Email'},
                               allow_blank=True)
    class Meta:
        model = Shop
        fields = ['name', 'url']


class ProductInfoSerializer(serializers.ModelSerializer):
    """Сериализатор информации о продукте"""
    shop = serializers.SlugRelatedField(queryset=Shop.objects.all(), slug_field='name', allow_null=True)
    model = serializers.CharField(max_length=80, allow_blank=True)
    quantity = serializers.IntegerField()
    price = serializers.IntegerField()
    class Meta:
        model = ProductInfo
        fields = ['shop', 'model', 'price', 'quantity']


class ProductSerializer(serializers.ModelSerializer):
    """Сериализатор продукта"""
    name = serializers.CharField(max_length=100)
    category = serializers.SlugRelatedField(queryset=Category.objects.all(), slug_field='name')
    product_info = ProductInfoSerializer(many=True)

    class Meta:
        model = Product
        fields = ['name', 'category',
                  'product_info']


class OrdersSerializer(serializers.ModelSerializer):
    """Сериализатор заказа"""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    contact = serializers.HiddenField(default=serializers.CurrentUserDefault())
    class Meta:
        model = Order
        fields = ['id', 'created_at', 'state']


class ContactSerializer(serializers.ModelSerializer):
    """Сериализатор контактов пользователя"""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    city = serializers.CharField(max_length=50)
    street = serializers.CharField(max_length=100)
    house = serializers.CharField(max_length=15)
    structure = serializers.CharField(max_length=15)
    building = serializers.CharField(max_length=15)
    apartment = serializers.CharField(max_length=15)
    phone = serializers.CharField(max_length=11)
    class Meta:
        model = Contact
        fields = ['user', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'phone']

    def create(self, validated_data):
        return super().create(validated_data)
