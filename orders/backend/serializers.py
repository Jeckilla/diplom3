from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework.fields import ListField, JSONField

from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User, Contact)
from rest_framework.authtoken.models import Token
from rest_framework.validators import ValidationError


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


class CategorySerializer(serializers.ModelSerializer):
    """Сериализатор категории"""
    class Meta:
        model = Category
        fields = ['id', 'name']


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ('name', 'category',)


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value',)


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)

    class Meta:
        model = ProductInfo
        fields = ('id', 'model', 'product', 'shop', 'quantity', 'price', 'price_rrc', 'product_parameters',)
        read_only_fields = ('id',)


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


class OrderItemSerializer(serializers.ModelSerializer):
    """Сериализатор корзины"""

    product_info = ProductInfoSerializer(read_only=True)
    shop = serializers.SlugRelatedField(queryset=Shop.objects.all(), slug_field='name')

    class Meta:
        model = OrderItem
        fields = ['order', 'shop', 'product_info', 'quantity']
        read_only_fields = ('id',)
        extra_kwargs = {
            'order': {'write_only': True}
        }


class OrderItemCreateSerializer(serializers.ModelSerializer):
    product_info = ProductInfoSerializer(read_only=True, many=True)

    class Meta:
        model = OrderItem
        fields = ['order', 'product_info', 'quantity']
        read_only_fields = ('id',)
        extra_kwargs = {
            'order': {'write_only': True}
        }

class OrderSerializer(serializers.ModelSerializer):
    """Сериализатор заказа"""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    contact = serializers.SerializerMethodField(method_name='get_contact_for_order')
    ordered_items = serializers.SerializerMethodField(method_name='get_ordered_items_for_order')

    def create(self, validated_data):
        user = self.context['request'].user
        validated_data['user'] = user
        return Order.objects.create(**validated_data)

    def get_contact_for_order(self, obj):
        if obj.contact:
            return (f"{obj.contact.city}, {obj.contact.street}, {obj.contact.house}, {obj.contact.structure}, "
                    f"{obj.contact.building}, {obj.contact.apartment}, {obj.contact.phone}")

    def get_ordered_items_for_order(self, obj):
        return OrderItemSerializer(obj.ordered_items, many=True).data

    class Meta:
        model = Order
        fields = ['id', 'user', 'created_at', 'state', 'contact', 'ordered_items']
        read_only_fields = ('id','user', 'created_at')


class UserSerializer(serializers.ModelSerializer):
    """Сериализатор пользователя"""
    contacts = ContactSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'username', 'company', 'position', 'type', 'contacts']

