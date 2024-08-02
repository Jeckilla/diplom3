from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework.fields import ListField, JSONField

from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User, Contact)
from rest_framework.authtoken.models import Token
from rest_framework.validators import ValidationError


class SignUpSerializer(serializers.ModelSerializer):
    """Serializer for registration"""
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
    """Serializer for login"""
    email = serializers.EmailField(
        max_length=100,
        style={'placeholder': 'Email', 'autofocus': True}
    )
    password = serializers.CharField(
        max_length=100,
        style={'input_type': 'password', 'placeholder': 'Password'}
    )



class ShopSerializer(serializers.ModelSerializer):
    """Serializer of shops"""
    url = serializers.URLField(max_length=300,
                               style={'placeholder': 'Email'},
                               allow_blank=True)
    filename = serializers.FileField(use_url=True, allow_empty_file=True)

    class Meta:
        model = Shop
        fields = ['name', 'url', 'filename']


class UpdatePartnerSerializer(serializers.ModelSerializer):
    """Serializer for updating info about products of the shop"""
    url = serializers.URLField(max_length=300,
                               style={'placeholder': 'Email'},
                               allow_blank=True)
    class Meta:
        model = Shop
        fields = ['name', 'url']


class CategorySerializer(serializers.ModelSerializer):
    """Serializer of categories"""
    class Meta:
        model = Category
        fields = ['id', 'name']


class ProductSerializer(serializers.ModelSerializer):
    """Serializer of products"""
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ('id', 'name', 'category',)


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value',)


class ProductInfoSerializer(serializers.ModelSerializer):
    """Serializer of product info"""
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)

    class Meta:
        model = ProductInfo
        fields = ('id', 'model', 'product', 'shop', 'quantity', 'price', 'price_rrc', 'product_parameters',)
        read_only_fields = ('id',)


class ContactSerializer(serializers.ModelSerializer):
    """Serializer for contacts of users"""
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
        fields = ['id', 'user', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'phone']

    def create(self, validated_data):
        return super().create(validated_data)


class OrderItemSerializer(serializers.ModelSerializer):
    """Serializer of basket items"""

    product_info = ProductInfoSerializer(read_only=True)
    shop = serializers.SlugRelatedField(queryset=Shop.objects.all(), slug_field='name')

    class Meta:
        model = OrderItem
        fields = ['order', 'product_info', 'shop', 'quantity']
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
    """Serializer of order"""
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    contact = ContactSerializer(write_only=True)
    product_ids = serializers.ListField(child=serializers.IntegerField(), write_only=True)
    ordered_items = serializers.SerializerMethodField(method_name='get_ordered_items_for_order')
    get_total_cost = serializers.SerializerMethodField()

    def get_total_cost(self, obj):
        return obj.get_total_cost()

    def create(self, validated_data):
        product_ids = validated_data.pop('product_ids')

        self.user = self.context['request'].user

        contact = validated_data.pop('contact')
        if self.user.is_authenticated:
            contact['user'] = self.user

        # Check if a Contact with the same unique fields already exists
        existing_contact = Contact.objects.filter(city=contact['city'], street=contact['street'],
                                                house=contact['house'], apartment=contact['apartment']).first()

        if existing_contact:
            contact_instance = existing_contact
        else:
            contact_instance = Contact.objects.create(**contact)

        order = Order.objects.create(contact=contact_instance, **validated_data)

        for product_id in product_ids:
            product = ProductInfo.objects.get(id=product_id)  # Access the correct attribute containing product_id
            ordered_item = OrderItem.objects.create(order=order,
                                                    shop=product.shop,
                                                    product_info=product,
                                                    quantity=1)  # Set quantity as needed
            product.quantity -= 1
            product.save()
            if product.quantity == 0:
                ordered_item.delete()

        return order

    def get_contact_for_order(self, instance, *args, **kwargs):
        if self.user.contact:
            return (f"{self.user.contact.city}, {self.user.contact.street}, {self.user.contact.house}, "
                    f"{self.user.contact.structure}, {self.user.contact.building},"
                    f" {self.user.contact.apartment}, {self.user.contact.phone}")

    def get_ordered_items_for_order(self, obj):
        return OrderItemSerializer(obj.ordered_items, many=True).data


    class Meta:
        model = Order
        fields = ['id', 'user', 'created_at', 'state', 'contact', 'product_ids', 'get_total_cost', 'ordered_items']
        read_only_fields = ('id', 'user', 'created_at')


class UserSerializer(serializers.ModelSerializer):
    """Serializer of user"""
    contacts = ContactSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name',
                  'username', 'company', 'position', 'type', 'contacts', 'email_confirm', 'is_active']

