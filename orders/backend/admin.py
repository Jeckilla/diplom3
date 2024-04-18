from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (User, Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
                 ConfirmEmailToken, Contact)


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Панель управления пользователями
    """
    model = User

    fieldsets = (
        (None, {'fields': ('email', 'password', 'type')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'company', 'position')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ['email', 'first_name', 'last_name', 'is_staff']


@admin.register(Shop)
class ShopAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'url', 'user', 'state', 'filename']
    list_filter = ['name', 'state']


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'name']
    list_filter = ['name',]


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'category']
    list_filter = ['category',]


@admin.register(ProductInfo)
class ProductInfoAdmin(admin.ModelAdmin):
    list_display = ['product', 'shop', 'quantity', 'price', 'price_rrc']
    list_filter = ['shop', 'quantity', 'price']


@admin.register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    list_display = ['name']


@admin.register(ProductParameter)
class ProductParameterAdmin(admin.ModelAdmin):
    list_display = ['product_info', 'parameter', 'value']
    list_filter = ['parameter',]


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ['user', 'state', 'contact']
    list_filter = ['user', 'state']



@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ['order', 'product', 'shop', 'quantity']
    list_filter = ['order', 'shop', 'quantity']


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ['user', 'city', 'street', 'phone']
    list_filter = ['user', 'city', 'street']


@admin.register(ConfirmEmailToken)
class ConfirmEmailTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'key', 'created_at',]
