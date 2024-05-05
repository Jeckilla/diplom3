from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (User, Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
                 ConfirmEmailToken, Contact)

class ContactInline(admin.TabularInline):
    model = Contact
    extra = 1


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Панель управления пользователями
    """
    model = User
    inlines = (ContactInline, )

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


class ProductParameterInline(admin.TabularInline):
    model = ProductParameter
    fields = ['product_info', 'parameter', 'value']


@admin.register(ProductParameter)
class ProductParameterAdmin(admin.ModelAdmin):
    list_display = ['id', 'product_info', 'parameter', 'value']
    list_filter = ['product_info', 'parameter']


class ProductInfoInline(admin.TabularInline):
    model = ProductInfo
    fields = ['product', 'quantity', 'price', 'price_rrc', 'shop', 'model', 'external_id']
    extra = 1


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    inlines = [ProductInfoInline, ]
    list_display = ['id', 'name', 'category']
    list_filter = ['category',]


@admin.register(ProductInfo)
class ProductInfoAdmin(admin.ModelAdmin):
    inlines = [ProductParameterInline, ]
    list_display = ['product', 'quantity', 'price', 'price_rrc']
    list_filter = ['quantity', 'price']


@admin.register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    inline = [ProductParameterInline, ]
    list_display = ['name']


class OrderItemInline(admin.TabularInline):
    model = OrderItem
    fields = ['shop', 'product_info', 'quantity']


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    inlines = [OrderItemInline, ]
    list_display = ['id', 'created_at', 'state', 'user', 'contact']


@admin.register(ConfirmEmailToken)
class ConfirmEmailTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'key', 'created_at',]
