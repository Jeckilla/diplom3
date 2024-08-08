from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (User, Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
                 ConfirmEmailToken, Contact)


class ContactInline(admin.TabularInline):
    model = Contact
    extra = 1
    classes = ('collapse-entry', 'expand-first',)


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Панель управления пользователями
    """
    model = User
    inlines = (ContactInline, )

    fieldsets = (
        (None, {'fields': ('username', 'email', 'password', 'type')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'company', 'position')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff']


@admin.register(Shop)
class ShopAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'url', 'user', 'state', 'filename']
    list_filter = ['name', 'state']


class ProductParameterInline(admin.TabularInline):
    model = ProductParameter
    fields = ['id', 'product_info', 'parameter', 'value']


@admin.register(ProductParameter)
class ProductParameterAdmin(admin.ModelAdmin):
    list_display = ['id', 'product_info', 'parameter', 'value']
    list_filter = ['product_info', 'parameter']


class ProductInfoInline(admin.TabularInline):
    model = ProductInfo
    fields = ['id', 'product', 'quantity', 'price', 'price_rrc', 'shop', 'model', 'external_id']
    extra = 1


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    inlines = [ProductInfoInline, ]
    list_display = ['id', 'name', 'category']
    list_filter = ['category']


class ProductInline(admin.TabularInline):
    model = Product
    fields = ['name', 'category']
    extra = 1


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    inlines = [ProductInline, ]
    list_display = ['id', 'name']
    list_filter = ['name',]


@admin.register(ProductInfo)
class ProductInfoAdmin(admin.ModelAdmin):
    inlines = [ProductParameterInline, ]
    list_display = ['id', 'product', 'shop', 'model', 'quantity', 'price', 'price_rrc']
    list_filter = ['shop', 'model', 'quantity', 'price']


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


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ['user', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'phone']
    list_filter = ['city', 'street', 'house', 'structure', 'building']



@admin.register(ConfirmEmailToken)
class ConfirmEmailTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'key', 'created_at',]
