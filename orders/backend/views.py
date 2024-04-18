from django.core.validators import URLValidator
from django.http import JsonResponse
from django.shortcuts import render
from requests import get
from rest_framework.exceptions import ValidationError
from rest_framework.status import HTTP_401_UNAUTHORIZED
from rest_framework.views import APIView
from ujson import loads as load_json
from yaml import load as load_yaml, Loader

from .serializers import ShopSerializer
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User)


class PartnerUpdate(APIView):
    def post(self, request, filename, *args, **kwargs):
        filename = input('Enter file name: ')
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type == 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        with open(f'fixtures/{filename}', 'r') as stream:
            data = load_yaml(stream, Loader=Loader)
            shop, _ = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)
            for category in data['categories']:
                category_obj, _ = Category.objects.get_or_create(id=category.id, name=category['name'])
                category_obj.shops.add(shop.id)
                category_obj.save()

            ProductInfo.objects.filter(shop_id=shop.id).delete()

            for product in data['goods']:
                product_obj, _ = Product.objects.get_or_create(name=product['name'], category_id=product['category_id'])
                product_info_obj, _ = ProductInfo.objects.create(
                        product_id=product_obj.id,
                        shop_id=shop.id,
                        model=product['model'],
                        external_id=product['id'],
                        quantity=product['quantity'],
                        price=product['price'],
                        price_rrc=product['price_rrc'],
                    )
                for name, value in product['parameters'].items():
                    parameter_obj, _ = Parameter.objects.get_or_create(name=name)
                    ProductParameter.objects.create(
                            product_info_id=product_info_obj.id,
                            parameter_id=parameter_obj.id,
                            value=value
                        )
                return JsonResponse({'status': True})
            return JsonResponse({'status': False,  'errors': 'Не указаны все необходимые аргументы'})


class ShopList(APIView):
    def get(self, request):
        shops = Shop.objects.all()
        serializer = ShopSerializer(shops, many=True)
        return JsonResponse(serializer.data, safe=False)

class ShopDetails(APIView):
    def get(self, request):
        shops = Shop.objects.filter(user_id=request.shop.id)
        serializer = ShopSerializer(shops, many=True)
        return JsonResponse(serializer.data, safe=False)



