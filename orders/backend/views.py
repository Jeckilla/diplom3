from django.contrib.auth import authenticate
from django.core.validators import URLValidator
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django_filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from requests import get
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.status import HTTP_401_UNAUTHORIZED
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from ujson import loads as load_json
from yaml import load as load_yaml, Loader
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.renderers import TemplateHTMLRenderer

from .permissions import IsOwnerOrReadOnly
# from rest_framework.permissions import permission_classes

from .serializers import ShopSerializer, SignUpSerializer, LoginSerializer, ProductSerializer, OrdersSerializer, \
    ContactSerializer
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User, Contact)


class PartnerUpdate(APIView):
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type == 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        url = request.data.get('url')
        if url:
            validate_url = URLValidator()
            try:
                validate_url(url)
            except ValidationError as e:
                return JsonResponse({'status': False, 'errors': str(e)})
            else:
                stream = get(url).content
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


class SignUpView(generics.GenericAPIView):
    serializer_class = SignUpSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            serializer.save()
            response = {
                "message": f"User created successfuly",
                "data": serializer.data
            }
            return Response(data=response, status=status.HTTP_201_CREATED)

        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    serializer_class = LoginSerializer

    def get(self, request):
        content = {
            'user': str(request.user),
            'auth': str(request.auth),
        }
        return Response(data=content, status=status.HTTP_200_OK)

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(email=email, password=password)

        if user is not None:
            response = {
                'message': 'Login successful',
                'email': user.email,
                'Token': user.auth_token.key,
            }
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            return Response(data={'message': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)


class ProductsList(APIView):
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ['model', ]
    filterset_fields = ['name', 'category', 'model', 'shop', 'price', 'quantity']

    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return JsonResponse(serializer.data, safe=False)


class OrdersList(APIView):

    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            orders = Order.objects.filter(user_id=request.user.id).order_by('-created_at')
            serializer = OrdersSerializer
            return JsonResponse(serializer.data, safe=False)


class ContactViewSet(ModelViewSet):

    queryset = Contact.objects.all()
    serializer_class = ContactSerializer



# class ContactView(APIView):
#
#     def get(self, request):
#         if not request.user.is_authenticated:
#             return JsonResponse({'detail': 'Authentication credentials were not provided.'},
#                                 status=HTTP_401_UNAUTHORIZED)
#         else:
#             contacts = Contact.objects.filter(user_id=request.user.id)
#             serializer = ContactSerializer
#             return JsonResponse(serializer.data, safe=False)
#
#     def post(self, request):
#         if not request.user.is_authenticated:
#             return JsonResponse({'detail': 'Authentication credentials were not provided.'},
#                                 status=HTTP_401_UNAUTHORIZED)
#         else:
#             serializer = ContactSerializer(data=request.data)
#             if serializer.is_valid():
#                 serializer.save()
#                 return Response(serializer.data, status=status.HTTP_201_CREATED)
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#
#     def delete(self, request):
#         if not request.user.is_authenticated:
#             return JsonResponse({'detail': 'Authentication credentials were not provided.'},
#                                 status=HTTP_401_UNAUTHORIZED)
#         else:
#             Contact.objects.filter(user_id=request.user.id).delete()
#             return Response(status=status.HTTP_204_NO_CONTENT)

