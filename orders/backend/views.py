from django.contrib import auth
from django.contrib.auth import authenticate
from django.core.validators import URLValidator
from django.db.models import Q
from django.http import JsonResponse
from django.db import IntegrityError
from django.shortcuts import render, get_object_or_404
from django_filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from requests import get
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST, HTTP_201_CREATED
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from ujson import loads as load_json
from yaml import load as load_yaml, Loader
from rest_framework import generics, status, viewsets
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.renderers import TemplateHTMLRenderer

from .permissions import IsOwnerOrReadOnly, IsOwner
# from rest_framework.permissions import permission_classes

from .serializers import ShopSerializer, SignUpSerializer, LoginSerializer, ProductSerializer, OrdersSerializer, \
    ContactSerializer, OrderItemSerializer
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User, Contact)





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


class LogoutView(APIView):
    serializer_class = LoginSerializer

    def get(self, request):
        return Response(status=status.HTTP_200_OK)

    def post(self, request):
        if request.user.is_authenticated:
            request.user.auth_token.delete()
            auth.logout(request)
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_401_UNAUTHORIZED)


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
    permission_classes = [IsOwner]


# class BascketView(APIView):
#
#     def get(self, request, *args, **kwargs):
#         if not request.user.is_authenticated:
#             return JsonResponse({'detail': 'Authentication credentials were not provided.'},
#                                 status=HTTP_401_UNAUTHORIZED)
#         else:
#             bascket = Order.objects.filter(user_id=request.user.id, state='basket').prefetch_related(
#                 'orderitems__product_info__product__category',
#                 'orderitems__product_info__product_parameters__parameter').annotate(
#
#                 ).distinct()
#             serializer = OrdersSerializer(bascket, many=True)
#             return JsonResponse(serializer.data, safe=False)
#
#     def post(self, request, *args, **kwargs):
#         if not request.user.is_authenticated:
#             return JsonResponse({'detail': 'Authentication credentials were not provided.'},
#                                 status=HTTP_401_UNAUTHORIZED)
#
#         items = request.data.get('items')
#         if items:
#             try:
#                 items_dict = load_json(items)
#             except ValueError:
#                 return JsonResponse({'detail': 'Неверный формат запроса'}, status=HTTP_400_BAD_REQUEST)
#             else:
#                 bascket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
#                 objects_created = 0
#                 for order_item in items_dict:
#                     order_item.update({'order': bascket.id})
#                     serializer = OrderItemSerializer(data=order_item)
#                     if serializer.is_valid():
#                         try:
#                             serializer.save()
#                         except IntegrityError as error:
#                             return JsonResponse({'detail': str(error)}, status=HTTP_400_BAD_REQUEST)
#                         else:
#                             objects_created += 1
#
#                     else:
#
#                         return JsonResponse({'detail': serializer.errors}, status=HTTP_400_BAD_REQUEST)
#
#                 return JsonResponse({'created': objects_created})
#         return JsonResponse({'detail': 'Не указаны все необходимые аргументы'}, status=HTTP_400_BAD_REQUEST)
#
#     def delete(self, request, *args, **kwargs):
#         if not request.user.is_authenticated:
#             return JsonResponse({'detail': 'Authentication credentials were not provided.'},
#                                 status=HTTP_401_UNAUTHORIZED)
#
#         items = request.data.get('items')
#         if items:
#             items_list = items.split(',')
#             bascket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
#             query = Q()
#             objects_deleted = False
#             for order_item_id in items_list:
#                 query = query | Q(id=order_item_id)
#             if query:
#                 OrderItem.objects.filter(query).delete()
#                 objects_deleted = True
#
#             if objects_deleted:
#                 deleted_count = OrderItem.objects.filter(query).delete()[0]
#                 return JsonResponse({'Status': True, 'deleted': deleted_count})
#         return JsonResponse({'detail': 'Не указаны все необходимые аргументы'}, status=HTTP_400_BAD_REQUEST)
#
#     def put(self, request, *args, **kwargs):
#         if not request.user.is_authenticated:
#             return JsonResponse({'detail': 'Authentication credentials were not provided.'},
#                                 status=HTTP_401_UNAUTHORIZED)
#
#         items = request.data.get('items')
#         if items:
#             try:
#                 items_dict = load_json(items)
#             except ValueError:
#                 return JsonResponse({'detail': 'Неверный формат запроса'}, status=HTTP_400_BAD_REQUEST)
#             else:
#                 bascket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
#                 objects_updated = 0
#                 for order_item in items_dict:
#                     if type(order_item[id]) == int and type(order_item['quantity']) == int:
#                         objects_updated += OrderItem.objects.filter(order_id=bascket.id, id=order_item['id']).update(
#                             quantity=order_item['quantity'])
#
#                 return JsonResponse({'updated': objects_updated, 'status': status.HTTP_200_OK})
#         return JsonResponse({'detail': 'Не указаны все необходимые аргументы'}, status=HTTP_400_BAD_REQUEST)
#


class NewOrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrdersSerializer

    def create(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            serializer = OrdersSerializer(data=request.data, context={'request': request}, many=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=HTTP_201_CREATED)
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

    def process_list(self,request):
        if request.method == 'POST':
            items_string = request.POST.get('items')
            items_list = items_string.split('\n') # Split the textarea input by new lines
        # Process the items_list further as needed


class OrderItemViewSet(viewsets.ModelViewSet):

    queryset = OrderItem.objects.all()
    serializer_class = OrderItemSerializer
    permission_classes = [IsAuthenticated, IsOwner]

    def create(self, request, *args, **kwargs):
        items_string = request.data
        if items_string is None or items_string == '':
            return ValidationError('No data to process')

        try:
            items_dict = load_json(items_string)
        except ValueError:
            return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})

        order = Order.objects.get_or_create(user_id=request.user.id, state='basket')
        objects_created = 0
        for order_item_data in items_dict:
            order_item_data['order'] = order.id
            serializer = OrderItemSerializer(data=order_item_data, many=True)
            if serializer.is_valid():
                try:
                    serializer.save()
                except IntegrityError as error:
                    return JsonResponse({'Status': False, 'Errors': str(error)}, status=HTTP_400_BAD_REQUEST)
                else:
                    objects_created += 1

        if objects_created > 0:
            Order.objects.filter(id=order.id).update(state='new')
            return JsonResponse(serializer.data, status=status.HTTP_201_CREATED)

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=HTTP_400_BAD_REQUEST)
        # if serializer.is_valid():
        #     user = request.user
        #     basket, _ = Order.objects.get_or_create(user_id=request.user.id,
        #                                             state='basket')
        #     serializer.save(order=basket)
        #     return Response(serializer.data, status=HTTP_201_CREATED)
        # else:
        #     return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)
        #         for order_item_data in items_dict:
        #             order_item_data.update({'order': basket.id})
        #
        #             if serializer.is_valid():
        #                 try:
        #                     serializer.save()
        #                 except IntegrityError as error:
        #                     return JsonResponse({'Status': False, 'Errors': str(error)}, status=HTTP_400_BAD_REQUEST)
        #                 else:
        #                     objects_created += 1
        #         if objects_created > 0:
        #             Order.objects.filter(id=basket.id).update(state='new')
        #         return JsonResponse(serializer.data, status=HTTP_201_CREATED)
        #
        #     return JsonResponse({'Status': False, 'Errors': 'Invalid serializer data'}, status=HTTP_400_BAD_REQUEST)
        #
        # return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            if getattr(instance, '_prefetched_objects_cache', None):
                # If 'prefetch_related' has been applied to a queryset, we need to
                # forcibly invalidate the prefetch cache on the instance.
                instance._prefetched_objects_cache = {}

            return Response(serializer.data)

