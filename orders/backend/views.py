import yaml
from django.contrib import auth
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.core.checks import messages
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.core.validators import URLValidator
from django.db.models import Q, Sum, F
from django.dispatch import receiver
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.db import IntegrityError
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.views import View
from django_filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from requests import get
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST, HTTP_201_CREATED, HTTP_200_OK, \
    HTTP_204_NO_CONTENT, HTTP_404_NOT_FOUND, HTTP_403_FORBIDDEN
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from ujson import loads as load_json
from yaml import load as load_yaml, Loader
from rest_framework import generics, status, viewsets, permissions
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.renderers import TemplateHTMLRenderer

from .utils import send_confirmation_email
from .permissions import IsOwnerOrReadOnly, IsOwner, IsShop
from .tasks import send_confirmation_email_task, send_confirmation_order_task
# from rest_framework.permissions import permission_classes

from .serializers import ShopSerializer, SignUpSerializer, LoginSerializer, ProductSerializer, OrderSerializer, \
    ContactSerializer, OrderItemSerializer, CategorySerializer, ProductInfoSerializer, UserSerializer
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User, Contact, ConfirmEmailToken)


class SignUpView(generics.GenericAPIView):

    """View for registration"""

    serializer_class = SignUpSerializer

    def post(self, request, *args, **kwargs):
        """Method for registration"""
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            user_created = serializer.save()
            user = User.objects.get(email=user_created.email)
            send_confirmation_email_task.delay(instance=user.id)

            return Response(data={'data': serializer.data,
                                  'message': 'User created successfuly'},
                            status=status.HTTP_201_CREATED)

        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):

    """View for login

    Methods:
        get(self, request) for get current user
        post(self, request) for login

    Returns:
        Response:
            data:
                "message": str,
                "email": str,
                "Token": str

    """

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


class ProfileView(APIView):

    """View for get and update profile


    Methods:
        get(self, request) for get current user
        post(self, request) for update user

    Returns:
        Response:
            data:
            "email": str,
            "first_name": str,
            "last_name": str,
            "username": str,
            "company": str,
            "position": str,
            "type": str,
            "contacts": list,
            "email_confirm": bool,
            "is_active": bool

    """

    permission_classes = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        try:
            serializer = UserSerializer(request.user, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=HTTP_200_OK)
            return None
        except (request.user.DoesNotExist, request.user.email.MultipleObjectsReturned) as e:
            return Response({'detail': str(e)}, status=HTTP_400_BAD_REQUEST)


class LogoutView(APIView):

    """View for logout user"""

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

    """A class for updating data of shop`s products from yaml file

    Methods:
        post(self, request) for update products

    """

    permission_classes = [IsAuthenticated and IsShop]
    def post(self, request, *args, **kwargs):

        filename = request.data.get('filename')

        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if request.user.type != 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        if not filename:
            return JsonResponse({'detail': 'Not all necessary arguments are specified'}, status=HTTP_400_BAD_REQUEST)

        with open(f'backend/data/{filename}', 'r', encoding="UTF-8") as stream:
            data = yaml.safe_load(stream)  # load data from yaml file
            shop, _ = Shop.objects.update_or_create(name=data['shop']['name'], user_id=request.user.id)
            if data:
                for category in data['categories']:
                    # get or create category
                    category_obj, _ = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_obj.shops.add(shop.id)
                    category_obj.save()

                ProductInfo.objects.filter(shop_id=shop.id).delete()

                for product in data['goods']:
                    # get or create product
                    product_obj, _ = Product.objects.get_or_create(name=product['name'], category_id=product['category'])
                    product_info_obj = ProductInfo.objects.create(
                            product_id=product_obj.id,
                            shop_id=shop.id,
                            model=product['model'],
                            external_id=product['id'],
                            quantity=product['quantity'],
                            price=product['price'],
                            price_rrc=product['price_rrc'],
                        )
                    for name, value in product['parameters'].items():
                        # get or create parameter
                        parameter_obj, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(
                                product_info_id=product_info_obj.id,
                                parameter_id=parameter_obj.id,
                                value=value
                            )
                return JsonResponse({'status': True})

        return JsonResponse({'status': False,  'errors': 'Not all necessary arguments are specified'})


class PartnerState(APIView):

    """A class for changing the state of the partner or get it"""

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type == 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type == 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        state = request.data.get('state')
        if state:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=state)
                return JsonResponse({'status': True})
            except ValueError as e:
                return JsonResponse({'status': False,  'errors': str(e)})

        return JsonResponse({'status': False,  'errors': 'Not all necessary arguments are specified'})


class PartnerListOrders(APIView):

    """View for getting list of orders for shop

    Methods:
        get(self, request) for get orders
    """

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type != 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        orders = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id).exclude(status='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class ShopList(APIView):

    """View for getting list of shops"""

    throttle_classes = [AnonRateThrottle, UserRateThrottle]
    def get(self, request):
        shops = Shop.objects.all()
        serializer = ShopSerializer(shops, many=True)
        return Response(serializer.data)


class ShopDetails(APIView):

    """View for getting details of shop"""

    throttle_classes = [AnonRateThrottle, UserRateThrottle]
    def get(self, request, pk):
        shops = Shop.objects.get(id=pk)
        serializer = ShopSerializer(shops)
        return Response(serializer.data)


class CategoryViewSet(ModelViewSet):

    """View for getting list of categories"""

    throttle_classes = [AnonRateThrottle, UserRateThrottle]
    queryset = Category.objects.all().order_by('id')
    serializer_class = CategorySerializer
    filterset_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ['name', ]


class ProductsList(APIView):

    """View for getting list of products"""

    throttle_classes = [AnonRateThrottle, UserRateThrottle]
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ['model', ]
    filterset_fields = ['category', 'model', 'shop', 'price']

    def get(self, request):
        products = Product.objects.all().order_by('name')
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)


class OrdersView(APIView):

    """View for getting list of orders"""

    permission_classes = [IsAuthenticated, IsOwner]

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            order = Order.objects.filter(user_id=request.user.id).prefetch_related(
                'ordered_items__product_info__product__category',
                'ordered_items__product_info__product_parameters__parameter').annotate(
                ).distinct()  # filter order by user_id
            serializer = OrderSerializer(order, many=True)
            return Response(serializer.data, status=HTTP_200_OK)


class OrderDetailsView(APIView):

    """View for getting details of order

    Methods:
        get(self, request, pk) for get order
        delete(self, request, *args, **kwargs) for delete order

    """

    permission_classes = [IsAuthenticated, IsOwner]

    def get(self, request, pk):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)

        try:
            order = Order.objects.get(user_id=request.user.id, id=pk)
        except ObjectDoesNotExist:
            return JsonResponse({'detail': 'No orders for this user'}, status=HTTP_404_NOT_FOUND)

        serializer = OrderSerializer(order)
        return Response(serializer.data, status=HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)

        order_id = kwargs.get('pk')
        try:
            order = Order.objects.get(user_id=request.user.id, id=order_id)
        except ObjectDoesNotExist:
            return JsonResponse({'detail': 'No orders for this user.'}, status=HTTP_404_NOT_FOUND)

        if request.user == order.user:
            order.delete()
            return JsonResponse({'detail': 'Order deleted successfully.'}, status=HTTP_204_NO_CONTENT)
        else:
            return JsonResponse({'detail': 'You can delete only your orders.'}, status=HTTP_403_FORBIDDEN)


class ContactViewSet(ModelViewSet):

    """View for getting list of contacts and filling form

    Methods:
        get(self, request) for get contacts
        post(self, request) for create contact
        destroy(self, request, *args, **kwargs) for delete contact
    """

    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [IsAuthenticated, IsOwner]
    ordering = ['id']

    def post(self, request, *args, **kwargs):
        serializer = ContactSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=HTTP_201_CREATED)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def destroy(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(status=HTTP_204_NO_CONTENT)


class ProductInfoView(APIView):

    """View for getting list of product info"""

    throttle_classes = [AnonRateThrottle, UserRateThrottle]

    def get(self, request, *args, **kwargs):
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop__id=shop_id)

        if category_id:
            query = query & Q(product__category__id=category_id)

        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


class NewOrderViewSet(viewsets.ModelViewSet):

    """View for creating new order"""

    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def create(self, request, *args, **kwargs):
        """Method for creating new order"""
        if not request.user.is_authenticated:
            return Response({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)

        serializer = OrderSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            serializer.save()
            order = Order.objects.filter(user_id=request.user.id,
                                         state='new').order_by('-created_at').first()
            order.save()
            send_confirmation_order_task.delay(instance=order.id) #  Send email to confirm order

            return JsonResponse(data={'data': serializer.data, 'message': 'An email has been sent to confirm your order'},
                                status=HTTP_201_CREATED)

        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

    def process_list(self,request):
        if request.method == 'POST':
            items_string = request.POST.get('items')
            items_list = items_string.split('\n') # Split the textarea input by new lines
        # Process the items_list further as needed

    def destroy(self, request, *args, **kwargs):
        """Method for deleting order"""
        if not request.user.is_authenticated:
            return Response({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(status=HTTP_204_NO_CONTENT)


def confirm_order(request):

    """Function for confirming order"""

    token_id = request.GET.get('token_id', None)
    order_id = request.GET.get('order_id', None)
    auth_token = request.GET.get('auth_token', None)
    user_id = request.GET.get('user_id', None)
    user = User.objects.get(pk=user_id)
    user = authenticate(email=user.email, auth_token=auth_token)
    order = Order.objects.get(pk=order_id)
    if token_id is None or order_id is None:
        return JsonResponse({'Status': False, 'Errors': 'Not all necessary arguments are specified for confirmation'},
                            status=HTTP_400_BAD_REQUEST)
    try:
        token = ConfirmEmailToken.objects.get(pk=token_id)
        if token.user != user:
            return JsonResponse({'Status': False, 'Errors': 'You are not the owner of this order'},
                                status=HTTP_400_BAD_REQUEST)
        order.state = "confirmed"
        order.save()
        return JsonResponse({'Status': True, 'order_id': order_id, 'order_state': order.state})
    except ConfirmEmailToken.DoesNotExist:
        return JsonResponse({'Status': False, 'Errors': 'Token does not exist'}, status=HTTP_400_BAD_REQUEST)


class OrderItemViewSet(viewsets.ModelViewSet):
    """View for getting list of order items

    Methods:
        create(self, request, *args, **kwargs) for create order item
        update(self, request, *args, **kwargs) for update order item
        destroy(self, request, *args, **kwargs) for delete order item

    Returns:
        Response:
            status=HTTP_201_CREATED for create
            status=HTTP_200_OK for update
            status=HTTP_204_NO_CONTENT for delete

    """

    queryset = OrderItem.objects.all()
    serializer_class = OrderItemSerializer
    permission_classes = [IsAuthenticated, IsOwner]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=HTTP_201_CREATED, headers=headers)

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

    def destroy(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(status=HTTP_204_NO_CONTENT)




def confirm_email_view(request):

    """Function for confirming email"""

    token_id = request.GET.get('token_id', None)
    user_id = request.GET.get('user_id', None)
    token_key = request.GET.get('token_key', None)
    if token_id is None or user_id is None:
        return JsonResponse({'Status': False, 'Errors': 'Недостаточно данных для подтверждения email'},
                            status=HTTP_400_BAD_REQUEST)
    try:
        token = ConfirmEmailToken.objects.get(pk=token_id)
        user = token.user
        user.email_confirm = True
        user.is_active = True
        user.save()
        if user.email_confirm:
            return HttpResponseRedirect(redirect_to='http://127.0.0.1:8000/user/profile')
    except ConfirmEmailToken.DoesNotExist:
        data = {'email_confirm': False}
        return JsonResponse(data=data, status=HTTP_400_BAD_REQUEST)


