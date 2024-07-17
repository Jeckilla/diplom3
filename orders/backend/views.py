from django.contrib import auth
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.core.validators import URLValidator
from django.db.models import Q, Sum, F
from django.dispatch import receiver
from django.http import JsonResponse, HttpResponseRedirect
from django.db import IntegrityError
from django.shortcuts import render, get_object_or_404
from django_filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from requests import get
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_400_BAD_REQUEST, HTTP_201_CREATED, HTTP_200_OK, \
    HTTP_204_NO_CONTENT
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from ujson import loads as load_json
from yaml import load as load_yaml, Loader
from rest_framework import generics, status, viewsets, permissions
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.renderers import TemplateHTMLRenderer

from .utils import send_confirmation_email, send_confirm_order
from .permissions import IsOwnerOrReadOnly, IsOwner, IsShop
# from rest_framework.permissions import permission_classes

from .serializers import ShopSerializer, SignUpSerializer, LoginSerializer, ProductSerializer, OrderSerializer, \
    ContactSerializer, OrderItemSerializer, CategorySerializer, ProductInfoSerializer, UserSerializer
from .models import (Order, OrderItem, ProductInfo, ProductParameter, Parameter,
                     Product, Category, Shop, User, Contact, ConfirmEmailToken)


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


class ConfirmRegistration(APIView):
    """
    Класс для подтверждения почтового адреса
    """

    # Регистрация методом POST
    def post(self, request, *args, **kwargs):
        """
                Подтверждает почтовый адрес пользователя.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        # проверяем обязательные аргументы
        if {'email', 'token'}.issubset(request.data):

            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return Response({'Status': True})
            else:
                return Response({'Status': False, 'Errors': 'Неправильно указан токен или email'})

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class ProfileView(APIView):

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

    permission_classes = [IsAuthenticated and IsShop]
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type != 'shop':
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
                    category_obj, _ = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_obj.shops.add(shop.id)
                    category_obj.save()

                ProductInfo.objects.filter(shop_id=shop.id).delete()

                for product in data['goods']:
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
                        parameter_obj, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(
                                product_info_id=product_info_obj.id,
                                parameter_id=parameter_obj.id,
                                value=value
                            )
                return JsonResponse({'status': True})
        return JsonResponse({'status': False,  'errors': 'Не указаны все необходимые аргументы'})


class PartnerState(APIView):

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type != 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        if not request.user.type != 'shop':
            return JsonResponse({'detail': 'Only for shops'}, status=HTTP_401_UNAUTHORIZED)

        state = request.data.get('state')
        if state:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=state)
                return JsonResponse({'status': True})
            except ValueError as e:
                return JsonResponse({'status': False,  'errors': str(e)})

        return JsonResponse({'status': False,  'errors': 'Не указаны все необходимые аргументы'})


class PartnerListOrders(APIView):

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
    def get(self, request):
        shops = Shop.objects.all()
        serializer = ShopSerializer(shops, many=True)
        return Response(serializer.data)


class ShopDetails(APIView):
    """View for getting details of shop"""
    def get(self, request, pk):
        shops = Shop.objects.get(id=pk)
        serializer = ShopSerializer(shops)
        return Response(serializer.data)


class CategoryViewSet(ModelViewSet):
    """View for getting list of categories"""
    queryset = Category.objects.all().order_by('id')
    serializer_class = CategorySerializer
    filterset_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ['name', ]


class ProductsList(APIView):
    filter_backends = [DjangoFilterBackend, OrderingFilter, SearchFilter]
    search_fields = ['model', ]
    filterset_fields = ['name', 'category', 'model', 'shop', 'price', 'quantity']

    def get(self, request):
        products = Product.objects.all().order_by('name')
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)


class OrdersView(APIView):

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            order = Order.objects.filter(user_id=request.user.id).prefetch_related(
                'ordered_items__product_info__product__category',
                'ordered_items__product_info__product_parameters__parameter').annotate(
                ).distinct()
            serializer = OrderSerializer(order, many=True)
            return Response(serializer.data, status=HTTP_200_OK)


class ContactViewSet(ModelViewSet):

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
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)

        serializer = OrderSerializer(data=request.data, context={'request': request}, many=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=HTTP_201_CREATED)

        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

    def process_list(self,request):
        if request.method == 'POST':
            items_string = request.POST.get('items')
            items_list = items_string.split('\n') # Split the textarea input by new lines
        # Process the items_list further as needed

    def destroy(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)
        else:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(status=HTTP_204_NO_CONTENT)


class OrderItemViewSet(viewsets.ModelViewSet):

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


class SendEmailConfirmationToken(APIView):

    permission_classes = [IsAuthenticated,]

    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        user = request.user
        token = user.confirm_email_tokens.filter(user=user)
        return Response(data=token, status=HTTP_200_OK)

    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=HTTP_401_UNAUTHORIZED)
        user = request.user
        token = ConfirmEmailToken.objects.create(user=user)
        send_confirmation_email(email=user.email,
                                token_id=token.pk,
                                token_key=token.key,
                                user_id=user.pk,
                                auth_token=user.auth_token)
        return Response(data=None, status=HTTP_201_CREATED)


class SendConfirmationOrder(APIView):

    permission_classes = [IsAuthenticated, IsOwner]
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'Authentication credentials were not provided.'},
                                status=HTTP_401_UNAUTHORIZED)

        if Order.objects.filter(user_id=request.user.id).exists():
            order = Order.objects.filter(user_id=request.user.id,
                                         state='new').order_by('-created_at').first()

            self.approve_order(order)
            return JsonResponse({'Status': 'Your order was confirmed'})

        return JsonResponse({'Status': 'Your order was not confirmed'})

    def approve_order(self, order):
        order.state = 'confirmed'
        order.save()
        send_confirm_order(email=order.user.email,
                            user_id=order.user.id,
                            order_id=order.pk,
                            order_state=order.state,
                            instance=order)


def confirm_email_view(request):
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
        user.save()
        if user.email_confirm:
            return HttpResponseRedirect(redirect_to='http://127.0.0.1:8000/user/profile')
    except ConfirmEmailToken.DoesNotExist:
        data = {'email_confirm': False}
        return JsonResponse(data=data, status=HTTP_400_BAD_REQUEST)


