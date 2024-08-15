import mixer
from rest_framework.test import APITestCase, APIClient, force_authenticate, APIRequestFactory
from rest_framework import status
from django.urls import reverse
import os
from django.conf import settings
import pytest




from rest_framework.authtoken.models import Token
from unittest.mock import patch

from orders.backend.models import Shop, Category, ProductInfo, OrderItem, Order, Contact, Product
from orders.backend.tasks import generate_thumbnail_task
from orders.backend.views import generate_thumbnail_path, SignUpView, LoginView
from django.contrib.auth.models import User
from rest_framework.settings import api_settings
from model_bakery import baker




@pytest.fixture
def client():
    return APIClient()


@pytest.fixture
def user_factory():
    def factory(*args, **kwargs):
        return baker.make(User, *args, **kwargs)

    return factory

@pytest.fixture
def token(user):
    return Token.objects.create(user=user)


@pytest.fixture
def shop_factory():
    def factory(*args, **kwargs):
        return baker.make(Shop, *args, **kwargs)
    return factory


@pytest.fixture
def category_factory():
    def factory(*args, **kwargs):
        return baker.make(Category, *args, **kwargs)

    return factory


@pytest.fixture
def product_info_factory(shop, category):
    def factory(*args, **kwargs):
        return baker.make(ProductInfo, shop=shop, product__category=category, *args, **kwargs)

    return factory

@pytest.fixture
def order_item_factory(instance):
    def factory(*args, **kwargs):
        return baker.make(OrderItem, product_info=instance, *args, **kwargs)  # Replace 'product_info' with the actual ProductInfo instance *)

    return factory


@pytest.fixture
def order_factory(user):
    def factory(client, user, *args, **kwargs):
        instance = baker.make(ProductInfo, *args, **kwargs)
        order_item = baker.make(OrderItem, product_info=instance)
        order = baker.make(Order, order_items=order_item, *args, **kwargs)

        token = Token.objects.get(user=user)
        client.credentials(HTTP_AUTHORIZATION=f'Token {token}')

        return baker.make(Order, order_items=order_item, *args, **kwargs)  # Replace 'order_item' with the actual OrderItem instance

    return factory


@pytest.fixture
def contact_factory(instance):
    def factory(*args, **kwargs):
        return baker.make(Contact, *args, **kwargs)

    return factory


@pytest.fixture
def product_factory(instance):
    def factory(*args, **kwargs):
        return baker.make(Product, *args, **kwargs)

    return factory


class TestSignUpView(APITestCase):
    def test_post_valid_data(self):
        factory = APIRequestFactory()
        view = SignUpView.as_view()
        user_data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john.doe@example.com',
            'username': 'johndoe',
            'password': 'securepassword'
        }
        request = factory.post('/api/signup/', data=user_data, format='json')
        force_authenticate(request, user=None)
        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_post_invalid_data(self):
        factory = APIRequestFactory()
        view = SignUpView.as_view()
        user_data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'invalid_email',  # Invalid email format
            'username': 'johndoe',
            'password': 'short'  # Password too short
        }
        request = factory.post('/api/signup/', data=user_data, format='json')
        force_authenticate(request, user=None)
        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestLoginView(APITestCase):
    def test_get_current_user(self):
        factory = APIRequestFactory()
        view = LoginView.as_view()
        request = factory.get('/api/login/')
        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_valid_credentials(self):
        factory = APIRequestFactory()
        view = LoginView.as_view()
        user = mixer.blend('auth.User')
        user.set_password('testpassword')
        user.save()
        user_data = {
            'email': user.email,
            'password': 'testpassword'
        }
        request = factory.post('/api/login/', data=user_data, format='json')
        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_invalid_credentials(self):
        factory = APIRequestFactory()
        view = LoginView.as_view()
        user_data = {
            'email': 'invalid_email',
            'password': 'wrongpassword'
        }
        request = factory.post('/api/login/', data=user_data, format='json')
        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
class ShopTests(APITestCase):

    def test_get_shop_list(self, shop_factory, client):
        shops = shop_factory(_quantity=2)
        url = reverse('/shop_list/')

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        assert len(data) == len(shops)
        for shop in enumerate(shops):
            self.assertEqual(data[shop[0]]['name'], shop[1].name)
            self.assertEqual(data[shop[0]]['url'], shop[1].url)
            self.assertEqual(data[shop[0]]['filename'], shop[1].filename)



    def test_get_shop_detail(self):
        Shop.objects.create(name='Shop 1', url='https://shop1.com', filename='shop1.png')
        url = reverse('/shop_details/')

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data['name'], 'Shop 1')
        self.assertEqual(data['url'], 'https://shop1.com')
        self.assertEqual(data['filename'], 'shop1.png')



@pytest.mark.django_db
class OrdersViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

    def test_get_orders_list_authenticated(self, order_factory, user, token):

        order_items = order_item_factory(_quantity=2)
        orders = order_factory(_quantity=2, user=user, order_items=order_items)

        url = reverse('/orders/')

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert len(response.data) == len(orders)
        for order in enumerate(orders):
            self.assertEqual(response.data[order[0]]['id'], order[1].id)

@pytest.mark.django_db
class CategoryViewSetTests(APITestCase):

    def test_list_categories(self, client, category_factory):
        categories = category_factory(_quantity=2)
        url = reverse('/categories/')

        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert len(response.data) == len(categories)
        for category in enumerate(categories):
            self.assertEqual(response.data[category[0]]['name'], category[1].name)

@pytest.mark.django_db
class ProductDetailsViewTests(APITestCase):

    @patch('orders.views.generate_thumbnail_path')
    @patch('orders.views.generate_thumbnail_task.delay')
    def test_get_product_details(self, mock_generate_thumbnail_task_delay, mock_generate_thumbnail_path, client, product_factory):
        products = product_factory(_quantity=10)

        url = reverse('products/<int:pk>/', kwargs={'pk': 1})

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check if the response contains the expected data
        for product in enumerate(products):
            self.assertEqual(response.data[product[0]]['name'], product[1].name)


        # Check if the generate_thumbnail_task.delay method is called with the correct parameters
        mock_generate_thumbnail_task_delay.assert_called_with(instance=1)

        # Check if the generate_thumbnail_path method is called
        self.assertTrue(mock_generate_thumbnail_path.called)


@pytest.mark.django_db
class ProductsListTests(APITestCase):

    def test_get_products_list(self, product_factory, client):
        products = product_factory(_quantity=10)
        url = reverse('/products/')

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert len(response.data) == len(products)
        for product in enumerate(products):
            self.assertEqual(response.data[product[0]]['name'], product[1].name)

@pytest.mark.django_db
class OrderDetailsViewTests(APITestCase):

    def test_get_order_details_authenticated(self, order_factory, order_item_factory, user, token, client):

        order_items = order_item_factory(_quantity=2)
        orders = order_factory(_quantity=2, user=self.user, order_items=order_items)
        url = reverse('orders/<str:pk>/', kwargs={'pk': 1})

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert len(response.data) == len(orders)

        # Check if the response contains the expected data
        for order in enumerate(orders):
            self.assertEqual(response.data[order[0]]['id'], order[1].id)

    def test_get_order_details_unauthenticated(self, order_factory, order_item_factory, user, token, client):

        order_items = order_item_factory(_quantity=2)
        orders = order_factory(_quantity=2, user=None, order_items=order_items)
        url = reverse('orders/<str:pk>/')

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


    def test_delete_order_authenticated(self):
        self.client.force_authenticate(user=self.user)
        url = reverse('orders/<str:pk>/', kwargs={'pk': 1})

        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_order_unauthenticated(self):
        self.client.force_authenticate(user=None)
        url = reverse('orders/<str:pk>/', kwargs={'pk': 1})

        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@pytest.mark.django_db
class ProductInfoViewTests(APITestCase):

    def setUp(self, product_info_factory, shop, category, client):
        self.shop = shop
        self.category = category
        self.product_info = product_info_factory(shop=self.shop, category=self.category)

    def test_get_product_info_with_filters(self, product_info_factory, client):
        product_info_list = product_info_factory(_quantity=10)
        url = reverse('product_info/')

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert len(response.data) == len(product_info_list)
        for product_info in enumerate(product_info_list):
            self.assertEqual(response.data[product_info[0]]['id'], product_info[1].id)
        # Add more assertions to check the response data and behavior

    def test_get_product_info_without_filters(self, product_info_factory, client):
        product_info_list = product_info_factory(_quantity=10)
        url = reverse('product_info/')

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        assert len(response.data) == len(product_info_list)
        for product_info in enumerate(product_info_list):
            self.assertEqual(response.data[product_info[0]]['id'], product_info[1].id)
        # Add more assertions to check the response data and behavior

@pytest.mark.django_db
class OrderItemViewSetTests(APITestCase):

    def setUp(self):
        self.user = baker.make(settings.AUTH_USER_MODEL)
        self.token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    def test_create_order_item_authenticated(self, order_item_factory, client, user, token, order_factory):
        order_items = order_item_factory(_quantity=1)
        order = order_factory(user=user, order_items=order_items, status='basket')

        url = reverse('basket/')

        response = self.client.post(url, order_items)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Add assertions to check the created order item


    def test_update_order_item_authenticated(self, order_item_factory, client, user, token, order_factory):
        order_items = order_item_factory(_quantity=1)
        order = order_factory(user=user, order_items=order_items, status='basket')

        url = reverse('basket/', kwargs={'pk': order_items[0].id})

        response = self.client.put(url, order_items)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Add assertions to check the updated order item


    def test_get_order_item_authenticated(self, order_item_factory, client, user, token, order_factory):
        order_items = order_item_factory(_quantity=1)
        order = order_factory(user=user, order_items=order_items, status='basket')

        url = reverse('basket/', kwargs={'pk': order_items[0].id})

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Add assertions to check the retrieved order item

    def test_delete_order_item_authenticated(self, order_item_factory, client, user, token, order_factory):
        order_items = order_item_factory(_quantity=1)
        order_item_id = order_items[0].id  # Replace with the actual ID of the order item to delete
        url = reverse('basket/', kwargs={'pk': order_item_id})

        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)


