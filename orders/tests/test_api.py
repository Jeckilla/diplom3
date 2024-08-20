import io
import os
from unittest import mock
from unittest.mock import patch, Mock
from django.core.files import File
from PIL import Image


from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import status
from rest_framework.exceptions import NotFound

# Set the DJANGO_SETTINGS_MODULE environment variable
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'orders.settings')

# Initialize Django settings
import django
django.setup()

ALLOWED_HOSTS = settings.ALLOWED_HOSTS


from django.test import TestCase
from django.urls import reverse
from backend.models import User, Category, Product, Contact, ProductInfo
from rest_framework.test import APIClient, APITestCase
from rest_framework.test import APIRequestFactory
from backend.views import ShopListView, ShopDetailsView, CategoryViewSet, ProductDetailsView, ProductsListView, \
    ProductInfoView
from backend.models import Shop
from backend.serializers import ShopSerializer, CategorySerializer, ProductDetailsSerializer, ProductInfoSerializer


class ShopListViewTest(TestCase):

    def test_get_shops(self):
        factory = APIRequestFactory()
        request = factory.get('/shops/')
        view = ShopListView.as_view()

        response = view(request)
        self.assertEqual(response.status_code, 200)

        shops = Shop.objects.all()
        serializer = ShopSerializer(shops, many=True)
        self.assertEqual(response.data, serializer.data)


class ShopDetailsViewTest(TestCase):

    def test_get_shop_details(self):
        # Create a shop instance for testing
        shop = Shop.objects.create(name='Test Shop', url='http://example.com', filename='test_shop.yaml')

        factory = APIRequestFactory()
        request = factory.get(f'/shops/{shop.id}/')  # Assuming the endpoint is /shops/<pk>/
        view = ShopDetailsView.as_view()

        response = view(request, pk=shop.id)
        self.assertEqual(response.status_code, 200)

        # Add more assertions based on the expected behavior of the get method
        expected_data = ShopSerializer(shop).data
        self.assertEqual(response.data, expected_data)


class CustomRequestFactory(APIRequestFactory):
    def generic(self, method, path, data='', content_type='application/octet-stream',
                secure=False, **extra):
        request = super().generic(method, path, data, content_type, secure, **extra)
        request.META['HTTP_HOST'] = '127.0.0.1'
        return request

class CategoryViewSetTest(TestCase):

    def test_list_categories(self):
        factory = CustomRequestFactory()
        request = factory.get('/categories/')
        view = CategoryViewSet.as_view({'get': 'list'})

        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class ProductDetailsViewTest(TestCase):

    def test_get_existing_product(self):
        file_mock = mock.MagicMock(spec=File)
        file_mock.name = '43-televizor-xiaomi.png'
        factory = APIRequestFactory()
        request = factory.get('/products/1/')
        view = ProductDetailsView.as_view()

        image = io.BytesIO()
        Image.new('RGBA', (100, 100)).save(image, 'PNG')
        image.seek(0)

        image = SimpleUploadedFile('43-televizor-xiaomi.png', image.getvalue(), content_type='image/png')
        file_mock.name = '43-televizor-xiaomi.png'
        file_mock.file = image

        # Create a mock Product instance
        product = Product(id=1, name='Test Product', image=file_mock.name)
        serializer_data = ProductDetailsSerializer(product).data

        # Mock the Product.objects.get method to return the mock Product instance
        with patch('backend.views.Product.objects.get', return_value=product):
            response = view(request, pk=1)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data, serializer_data)


class ProductsListViewTest(APITestCase):
    def test_products_list_view(self):
        factory = APIRequestFactory()
        url = reverse('products')

        request = factory.get(url)
        response = ProductsListView.as_view()(request)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 21)  # Assuming no products in the database for initial test

        product1 = Product.objects.create(name='Product 1', image='noutbuk-huawei-matebook.png')
        product2 = Product.objects.create(name='Product 2', image='oled55cx6la-tv-oled.png')

        request = factory.get(url)

        # Make the request again after adding test data
        response = ProductsListView.as_view()(request)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 23)


# class ContactViewSetTest(APITestCase):
#     def setUp(self):
#         self.user = User.objects.create_user(id=57, email='testuser@mail.ru', password='testpassword')
#         self.client.force_authenticate(user=self.user)
#
#     def test_create_contact(self):
#         url = reverse('contacts')
#         data = {user: self.user, city: 'New York', street: '123 Main St', house: '1', apartment: 'A', phone: '1234567890'}
#
#         response = self.client.post(url, data, format='json')
#
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         self.assertEqual(Contact.objects.count(), 1)
#         self.assertEqual(Contact.objects.get().city, 'New York')
#
#     def test_delete_contact(self):
#         contact = Contact.objects.create()
#
#         url = reverse('contacts', kwargs={'pk': contact.pk})
#         response = self.client.delete(url)
#
#         self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
#         self.assertEqual(Contact.objects.count(), 0)

class ProductInfoViewTest(APITestCase):
    def test_product_info_view(self):
        # Create test data
        shop = Shop.objects.create(name='Test Shop', state=True)
        product = Product.objects.create(name='Test Product', image='noutbuk-huawei-matebook.png')
        product_info = ProductInfo.objects.create(product=product, shop=shop, model='huawei matebook', external_id=3624623, quantity=10, price=1000, price_rrc=990)

        # Mock request and query params
        url = reverse('product_info')
        response = self.client.get(url, {'shop_id': shop.id})

        # Assert the response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        serialized_data = ProductInfoSerializer(instance=product_info).data
        self.assertEqual(response.data[0]['id'], serialized_data['id'])

