from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm
from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import PartnerUpdate, ShopList, ShopDetails

urlpatterns = [
    path('partner_update/', PartnerUpdate.as_view(), name='partner_update'),
    path('shops/', ShopList.as_view(), name='shop_list'),
    path('shops/<str:name>/', ShopDetails.as_view(), name='shop_details'),
]