from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm
from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import PartnerUpdate, ShopList, ShopDetails, LoginView, SignUpView, ContactViewSet, ProductsList

r = DefaultRouter()
r.register('contacts', ContactViewSet, basename='contact')


urlpatterns = [
    path('partner_update/', PartnerUpdate.as_view(), name='partner_update'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('shops/', ShopList.as_view(), name='shop_list'),
    path('shops/<str:name>/', ShopDetails.as_view(), name='shop_details'),
    path('products/', ProductsList.as_view(), name='product_list'),
    # path('contacts/', ContactViewSet.as_view({'get': 'list'}), name='contact_list'),
] + r.urls