from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from .authentication import social_auth, social_auth_complete
from .views import PartnerUpdate, ShopList, ShopDetails, LoginView, SignUpView, ContactViewSet, ProductsList, \
    LogoutView, OrderItemViewSet, NewOrderViewSet, CategoryViewSet, OrdersView, PartnerListOrders, \
    PartnerState, ProductInfoView, ProfileView, confirm_email_view, OrderDetailsView, confirm_order

r = DefaultRouter()
r.register('contacts', ContactViewSet, basename='contact')
r.register('basket', OrderItemViewSet, basename='basket')
r.register('new_order', NewOrderViewSet, basename='new_order')
r.register('categories', CategoryViewSet, basename='category')



urlpatterns = [
    path('partner/update/', PartnerUpdate.as_view(), name='partner_update'),
    path('partner/orders/', PartnerListOrders.as_view(), name='partner_orders'),
    path('partner/state/', PartnerState.as_view(), name='partner_state'),
    path('reset_password/', reset_password_request_token, name='reset_password'),
    path('reset_password_confirm/', reset_password_confirm, name='reset_password_confirm'),
    path('user/signup/', SignUpView.as_view(), name='signup'),
    path('social-auth/', include('social_django.urls', namespace='social_auth')),
    path('social-auth/login/vk-oauth2/', social_auth, name='vk_oauth2_login'),
    path('social/complete/vk-oauth2/', social_auth_complete, name='vk_oauth2_complete'),
    path('social-auth/login/google-oauth2/', social_auth, name='google_oauth2_login'),
    path('social/complete/google-oauth2/', social_auth_complete, name='google_oauth2_complete'),
    path('user/login/', LoginView.as_view(), name='login'),
    path('user/confirmed_email/', confirm_email_view, name='confirmed_email_view'),
    path('accounts/profile/', ProfileView.as_view(), name='profile'),
    path('user/logout/', LogoutView.as_view(), name='logout'),
    path('shops/', ShopList.as_view(), name='shop_list'),
    path('shops/<int:pk>/', ShopDetails.as_view(), name='shop_details'),
    path('product_info/', ProductInfoView.as_view(), name='product_info'),
    path('products/', ProductsList.as_view(), name='products'),
    path('order/confirm/', NewOrderViewSet.as_view({'post': 'create'}), name='order_confirm'),
    path('order/confirmed/', confirm_order, name='order_confirmed'),
    path('orders/', OrdersView.as_view(), name='orders'),
    path('order/<int:pk>/', OrderDetailsView.as_view(), name='order_detail'),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    # Optional UI:
    path('schema/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('schema/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
] + r.urls
