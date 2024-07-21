from django_rest_passwordreset.views import reset_password_request_token, reset_password_confirm
from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import PartnerUpdate, ShopList, ShopDetails, LoginView, SignUpView, ContactViewSet, ProductsList, \
    LogoutView, OrderItemViewSet, NewOrderViewSet, CategoryViewSet, OrdersView, PartnerListOrders, \
    PartnerState, ProductInfoView, ProfileView, SendEmailConfirmationToken, confirm_email_view, \
    SendConfirmationOrder, OrderDetailsView

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
    path('user/login/', LoginView.as_view(), name='login'),
    path('user/send_email_confirm/', SendEmailConfirmationToken.as_view(), name='send_email_confirm'),
    path('user/confirmed_email/', confirm_email_view, name='confirmed_email_view'),
    path('user/profile/', ProfileView.as_view(), name='profile'),
    path('user/logout/', LogoutView.as_view(), name='logout'),
    path('shops/', ShopList.as_view(), name='shop_list'),
    path('shops/<int:pk>/', ShopDetails.as_view(), name='shop_details'),
    path('product_info/', ProductInfoView.as_view(), name='product_info'),
    path('products/', ProductsList.as_view(), name='products'),
    path('order/confirm/<int:user_id>/<int:order_id>/', SendConfirmationOrder.as_view(),
         name='order_confirm'),
    path('orders/', OrdersView.as_view(), name='orders'),
    path('orders/<int:pk>/', OrderDetailsView.as_view(), name='order_detail'),
] + r.urls