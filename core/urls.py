from django.urls import path
from . import views
from .views import OrderHistoryView

app_name = "core"

urlpatterns = [
    path("", views.HomeView.as_view(), name="home"),
    path("product/<slug>", views.ItemDetailView.as_view(), name="product"),
    path("order-summary/", views.OrderSummaryView.as_view(), name="order-summary"),
    path("checkout/", views.CheckoutView.as_view(), name="checkout"),
    path("payment/<payment_option>", views.PaymentView.as_view(), name="payment"),
    path("request-refund/", views.RequestRefundView.as_view(), name="request-refund"),
    path("products/", views.products, name="products"),
    path("add-to-cart/<slug>", views.add_to_cart, name="add-to-cart"),
    path("add-coupon/", views.AddCouponView.as_view(), name="add-coupon"),
    path("remove-from-cart/<slug>", views.remove_from_cart, name="remove-from-cart"),
    path("remove-all-from-cart/<slug>", views.remove_all_from_cart, name="remove-all-from-cart"),
    path("account-login/", views.custom_login, name="account_login"),
    path("account-logout/", views.logout, name="account_logout"),
    path("account-signup/", views.signup, name="account_signup"),
    path('order-history/', OrderHistoryView.as_view(), name='order-history'), # New URL pattern

# path("accounts/", include("allauth.urls")),
    path("logout/", views.custom_logout, name="logout"),
]
