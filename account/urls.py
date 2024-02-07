from django.urls import path

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from . import views

urlpatterns = [
    path('account/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('account/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('account/users/', views.UserAccountManager.as_view(), name='users'),
    path('account/users/<int:pk>/', views.UserAccountManager.as_view(), name='users'),
    path('account/verify-email/', views.VerifyEmail.as_view(), name='verify_email'),

]
