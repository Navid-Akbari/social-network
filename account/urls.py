from django.urls import path

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView
)

from . import views

app_name = 'account'

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('users/', views.UserList.as_view(), name='users'),
    path('users/detail/', views.UserDetailWithToken.as_view(), name='users_detail_token'),
    path('users/<int:pk>/', views.UserDetail.as_view(), name='users_detail'),
    path('request-email-verification/',
        views.RequestEmailVerification.as_view(),
        name='request_email_verification'
    ),
    path('verify-email/', views.VerifyEmail.as_view(), name='verify_email'),
    path('request-password-reset/', views.RequestPasswordReset.as_view(), name='request_password_reset'),
    path('reset-password/', views.ResetPassword.as_view(), name='reset_password')
]
