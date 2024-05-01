from django.test import SimpleTestCase
from django.urls import reverse, resolve
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from account import views


class TestUrls(SimpleTestCase):

    def test_obtain_token_pair_url_is_resolved(self):
        url = reverse('account:token_obtain_pair')
        self.assertEqual(resolve(url).func.view_class, TokenObtainPairView)

    def test_token_refresh_is_resolved(self):
        url = reverse('account:token_refresh')
        self.assertEqual(resolve(url).func.view_class, TokenRefreshView)

    def test_user_list_create_url_is_resolved(self):
        url = reverse('account:users')
        self.assertEqual(resolve(url).func.view_class, views.UserListCreate)

    def test_user_update_delete_url_is_resolved(self):
        url = reverse('account:users_detail', kwargs={'pk': 1})
        self.assertEqual(resolve(url).func.view_class, views.UserRetrieveUpdateDestroy)

    def test_user_get_with_token_url_is_resolved(self):
        url = reverse('account:users_detail_token')
        self.assertEqual(resolve(url).func.view_class, views.UserRetrieveWithToken)

    def test_profile_picture_retrieve_update_url_is_resolved(self):
        url = reverse('account:profile', kwargs={'pk': 1})
        self.assertEqual(resolve(url).func.view_class, views.ProfileRetrieveUpdate)

    def test_request_email_verification_url_is_resolved(self):
        url = reverse('account:request_email_verification')
        self.assertEqual(resolve(url).func.view_class, views.RequestEmailVerification)

    def test_verify_email_url_is_resolved(self):
        url = reverse('account:verify_email')
        self.assertEqual(resolve(url).func.view_class, views.VerifyEmail)

    def test_request_password_reset_url_is_resolved(self):
        url = reverse('account:request_password_reset')
        self.assertEqual(resolve(url).func.view_class, views.RequestPasswordReset)

    def test_reset_password_url_is_resolved(self):
        url = reverse('account:reset_password')
        self.assertEqual(resolve(url).func.view_class, views.ResetPassword)

    def test_friend_request_url_is_resolved(self):
        url = reverse('account:friend_request')
        self.assertEqual(resolve(url).func.view_class, views.FriendRequestListCreateDestroy)

    def test_friend_url_is_resolved(self):
        url = reverse('account:manage_friends')
        self.assertEqual(resolve(url).func.view_class, views.FriendListCreateDestroy)

