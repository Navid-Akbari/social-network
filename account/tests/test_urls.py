from django.test import SimpleTestCase
from django.urls import reverse, resolve

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from account import views


class TestUrls(SimpleTestCase):

    def test_obtain_tokan_pair_url_is_resolved(self):
        url = reverse('token_obtain_pair')
        self.assertEqual(resolve(url).func.view_class, TokenObtainPairView)


    def test_tokan_refresh_is_resolved(self):
        url = reverse('token_refresh')
        self.assertEqual(resolve(url).func.view_class, TokenRefreshView)


    def test_list_create_url_is_resolved(self):
        url = reverse('users')
        self.assertEqual(resolve(url).func.view_class, views.UserAccountManager)

    
    def test_update_delete_url_is_resolved(self):
        url = reverse('users_detail', kwargs={'pk': 1})
        self.assertEqual(resolve(url).func.view_class, views.UserAccountManager)