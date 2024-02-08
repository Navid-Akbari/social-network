from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password

from rest_framework_simplejwt.tokens import AccessToken
import json

from account.views import UserAccountManager

CustomUser = get_user_model()


# since the other parts have been unit tested, we won't test all invalid inputs
class UserAccountManagement(TestCase):

    def setUp(self):
        self.client = Client()
        self.list_create_url = reverse('users')
        self.update_destroy_url = reverse('users_detail', args=[1])
        self.first_test_user = CustomUser.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        CustomUser.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.first_test_user)


    def test_post_valid(self):
        user = {
            'username': 'test2',
            'email': 'test2@example.com',
            'password': 'testing321'
        }

        response = self.client.post(
            self.list_create_url, 
            json.dumps(user), 
            content_type='application/json'
        )

        user_from_db = CustomUser.objects.get(username='test2')

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['username'], 'test2')
        self.assertEqual(response.data['email'], 'test2@example.com')
        self.assertTrue(check_password(user['password'], user_from_db.password))


    def test_post_invalid(self):
        user = {
            'username': '',
            'email': 'test2@example.com',
            'password': 'testing321'
        }

        response = self.client.post(
            self.list_create_url, 
            json.dumps(user), 
            content_type='application/json'
        )

        self.assertTrue(response.status_code, 400)


    def test_get_with_no_parameter(self):
        response = self.client.get(self.list_create_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]['username'], 'test')
        self.assertEqual(response.data[1]['username'], 'test1')


    def test_get_with_parameter(self):
        response = self.client.get(self.list_create_url + '?username=test')

        self.assertEqual(response.status_code, 200)
        self.assertTrue(len(response.data), 1)
        self.assertEqual(response.data[0]['username'], 'test')


    def test_patch_valid(self):
        response = self.client.patch(
            self.update_destroy_url,
            data={'username': 'updatedtest', 'email': 'updatedtest@example.com'},
            HTTP_AUTHORIZATION=f' Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['username'], 'updatedtest')
        self.assertEqual(response.data['email'], 'updatedtest@example.com')


    def test_patch_invalid_data(self):
        response = self.client.patch(
            self.update_destroy_url,
            data={'username': '', 'email': ''},
            HTTP_AUTHORIZATION=f' Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)


    def test_patch_unauthorized_request(self):
        response = self.client.patch(
            self.update_destroy_url,
            data={'username': 'updatedtest', 'email': 'updatedtest@example.com'},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)


    def test_delete_valid(self):
        response = self.client.delete(
            self.update_destroy_url,
            HTTP_AUTHORIZATION=f' Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 204)


    def test_patch_unauthorized_request(self):
        response = self.client.patch(
            self.update_destroy_url,
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

