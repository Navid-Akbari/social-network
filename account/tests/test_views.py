from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils import timezone

from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta
import json

from account.utils import generate_verification_token

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
        response_data = json.loads(response.content)
        self.assertEqual(response_data['username'][0], 'This field may not be blank.')


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
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['username'], 'updatedtest')
        self.assertEqual(response.data['email'], 'updatedtest@example.com')


    def test_patch_invalid_data(self):
        response = self.client.patch(
            self.update_destroy_url,
            data={'username': '', 'email': ''},
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['username'][0], 'This field may not be blank.')


    def test_patch_unauthorized_request(self):
        response = self.client.patch(
            self.update_destroy_url,
            data={'username': 'updatedtest', 'email': 'updatedtest@example.com'},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 403)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['error']['message'], 'Request forbidden -- authorization will not help')
        


    def test_delete_valid(self):
        response = self.client.delete(
            self.update_destroy_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 204)


    def test_delete_unauthorized_request(self):
        response = self.client.delete(
            self.update_destroy_url,
        )

        self.assertEqual(response.status_code, 403)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['detail'], 'Authentication credentials were not provided.')


class TestEmailVerification(TestCase):

    def setUp(self):
        settings.EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
        self.verify_email_url = reverse('verify_email')
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321',
        )
        self.access_token = AccessToken.for_user(user=self.user)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))


    def test_email_verification_valid_post(self):
        response = self.client.post(
            self.verify_email_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'An email has been sent.')


    def test_email_verification_already_verified_post(self):
        self.user.email_verified = True
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'This email has already been verified.')



    def test_email_verification_has_token_post(self):
        self.user.verification_code_expiration = timezone.now() + timedelta(minutes=5)
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'An email has been sent recently.')


    def test_email_verification_valid_get(self):
        self.user.verification_code = generate_verification_token(32)
        self.user.save()

        response = self.client.get(
            self.verify_email_url
            + f'?uidb64={self.uidb64}'
            + f'&token={self.user.verification_code}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Email verified.')


    def test_email_verification_missing_params_get(self):
        response = self.client.get(self.verify_email_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'parameters are missing.')


    def test_email_verification_already_verified_get(self):
        self.user.verification_code = generate_verification_token(32)
        self.user.email_verified = True
        self.user.save()

        response = self.client.get(
            self.verify_email_url
            + f'?uidb64={self.uidb64}'
            + f'&token={self.user.verification_code}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'This email has already been verified.')


    def test_email_verification_token_expired_get(self):
        self.user.verification_code = generate_verification_token(32)
        self.user.verification_code_expiration = timezone.now() - timedelta(minutes=10)
        self.user.save()

        response = self.client.get(
            self.verify_email_url
            + f'?uidb64={self.uidb64}'
            + f'&token={self.user.verification_code}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'The verification token has expired.')


    def test_email_verification_wrong_token_get(self):
        self.user.verification_code = generate_verification_token(32)
        self.user.save()

        response = self.client.get(
            self.verify_email_url
            + f'?uidb64={self.uidb64}'
            + f'&token={self.user.verification_code}abcd'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Invalid Token.')
