from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
from django.conf import settings
from django.test import TestCase, Client
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils import timezone

from rest_framework_simplejwt.tokens import AccessToken
from datetime import timedelta
import json

from account.utils import generate_verification_token

User = get_user_model()


class TestUserAccountManager(TestCase):

    def setUp(self):
        self.client = Client()
        self.list_create_url = reverse('account:users')
        self.first_test_user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.second_test_user = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.admin = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='testing321'
        )
        self.update_destroy_url = reverse(
            'account:users_detail',
            kwargs={'pk':self.second_test_user.pk}
        )
        self.test_user_access_token = AccessToken.for_user(user=self.first_test_user)
        self.second_test_user_access_token = AccessToken.for_user(user=self.second_test_user)
        self.admin_access_token = AccessToken.for_user(user=self.admin)

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

        user_from_db = User.objects.get(username='test2')

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
        response = self.client.get(
            self.list_create_url,
            HTTP_AUTHORIZATION=f'Bearer {self.admin_access_token}',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 3)
        self.assertEqual(response.data[0]['username'], 'test')
        self.assertEqual(response.data[1]['username'], 'test1')
        self.assertEqual(response.data[2]['username'], 'admin')

    def test_get_with_parameter(self):
        response = self.client.get(
            self.list_create_url + '?username=test',
            HTTP_AUTHORIZATION=f'Bearer {self.admin_access_token}',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['username'], 'test')

    def test_patch_valid(self):
        response = self.client.patch(
            self.update_destroy_url,
            data={'username': 'updatedtest', 'email': 'updatedtest@example.com'},
            HTTP_AUTHORIZATION=f'Bearer {self.second_test_user_access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['username'], 'updatedtest')
        self.assertEqual(response.data['email'], 'updatedtest@example.com')
        self.assertEqual(response.data['id'], 2)

    def test_patch_invalid_data(self):
        response = self.client.patch(
            self.update_destroy_url,
            data={'username': '', 'email': ''},
            HTTP_AUTHORIZATION=f'Bearer {self.second_test_user_access_token}',
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

        self.assertEqual(response.status_code, 401)

        response_data = json.loads(response.content)
        self.assertEqual(
            response_data['error']['message'],
            'No permission -- see authorization schemes'
        )

    def test_delete_valid(self):
        response = self.client.delete(
            self.update_destroy_url,
            HTTP_AUTHORIZATION=f'Bearer {self.second_test_user_access_token}',
        )

        self.assertEqual(response.status_code, 204)

    def test_delete_unauthorized_request(self):
        response = self.client.delete(
            self.update_destroy_url,
        )

        self.assertEqual(response.status_code, 401)

        response_data = json.loads(response.content)
        self.assertEqual(response_data['detail'], 'Authentication credentials were not provided.')


class TestRequestEmailVerification(TestCase):

    def setUp(self):
        settings.EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
        self.request_email_verification_url = reverse('account:request_email_verification')
        self.client = Client()
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.test_user_access_token = AccessToken.for_user(user=self.user)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))

    def test_request_email_verification_valid_post(self):
        response = self.client.post(
            self.request_email_verification_url,
            HTTP_AUTHORIZATION=f'Bearer {self.test_user_access_token}',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'An email has been sent.')

    def test_request_email_verification_already_verified_post(self):
        self.user.email_verified = True
        self.user.save()

        response = self.client.post(
            self.request_email_verification_url,
            HTTP_AUTHORIZATION=f'Bearer {self.test_user_access_token}',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'This email has already been verified.')

    def test_request_email_verification_has_token(self):
        self.user.verification_token_expiration = timezone.now() + timedelta(minutes=5)
        self.user.save()

        response = self.client.post(
            self.request_email_verification_url,
            HTTP_AUTHORIZATION=f'Bearer {self.test_user_access_token}',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'An email has been sent recently.')


class TestVerifyEmail(TestCase):

    def setUp(self):
        self.verify_email_url = reverse('account:verify_email')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.verification_token = generate_verification_token()
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))

    def test_verify_email_valid(self):
        self.user.verification_token = self.verification_token
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': self.uidb64},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Email verified.')

    def test_verify_email_missing_params(self):
        response = self.client.post(self.verify_email_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Parameters are missing.')

    def test_verify_email_already_verified(self):
        self.user.email_verified = True
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': self.uidb64},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'This email has already been verified.')

    def test_verify_email_token_has_expired(self):
        self.user.verification_token_expiration = timezone.now() - timedelta(minutes=10)
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': self.uidb64},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'The verification token has expired.')

    def test_verify_email_wrong_token(self):
        response = self.client.post(
            self.verify_email_url,
            data={'token': 'abcd', 'uidb64': self.uidb64},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Invalid Token.')
    
    def test_verify_email_bad_uidb64(self):
        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': 'abcd'},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Bad uidb64.')


class TestRequestPasswordReset(TestCase):
    
    def setUp(self):
        settings.EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
        self.request_password_reset_url = reverse('account:request_password_reset')
        self.client = Client()
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
    
    def test_request_password_reset_valid(self):
        response = self.client.post(
            self.request_password_reset_url,
            data={'email': 'test@example.com'},
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'A password reset email has been sent.')

    def test_request_password_reset_missing_param(self):
        response = self.client.post(self.request_password_reset_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Email missing.')

    def test_request_password_reset_throttle(self):
        self.user.verification_token_expiration = timezone.now() + timedelta(minutes=5)
        self.user.save()

        response = self.client.post(
            self.request_password_reset_url,
            data={'email': 'test@example.com'}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'An Email has been sent recently.')

    def test_request_password_reset_wrong_email(self):
        response = self.client.post(
            self.request_password_reset_url,
            data={'email': 'test1@example.com'}
        )
        response_data = json.loads(response.content)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response_data['detail'], 'Not found.')


class TestResetPassword(TestCase):

    def setUp(self):
        self.reset_password_url = reverse('account:reset_password')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.verification_token = generate_verification_token()
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.access_token = AccessToken.for_user(user=self.user)

    def test_reset_password_with_email_valid(self):
        self.user.verification_token = self.verification_token
        self.user.save()
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Password changed successfully.')

    def test_reset_password_with_email_missing_params(self):
        response = self.client.post(self.reset_password_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['error'],
            'Missing Parameters. (token, uidb64, password1, password2)'
        )

    def test_reset_password_with_email_mismatched_passwords(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting4321'
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Passwords do not match.')

    def test_reset_password_with_email_bad_uidb64(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': 'abcd',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            },
            content_type='application/json'
        )

        response_data = json.loads(response.content)

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response_data['detail'], 'Passwords do not match.')

    def test_reset_password_with_email_bad_uidb64(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': 'abcd',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Bad uidb64.')

    def test_reset_password_with_email_bad_input_for_user_lookup(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64 + 'a',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Bad input for user lookup.')

    def test_reset_password_with_email_expired_token(self):
        self.user.verification_token_expiration = timezone.now() - timedelta(minutes=5)
        self.user.save()

        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Token has expired.')

    def test_reset_password_with_email_wrong_token(self):
        self.user.verification_token = self.verification_token
        self.user.save()

        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token + 'a',
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Invalid Token.')

    def test_reset_password_with_jwt_token_valid(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing321',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321',
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Password changed successfully.')

    def test_reset_password_with_jwt_token_bad_token(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing321',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321',
            },
            HTTP_AUTHORIZATION=f'Bearer abcd',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'][0:19], 'Problem with token:')

    def test_reset_password_with_jwt_token_missing_params(self):
        response = self.client.post(
            self.reset_password_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['error'], 
            'Missing parameters. (old_password, password1, password2)'
        )

    def test_reset_password_with_jwt_token_wrong_old_password(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321',
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Old password is not correct.')

    def test_reset_password_with_jwt_token_mismatched_password(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing321',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting',
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Passwords do not match.')
