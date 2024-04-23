from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils import timezone

from datetime import timedelta
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.test import APITestCase, override_settings
from PIL import Image
import io
import os


from account.utils import generate_verification_token
from account.models import FriendRequest, Friend
from social_network.settings import BASE_DIR, TEST_MEDIA_ROOT

User = get_user_model()


class TestUserListCreate(APITestCase):

    def setUp(self):
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
        self.test_user_access_token = AccessToken.for_user(user=self.first_test_user)
        self.admin_access_token = AccessToken.for_user(user=self.admin)

    def test_valid_post(self):
        response = self.client.post(
            self.list_create_url, 
            data={
                'username': 'test2',
                'email': 'test2@example.com',
                'password': 'testing321'
            }, 
        )

        user = User.objects.get(username='test2')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['username'], 'test2')
        self.assertEqual(response.data['email'], 'test2@example.com')
        self.assertTrue(check_password('testing321', user.password))

    def test_empty_username_email_password(self):
        response = self.client.post(
            self.list_create_url, 
            data={
                'username': '',
                'email': '',
                'password': ''
            }
        )

        self.assertTrue(response.status_code, 400)
        self.assertEqual(response.data['username'][0], 'This field may not be blank.')
        self.assertEqual(response.data['email'][0], 'This field may not be blank.')
        self.assertEqual(response.data['password'][0], 'This field may not be blank.')

    def test_valid_get(self):
        response = self.client.get(
            self.list_create_url,
            HTTP_AUTHORIZATION=f'Bearer {self.admin_access_token}',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 3)
        self.assertEqual(response.data[0]['username'], 'test')
        self.assertEqual(response.data[1]['username'], 'test1')
        self.assertEqual(response.data[2]['username'], 'admin')

    def test_valid_get_with_parameter(self):
        response = self.client.get(
            self.list_create_url + '?username=test',
            HTTP_AUTHORIZATION=f'Bearer {self.admin_access_token}',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['username'], 'test')

    def test_unauthenticated_get_request(self):
        response = self.client.get(self.list_create_url)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_unauthorized_get_request(self):
        response = self.client.get(
            self.list_create_url,
            HTTP_AUTHORIZATION=f'Bearer {self.test_user_access_token}',
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            'You do not have permission to perform this action.'
        )


class TestUserRetrieveUpdateDestroy(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)
        self.admin = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='testing321'
        )
        self.admin_access_token = AccessToken.for_user(user=self.admin)

    def test_valid_get(self):
        response = self.client.get(
            reverse('account:users_detail', kwargs={'pk': 1}),
            HTTP_AUTHORIZATION=f'Bearer {self.admin_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['username'], 'test')
        self.assertEqual(response.data['id'], 1)

    def test_unauthenticated_get(self):
        response = self.client.get(
            reverse('account:users_detail', kwargs={'pk': 1}),
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )
    
    def test_user_not_found(self):
        response = self.client.get(
            reverse('account:users_detail', kwargs={'pk': 3}),
            HTTP_AUTHORIZATION=f'Bearer {self.admin_access_token}'
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.data['detail'],
            'Not found.'
        )

    def test_valid_patch(self):
        response = self.client.patch(
            reverse('account:users_detail', kwargs={'pk': 1}),
            data={'username': 'updatedtest', 'email': 'updatedtest@example.com'},
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['username'], 'updatedtest')
        self.assertEqual(response.data['email'], 'updatedtest@example.com')
        self.assertEqual(response.data['id'], 1)

    def test_empty_username_email(self):
        response = self.client.patch(
            reverse('account:users_detail', kwargs={'pk': 1}),
            data={'username': '', 'email': ''},
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['username'][0], 'This field may not be blank.')

    def test_unauthorized_patch(self):
        response = self.client.patch(
            reverse('account:users_detail', kwargs={'pk': 2}),
            data={'username': 'updatedtest', 'email': 'updatedtest@example.com'},
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            'User does not have permission to access this object.'
        )

    def test_valid_delete(self):
        response = self.client.delete(
            reverse('account:users_detail', kwargs={'pk': 1}),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 204)


class TestUserRetrieveWithToken(APITestCase):

    def setUp(self):
        self.users_detail_token_url = reverse('account:users_detail_token')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)

    def test_valid(self):
        response = self.client.get(
            self.users_detail_token_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['id'], self.user.pk)
    
    def test_unauthenticated(self):
        response = self.client.get(
            self.users_detail_token_url,
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT)
class TestProfileRetrieveUpdate(APITestCase):

    def setUp(self):
        self.url = reverse('account:profile', kwargs={'pk':1})
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.access_token1 = AccessToken.for_user(user=self.user1)
        with Image.open(BASE_DIR / 'account/tests/cat.jpg') as im:
            image_io = io.BytesIO()
            im.save(image_io, format='JPEG')
            image_io.seek(0)
            self.image = SimpleUploadedFile('cat.jpg', image_io.read(), content_type='image/jpeg')

    def test_unauthenticated_request(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['detail'], 'Authentication credentials were not provided.')

    def test_unauthorized_request(self):
        response = self.client.put(
            self.url,
            data={'image': self.image},
            format='multipart',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token1}'
        )

        self.assertEqual(response.status_code, 403)
        self.assertAlmostEqual(response.data['detail'], 'User does not have permission to access this object.')

    def test_valid_put_request(self):
        response = self.client.put(
            self.url,
            data={'image': self.image},
            format='multipart',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('image', response.data)
        self.assertTrue(os.path.exists(TEST_MEDIA_ROOT / 'cat.jpg'))

    def test_invalid_image_data(self):
        with open(BASE_DIR / 'account/tests/file.txt', 'rb') as f:
            invalid_image_data = f.read()
        image = SimpleUploadedFile('test.jpg', invalid_image_data, content_type='image/jpeg')
        response = self.client.put(
            self.url,
            data={'image': image},
            format='multipart',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            str(response.data['image'][0]), 
            'Upload a valid image. The file you uploaded was either not an image or a corrupted image.'
        )

    def test_valid_get_request(self):
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertTrue(response.status_code, 200)
        self.assertIn('user', response.data)
        self.assertIn('image', response.data)

    def tearDown(self):
        for file in ['cat.jpg']:
            if os.path.exists(TEST_MEDIA_ROOT / file):
                os.remove(TEST_MEDIA_ROOT / file)

        return super().tearDown()


class TestRequestEmailVerification(APITestCase):

    def setUp(self):
        settings.EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
        self.request_email_verification_url = reverse('account:request_email_verification')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.test_user_access_token = AccessToken.for_user(user=self.user)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))

    def test_valid(self):
        response = self.client.post(
            self.request_email_verification_url,
            HTTP_AUTHORIZATION=f'Bearer {self.test_user_access_token}',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'An email has been sent.')

    def test_already_verified(self):
        self.user.email_verified = True
        self.user.save()

        response = self.client.post(
            self.request_email_verification_url,
            HTTP_AUTHORIZATION=f'Bearer {self.test_user_access_token}',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'This email has already been verified.')

    def test_still_has_active_token(self):
        self.user.verification_token_expiration = timezone.now() + timedelta(minutes=5)
        self.user.save()

        response = self.client.post(
            self.request_email_verification_url,
            HTTP_AUTHORIZATION=f'Bearer {self.test_user_access_token}',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'An email has been sent recently.')


class TestVerifyEmail(APITestCase):

    def setUp(self):
        self.verify_email_url = reverse('account:verify_email')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.verification_token = generate_verification_token()
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))

    def test_valid(self):
        self.user.verification_token = self.verification_token
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': self.uidb64}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Email verified.')

    def test_missing_params(self):
        response = self.client.post(self.verify_email_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Parameters are missing.')

    def test_already_verified(self):
        self.user.email_verified = True
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': self.uidb64}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'This email has already been verified.')

    def test_token_has_expired(self):
        self.user.verification_token_expiration = timezone.now() - timedelta(minutes=10)
        self.user.save()

        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': self.uidb64}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'The verification token has expired.')

    def test_wrong_token(self):
        response = self.client.post(
            self.verify_email_url,
            data={'token': 'abcd', 'uidb64': self.uidb64}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Invalid Token.')

    def test_bad_uidb64(self):
        response = self.client.post(
            self.verify_email_url,
            data={'token': self.verification_token, 'uidb64': 'abcd'}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Bad uidb64.')


class TestRequestPasswordReset(APITestCase):

    def setUp(self):
        settings.EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
        self.request_password_reset_url = reverse('account:request_password_reset')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )

    def test_valid(self):
        response = self.client.post(
            self.request_password_reset_url,
            data={'email': 'test@example.com'}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'A password reset email has been sent.')

    def test_missing_param(self):
        response = self.client.post(self.request_password_reset_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Email missing.')

    def test_still_has_active_token(self):
        self.user.verification_token_expiration = timezone.now() + timedelta(minutes=5)
        self.user.save()

        response = self.client.post(
            self.request_password_reset_url,
            data={'email': 'test@example.com'}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'An Email has been sent recently.')

    def test_wrong_email(self):
        response = self.client.post(
            self.request_password_reset_url,
            data={'email': 'test1@example.com'}
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data['detail'], 'Not found.')
        

"""
The ones with through_email at the end are as the name suggests, for requests that have been made
by requesting an email. The ones that end with through_token, are testing part of the view that
handles authenticated requests.
"""
class TestResetPassword(APITestCase):

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

    def test_valid_through_email(self):
        self.user.verification_token = self.verification_token
        self.user.save()
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Password changed successfully.')

    def test_missing_params_through_email(self):
        response = self.client.post(self.reset_password_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['error'],
            'Missing Parameters. (token, uidb64, password1, password2)'
        )

    def test_mismatched_passwords_through_email(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting4321'
            }
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Passwords do not match.')

    def test_bad_uidb64_through_email(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': 'abcd',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            }
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Bad uidb64.')

    def test_bad_input_for_user_lookup_through_email(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64 + 'a',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            }
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Bad input for user lookup.')

    def test_token_has_expired_through_email(self):
        self.user.verification_token_expiration = timezone.now() - timedelta(minutes=5)
        self.user.save()

        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token,
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            }
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Token has expired.')

    def test_wrong_token_through_email(self):
        self.user.verification_token = self.verification_token
        self.user.save()

        response = self.client.post(
            self.reset_password_url,
            data={
                'token': self.verification_token + 'a',
                'uidb64': self.uidb64,
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321'
            }
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Invalid Token.')

    def test_valid_through_token(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing321',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321',
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], 'Password changed successfully.')

    def test_bad_token_through_token(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing321',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321',
            },
            HTTP_AUTHORIZATION=f'Bearer abcd'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'][0:19], 'Problem with token:')

    def test_missing_params_through_token(self):
        response = self.client.post(
            self.reset_password_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['error'], 
            'Missing parameters. (old_password, password1, password2)'
        )

    def test_wrong_old_password_through_token(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting321',
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Old password is not correct.')

    def test_mismatched_passwords_through_token(self):
        response = self.client.post(
            self.reset_password_url,
            data={
                'old_password': 'testing321',
                'password1': 'updatedtesting321',
                'password2': 'updatedtesting',
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Passwords do not match.')


class TestFriendRequestListCreateDestroy(APITestCase):

    def setUp(self):
        self.url = reverse('account:friend_request')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.user2 = User.objects.create_user(
            username='test2',
            email='test2@example.com',
            password='testing321'
        )
        self.friend_request = FriendRequest.objects.create(
            from_user=self.user,
            to_user=self.user1
        )
        self.friend_request = FriendRequest.objects.create(
            from_user=self.user,
            to_user=self.user2
        )
        self.user_access_token = AccessToken.for_user(self.user)
        self.user1_access_token = AccessToken.for_user(self.user1)

    def test_valid_get_request(self):
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]['from_user'], self.user.pk)
        self.assertEqual(response.data[0]['to_user'], self.user1.pk)

    def test_unauthenticated_request(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['detail'], 'Authentication credentials were not provided.')

    def test_valid_post_request(self):
        response = self.client.post(
            self.url,
            data={'from_user': self.user1.pk, 'to_user': self.user2.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['from_user'], self.user1.pk)

    def test_user_friends_themselves(self):
        response = self.client.post(
            self.url,
            data={'from_user': self.user1.pk, 'to_user': self.user1.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'][0], 'Users cannot friend themselves.')

    def test_unique_friend_set(self):
        response = self.client.post(
            self.url,
            data={'from_user': self.user.pk, 'to_user': self.user1.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['non_field_errors'][0], 'The fields from_user, to_user must make a unique set.')

    def test_invalid_authentication_token(self):
        response = self.client.post(
            self.url,
            data={'from_user': self.user1.pk, 'to_user': self.user.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['error'],
            'Token is not valid. It does not belong to the requestor.'
        )

    def test_valid_delete(self):
        response = self.client.delete(
            self.url,
            data={'from_user': 1, 'to_user': 2},
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 204)
    
    def test_invalid_delete_data(self):
        response = self.client.delete(
            self.url,
            data={'from_user': 1, 'to_user': ''},
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'], 'Sender ID and receiver ID must be provided.')


class TestFriendListCreateDestroy(APITestCase):

    def setUp(self):
        self.url = reverse('account:manage_friends')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.user2 = User.objects.create_user(
            username='test2',
            email='test2@example.com',
            password='testing321'
        )
        self.user_access_token = AccessToken.for_user(self.user)
        self.user1_access_token = AccessToken.for_user(self.user1)
        Friend.objects.create(
            first_user = self.user,
            second_user = self.user1
        )
        Friend.objects.create(
            first_user = self.user,
            second_user = self.user2
        )

    def test_valid_get(self):
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION = f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]['first_user'], self.user.pk)
        self.assertEqual(response.data[1]['first_user'], self.user.pk)
    
    def test_unauthenticated_request(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['detail'], 'Authentication credentials were not provided.')

    def test_valid_post(self):
        response = self.client.post(
            self.url,
            data={'first_user': self.user2.pk, 'second_user': self.user1.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['first_user'], self.user2.pk)

    def test_bad_first_user_data(self):
        response = self.client.post(
            self.url,
            data={'first_user': '', 'second_user': self.user1.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        print()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['first_user'][0], 'This field may not be null.')

    def test_authenticate_token_does_not_belong_to_the_correct_party(self):
        response = self.client.post(
            self.url,
            data={'first_user': self.user1.pk, 'second_user': self.user2.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['error'][0],
            'The request was not accepted by the proper party.'
        )

    def test_valid_delete(self):
        response = self.client.delete(
            self.url,
            data={'user': self.user1.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 204)

    def test_nonexistent_friend_instance(self):
        response = self.client.delete(
            self.url,
            data={'user': self.user2.pk},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'][0], 'Current user is not a friend with the given user.')

    def test_invalid_delete_key_format(self):
        response = self.client.delete(
            self.url,
            data={'bad_data': 2},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'][0], 'Invalid data format.')

    def test_invalid_delete_value_format(self):
        response = self.client.delete(
            self.url,
            data={'user': 'bad_data'},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['error'][0], 'Invalid data format.')
