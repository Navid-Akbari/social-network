from django.urls import reverse
from django.test import TestCase, RequestFactory
from django.db import IntegrityError
from django.conf import settings

from rest_framework import status
from rest_framework.test import APITestCase
import datetime
import jwt

from .serializers import UserSerializer
from .models import CustomUser
from .views import VerifyEmail
from .utils import generate_verification_token


class CustomUserModelTest(TestCase):
    def test_create_user_success(self):
        user = CustomUser.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='testpassword'
        )
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'testuser')
        self.assertTrue(user.check_password('testpassword'))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_superuser(self):
        superuser = CustomUser.objects.create_superuser(
            email='superuser@example.com',
            username='superuser',
            password='superpassword',
            first_name = 'test',
            last_name = 'testable',
        )

        self.assertEqual(superuser.email, 'superuser@example.com')
        self.assertEqual(superuser.username, 'superuser')
        self.assertEqual(superuser.first_name, 'test')
        self.assertEqual(superuser.last_name, 'testable')
        self.assertTrue(superuser.check_password('superpassword'))
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)

    def test_unique_username(self):
        CustomUser.objects.create_user(
            email='test1@example.com',
            username='testuser',
            password='testpassword1'
        )
        with self.assertRaises(IntegrityError):
            CustomUser.objects.create_user(
                email='test2@example.com',
                username='testuser',
                password='testpassword2'
            )


class UserSerializerTest(TestCase):
    def test_create_user_success(self):
        user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword',
        }
        serializer = UserSerializer(data=user_data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertIsInstance(user, CustomUser)
        self.assertTrue(user.check_password(user_data['password']))

    def test_create_user_fail(self):
        user_data = {
            'username': '',
            'email': '',
            'password': '',
        }

        serializer = UserSerializer(data=user_data)
        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['password'], ['This field may not be blank.'])
        self.assertEqual(serializer.errors['email'], ['This field may not be blank.'])
        self.assertEqual(serializer.errors['username'], ['This field may not be blank.'])


class RegisterTestCase(APITestCase):
    def setUp(self):
        self.url = reverse('register')

    def test_register_user_success(self):
        data = {
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'testemail@test.com',
        }
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(CustomUser.objects.filter(username='testuser').exists())
        self.assertTrue('user' in response.data)
        self.assertEqual(response.data['user']['username'], data['username'])

    def test_register_user_failed(self):
        data = {
            'username': '',
            'password': '',
            'email': '',
        }
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(CustomUser.objects.filter(username='testuser').exists())
        self.assertTrue(response.data['email'] == ['This field may not be blank.'])
        self.assertTrue(response.data['username'] == ['This field may not be blank.'])
        self.assertTrue(response.data['password'] == ['This field may not be blank.'])

    def test_register_user_phone_number_validation(self):
        data = {
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'testemail@test.com',
            'phone_number': '99'
        }
        response = self.client.post(self.url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(CustomUser.objects.filter(username='testuser').exists())
        self.assertTrue(response.data['phone_number'] == [
            "Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        ])

