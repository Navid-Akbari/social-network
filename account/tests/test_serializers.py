from django.test import TestCase
from django.contrib.auth import get_user_model

from account.serializers import UserSerializer

CustomUser = get_user_model()


class UserSerializerTestCase(TestCase):

    def setUp(self):
        self.data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testing321',
            'first_name': 'test',
            'last_name': 'test',
            'phone_number': '1234567890'
        }

    def test_create_user(self):
        serializer = UserSerializer(data=self.data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()

        self.assertIsNotNone(user)
        self.assertEqual(user.username, self.data['username'])
        self.assertEqual(user.email, self.data['email'])
        self.assertEqual(user.first_name, self.data['first_name'].capitalize())
        self.assertEqual(user.last_name, self.data['last_name'].capitalize())
        self.assertEqual(user.phone_number, self.data['phone_number'])
        self.assertNotEqual(user.password, self.data['password'])
        self.assertTrue(user.check_password(self.data['password']))