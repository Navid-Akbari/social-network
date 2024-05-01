from django.contrib.auth import get_user_model
from django.test import TestCase

from chat.serializers import PrivateChatSerializer, DirectMessageSerializer

User = get_user_model()


class TestPrivateChatSerializer(TestCase):

    def setUp(self):
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

    def test_valid_input(self):
        serializer = PrivateChatSerializer(
            data={'users': [self.user.pk, self.user1.pk]}
        )

        self.assertTrue(serializer.is_valid())
        self.assertIn(self.user.pk, serializer.data['users'])

    def test_invalid_user_input(self):
        serializer = PrivateChatSerializer(
            data={'users': ['', '']}
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['users'][0],
            'Incorrect type. Expected pk value, received str.'
        )

    def test_only_two_users(self):
        serializer = PrivateChatSerializer(
            data={'users': [self.user.pk, self.user1.pk, self.user2.pk]}
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['error'][0],
            'There can only be two users in a conversation.'
        )


class TestDirectMessageSerializer(TestCase):

    def setUp(self):
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
        serializer = PrivateChatSerializer(data={'users': [self.user.pk, self.user1.pk]})
        serializer.is_valid()
        self.private_chat = serializer.save()
    
    def test_valid_input(self):
        serializer = DirectMessageSerializer(
            data={
                'room': self.private_chat.pk,
                'sender': self.user.pk,
                'message': 'test message.'
            }
        )

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.data['room'], self.private_chat.pk)
        self.assertEqual(serializer.data['sender'], self.user.pk)
