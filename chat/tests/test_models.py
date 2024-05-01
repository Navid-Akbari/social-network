from django.contrib.auth import get_user_model
from django.test import TestCase

from chat.models import PrivateChat, DirectMessage

User = get_user_model()


class TestPrivateChatModel(TestCase):
    
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

    def test_valid_input(self):
        PrivateChat.objects.create().users.set([self.user, self.user1])

        private_chat = PrivateChat.objects.all().first()
        users = private_chat.users.all()

        self.assertIsNotNone(private_chat)
        self.assertIn(self.user, users)
        self.assertIn(self.user1, users)


class TestDirectMessageModel(TestCase):
    
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
        self.private_chat = PrivateChat.objects.create()
        self.private_chat.users.set([self.user, self.user1])
        
    def test_valid_input(self):
        DirectMessage.objects.create(
            room=self.private_chat,
            sender=self.user,
            message='test message.'
        )

        dm = DirectMessage.objects.all().first()
        self.assertIsNotNone(dm)
        self.assertEqual(dm.room, self.private_chat)
        self.assertEqual(dm.sender, self.user)
