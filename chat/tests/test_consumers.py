from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework_simplejwt.tokens import AccessToken

from chat.middleware import JWTAuthMiddleware
from chat.routing import websocket_urlpatterns


User = get_user_model()


class TestChatConsumer(TestCase):

    def setUp(self):
        self.application = JWTAuthMiddleware(URLRouter((websocket_urlpatterns)))
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
        self.user3 = User.objects.create_user(
            username='test3',
            email='test3@example.com',
            password='testing321'
        )

        self.user_access_token = AccessToken.for_user(self.user)
        self.user1_access_token = AccessToken.for_user(self.user1)
        self.user2_access_token = AccessToken.for_user(self.user2)
        self.user3_access_token = AccessToken.for_user(self.user3)

    async def test_two_communications_at_once(self):
        communicator = WebsocketCommunicator(self.application, f'ws/chat/{self.user1.pk}/?token={self.user_access_token}')
        communicator1 = WebsocketCommunicator(self.application, f'ws/chat/{self.user.pk}/?token={self.user1_access_token}')
        communicator2 = WebsocketCommunicator(self.application, f'ws/chat/{self.user3.pk}/?token={self.user2_access_token}')
        communicator3 = WebsocketCommunicator(self.application, f'ws/chat/{self.user2.pk}/?token={self.user3_access_token}')
        connected, subprotocol = await communicator.connect()
        connected1, subprotocol1 = await communicator1.connect()
        connected2, subprotocol2 = await communicator2.connect()
        connected3, subprotocol3 = await communicator3.connect()

        self.assertTrue(connected)
        self.assertTrue(connected1)
        self.assertTrue(connected2)
        self.assertTrue(connected3)

        await communicator.send_json_to({
            'message': 'Hello from user',
            'sender': self.user.pk,
        })

        user1_received_response = await communicator1.receive_json_from()
        self.assertEqual(user1_received_response['message'], 'Hello from user')


        await communicator2.send_json_to({
            'message': 'Hello from user2',
            'sender': self.user2.pk,
        })

        user3_received_response = await communicator3.receive_json_from()
        self.assertEqual(user3_received_response['message'], 'Hello from user2')

        await communicator.disconnect()
        await communicator1.disconnect()
        await communicator2.disconnect()
        await communicator3.disconnect()


    async def test_chat_history_is_retrieved(self):
        communicator = WebsocketCommunicator(self.application, f'ws/chat/{self.user1.pk}/?token={self.user_access_token}')
        connected, subprotocol = await communicator.connect()

        self.assertTrue(connected)

        await communicator.send_json_to({
            'message': 'Hello from user',
            'sender': self.user.pk,
        })
        await communicator.send_json_to({
            'message': 'How are you?',
            'sender': self.user.pk,
        })
        await communicator.send_json_to({
            'message': 'Are you getting these messages?',
            'sender': self.user.pk,
        })

        await communicator.disconnect()

        communicator1 = WebsocketCommunicator(self.application, f'ws/chat/{self.user.pk}/?token={self.user1_access_token}')
        connected1, subprotocol1 = await communicator1.connect()

        self.assertTrue(connected1)

        response = []
        response.append(await communicator1.receive_json_from())
        response.append(await communicator1.receive_json_from())
        response.append(await communicator1.receive_json_from())

        self.assertEqual(len(response), 3)

        await communicator1.disconnect()

