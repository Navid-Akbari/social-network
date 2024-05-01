import json
from datetime import datetime

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer
from channels.exceptions import StopConsumer
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

from chat.models import PrivateChat, DirectMessage
from chat.serializers import PrivateChatSerializer, DirectMessageSerializer

User = get_user_model()


class ChatConsumer(WebsocketConsumer):

    def __init__(self, *args, **kwargs):
        self.room_group_name = None
        super().__init__(*args, **kwargs)

    def websocket_connect(self, message):
        receiver_id = self.scope['url_route']['kwargs']['receiver_id']

        try:
            receiver_id = int(receiver_id)
        except ValueError:
            self.websocket_disconnect(message={'error': ['Invalid receiver id type. Expected a digit.']})

        if receiver_id == self.scope['user'].id:
            self.websocket_disconnect(message={'error': ['Messages cannot be sent to self.']})

        self.receiver = self.get_user(receiver_id)
        private_chat = PrivateChat.objects.filter(users__in=[self.receiver, self.scope['user']])

        if not private_chat.exists():
            serializer = PrivateChatSerializer(
                data={
                    'name': f'chat_room_{self.receiver.pk}_{self.scope["user"].pk}',
                    'users': [self.receiver.pk, self.scope['user'].pk]
                }
            )
            serializer.is_valid()
            self.private_chat = serializer.save()
        else:
            self.private_chat = private_chat.first()

        self.room_group_name = self.private_chat.name
        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name, self.channel_name
        )

        self.connect()
    
        dm_history = DirectMessage.objects.filter(room=self.private_chat)

        if dm_history.exists():
            for dm in dm_history:
                self.send(text_data=
                    {
                        'message': dm.message,
                        'sender': dm.sender.username,
                        'timestamp': datetime.strftime(dm.timestamp, '%d %b, %H:%M')
                    }
                )

    def websocket_receive(self, message):
        message = json.loads(message['text'])
        if 'message' not in message:
            self.send(text_data={'error': ['No message has been sent.']})
        else:
            self.receive(text_data=message['message'])

    def receive(self, text_data=None, bytes_data=None):
        serializer = DirectMessageSerializer(
            data={
                'room': self.private_chat.pk,
                'sender': self.scope['user'].pk,
                'message': text_data
            }
        )

        if serializer.is_valid():
            data = serializer.save()
            async_to_sync(self.channel_layer.group_send)(
                self.room_group_name,
                {
                    'type': 'group.message',
                    'sender': self.scope['user'].username,
                    'message': data.message,
                    'timestamp': datetime.strftime(data.timestamp, '%d %b, %H:%M')
                }
            )
        else:
            serializer.is_valid()
            errors = []
            for key in serializer.errors:
                errors.append(serializer.errors[key])
            print(errors)
            self.send(text_data={'error': errors})
    
    def websocket_disconnect(self, message):
        if self.room_group_name is not None:
            async_to_sync(self.channel_layer.group_discard)(
                self.room_group_name, self.channel_name
            )

        self.disconnect(message)
        raise StopConsumer()

    def disconnect(self, code):
        self.send(text_data=code)

    def send(self, text_data=None, bytes_data=None, close=False):
        text_data = json.dumps(text_data)
        return super().send(text_data, bytes_data, close)

    def group_message(self, event):
        self.send(text_data=
            {
                'message': event['message'],
                'sender': event['sender'],
                'timestamp': event['timestamp']
            }
        )

    def get_user(self, user_id):
        try:
            user = User.objects.get(id=user_id)
            return user
        except ObjectDoesNotExist:
            self.websocket_disconnect(message={'error': ['User was not found.']})
