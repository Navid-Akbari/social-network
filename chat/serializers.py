from django.core.exceptions import ValidationError
from rest_framework import serializers

from chat.models import PrivateChat, DirectMessage


class PrivateChatSerializer(serializers.ModelSerializer):

    class Meta:
        model = PrivateChat
        fields = ['id','users', 'name']
        extra_kwargs = {
            'id': {'read_only': True}
        }

    def validate(self, attrs):
        users = attrs.get('users')

        if len(users) != 2:
            raise ValidationError({'error': ['There can only be two users in a conversation.']})

        return super().validate(attrs)


class DirectMessageSerializer(serializers.ModelSerializer):

    class Meta:
        model = DirectMessage
        fields = ['room', 'sender', 'message', 'timestamp']
