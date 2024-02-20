from django.contrib.auth import get_user_model

from rest_framework import serializers

from account.serializers import UserSerializer
from .models import Post

User = get_user_model()


class PostSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Post
        fields = ['id', 'user', 'body', 'created_at', 'last_edited']
        extra_kwargs = {
            'created_at': {'read_only': True},
            'last_edited': {'read_only': True},
        }

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = UserSerializer(instance.user).data
        return representation
