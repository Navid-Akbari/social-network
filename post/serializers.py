from django.contrib.auth import get_user_model

from rest_framework import serializers

from account.serializers import UserSerializer
from .models import Post

User = get_user_model()


class PostSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Post
        fields = ['user', 'body', 'created_at', 'last_edited']
        extra_kwargs = {
            'created_at': {'read_only': True},
            'last_edited': {'read_only': True},
        }


    def create(self, validated_data):
        user = self.context['request'].user
        
        if not isinstance(user, User):
            raise serializers.ValidationError(
                {'user': ['User must be authenticated and a valid user instance.']}
            )

        validated_data['user'] = user

        return super().create(validated_data)


    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = UserSerializer(instance.user).data
        return representation
