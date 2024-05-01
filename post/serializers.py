from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.response import Response

from account.serializers import UserSerializer
from .models import Post, Like, Comment

User = get_user_model()


class PostSerializer(serializers.ModelSerializer):

    class Meta:
        model = Post
        fields = ['id', 'user', 'body', 'created_at', 'last_edited']
        extra_kwargs = {
            'created_at': {'read_only': True},
            'last_edited': {'read_only': True},
            'id': {'read_only': True}
        }

    def update(self, instance, validated_data):
        instance.body = validated_data['body']
        instance.save()
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = UserSerializer(instance.user).data
        return representation


class LikeSerializer(serializers.ModelSerializer):

    class Meta:
        model = Like
        fields = ['post', 'user', 'is_like']

    def get_validators(self):
        validators = getattr(getattr(self, 'Meta', None), 'validators', None)
        if validators is not None:
            return list(validators)

        return (
            self.get_unique_for_date_validators()
        )


class CommentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Comment
        fields = ['id', 'post', 'user', 'body', 'created_at']
        extra_kwargs = {
            'created_at': {'read_only': True},
            'id': {'read_only': True}
        } 
    
    def update(self, instance, validated_data):
        if 'body' in validated_data:
            instance.body = validated_data['body']
            instance.save()
            return instance

        return Response({'detail': 'Invalid request data.'})

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = UserSerializer(instance.user).data
        return representation
