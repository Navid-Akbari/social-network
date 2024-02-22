from django.contrib.auth import get_user_model

from rest_framework import serializers

from account.serializers import UserSerializer
from .models import Post, Like

User = get_user_model()


class PostSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Post
        fields = ['id', 'user', 'body', 'created_at', 'last_edited']
        extra_kwargs = {
            'created_at': {'read_only': True},
            'last_edited': {'read_only': True}
        }

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = UserSerializer(instance.user).data
        return representation


class LikeSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    post = serializers.PrimaryKeyRelatedField(queryset=Post.objects.all())

    class Meta:
        model = Like
        fields = ['post', 'user', 'is_like']

    # overridding the default behavior and removing the self.get_unique_together_validators()
    def get_validators(self):
        validators = getattr(getattr(self, 'Meta', None), 'validators', None)
        if validators is not None:
            return list(validators)

        return (
            self.get_unique_for_date_validators()
        )

    def create(self, validated_data):
        is_like = validated_data['is_like']

        existing_like = Like.objects.filter(
            user=validated_data['user'], 
            post=validated_data['post']
        ).first()

        if existing_like:
            if existing_like.is_like == is_like:
                existing_like.delete()
                return {'message': 'Like removed successfully.'}
            else:
                existing_like.is_like = is_like
                existing_like.save()
                return existing_like

        return Like.objects.create(**validated_data)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['user'] = instance.user.pk
        representation['post'] = instance.post.pk
