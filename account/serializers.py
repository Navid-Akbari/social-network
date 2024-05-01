from PIL import Image

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from rest_framework import serializers

from account.models import Profile, FriendRequest, Friend

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id',
            'password',
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'profile'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'write_only': True},
            'phone_number': {'write_only': True},
            'id': {'read_only': True}
        }

    def get_profile(self, obj):
        profile_instance = Profile.objects.filter(user=obj).first()
        return profile_instance.image.path if profile_instance.image else None

    def validate(self, attrs):
        if attrs.get('first_name'):
            if not attrs.get('last_name'):
                raise ValidationError({'first_name': 'last_name is missing.'})

        if attrs.get('last_name'):
            if not attrs.get('first_name'):
                raise ValidationError({'last_name': 'first_name is missing.'})

        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = Profile
        fields = ['id', 'user', 'image']
        extra_kwargs = {
            'id': {'read_only': True},
            'user': {'read_only': True}
        }

    def validate(self, attrs):
        image = attrs.get('image')
        if not image:
            raise serializers.ValidationError('No profile picture provided.')

        try:
            with Image.open(image) as im:
                if not any(im.format == file_type.upper() for  file_type in ['jpeg', 'jpg', 'png']):
                    raise serializers.ValidationError('Invalid image format. Please upload a valid JPEG image.')
        except Exception as error:
            raise serializers.ValidationError('Failed to process image.')

        return attrs


class FriendRequestSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = FriendRequest
        fields = ['from_user', 'to_user']

    def validate(self, attrs):
        if attrs.get('from_user') == attrs.get('to_user'):
            raise serializers.ValidationError({'error':['Users cannot friend themselves.']})
        
        return super().validate(attrs)


class FriendSerializer(serializers.ModelSerializer):

    class Meta:
        model = Friend
        fields = ['first_user', 'second_user']
