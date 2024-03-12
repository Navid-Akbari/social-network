from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from rest_framework import serializers
from PIL import Image

from account.models import Profile

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            'id',
            'password',
            'username',
            'email',
            'first_name',
            'last_name',
            'phone_number'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True}
        }

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
