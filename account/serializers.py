from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from rest_framework import serializers

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
