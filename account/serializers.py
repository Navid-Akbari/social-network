from django.contrib.auth.hashers import make_password

from rest_framework import serializers, status

from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
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

    def create(self, validated_data):
        password = validated_data.pop('password')
        validated_data['password'] = make_password(password)
        user = super().create(validated_data)
        return user