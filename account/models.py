import os
from PIL import Image

from django.core.exceptions import ValidationError
from django.contrib.auth import password_validation
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

from .validators import (
    USERNAME_VALIDATOR, 
    PHONE_NUMBER_VALIDATOR, 
    NAME_VALIDATOR, 
    name_length_validation
)
from social_network.settings import BASE_DIR, MEDIA_ROOT


class CustomUserManager(BaseUserManager):

    def create_user(self, username, email, password, **extra_fields):
        user = self.model(
            email=self.normalize_email(email),
            username=username,
            password=password,
        )

        for field in ['first_name', 'last_name', 'phone_number', 'is_staff', 'is_active', 'is_superuser']:
            if field in extra_fields:
                setattr(user, field, extra_fields[field])

        if user.first_name:
            if not user.last_name:
                raise ValidationError({'first_name': 'last_name is missing.'})
            user.first_name = user.first_name.capitalize()

        if user.last_name:
            if not user.first_name:
                raise ValidationError({'last_name': 'first_name is missing.'})
            user.last_name = user.last_name.capitalize()

        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password, **extra_fields):

        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff set to True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser set to True.')

        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):

    first_name = models.CharField(
        max_length=50, 
        validators=[NAME_VALIDATOR, name_length_validation], 
        blank=True, null=True
    )
    last_name = models.CharField(
        max_length=50, 
        validators=[NAME_VALIDATOR, name_length_validation], 
        blank=True, 
        null=True
    )
    username = models.CharField(
        max_length=50, 
        validators=[USERNAME_VALIDATOR, name_length_validation], 
        unique=True, 
        blank=False
    )
    email = models.EmailField(max_length=50, unique=True, blank=False)
    password = models.CharField(max_length=128, validators=[password_validation.validate_password], blank=False)
    phone_number = models.CharField(
        max_length=15, 
        validators=[PHONE_NUMBER_VALIDATOR], 
        blank=True, 
        null=True, 
        unique=True
    )
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=64, default=None, null=True, blank=True)
    verification_token_expiration = models.DateTimeField(default=None, null=True, blank=True)

    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(default=timezone.now)

    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']


class Profile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='', default='default.jpg')
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} Profile"

    def save(self, *args, **kwargs):
        instance = Profile.objects.filter(user=self.user).first()
        if instance and instance.image.name != 'default.jpg':
            os.remove(BASE_DIR / MEDIA_ROOT / instance.image.path)

        super().save(*args, **kwargs)

        with Image.open(self.image.path) as im:
            if im.height > 300 or im.width > 300:
                output_size = (300, 300)
                im.thumbnail(output_size)
                im.save(self.image.path)


class FriendRequest(models.Model):
    from_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sent_friend_request')
    to_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='recieved_friend_request')

    class Meta:
        unique_together = [['from_user', 'to_user']]


class Friend(models.Model):
    first_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='first_friend')
    second_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='second_friend')

    class Meta:
        unique_together = [['first_user', 'second_user']]
