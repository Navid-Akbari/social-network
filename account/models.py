from django.core.exceptions import ValidationError
from django.contrib.auth import password_validation
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models, utils
from django.utils import timezone

from .validators import USERNAME_VALIDATOR, PHONE_NUMBER_VALIDATOR, NAME_VALIDATOR, name_length_validation


class CustomUserManager(BaseUserManager):

    def create_user(self, username, email, password=None, **extra_fields):

        user = self.model(
            email = self.normalize_email(email),
            username = username,
        )

        for field in ['first_name', 'last_name', 'phone_number', 'is_staff', 'is_active', 'is_superuser']:
            if field in extra_fields:
                setattr(user, field, extra_fields[field])

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):

        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must be assigned to is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must be assigned to is_superuser=True')

        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):

    first_name = models.CharField(max_length=50, validators=[NAME_VALIDATOR, name_length_validation], blank=True, null=True)
    last_name = models.CharField(max_length=50, validators=[NAME_VALIDATOR, name_length_validation], blank=True, null=True)
    username = models.CharField(max_length=50, validators=[USERNAME_VALIDATOR, name_length_validation], unique=True, blank=False)
    email = models.EmailField(max_length=50, unique=True, blank=False)
    password = models.CharField(max_length=128, validators=[password_validation.validate_password], blank=False)
    phone_number = models.CharField(max_length=15, validators=[PHONE_NUMBER_VALIDATOR], blank=True, null=True, unique=True)
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

    def save(self, *args, **kwargs):
        try:
            self.full_clean()

            if self.first_name:
                self.first_name = self.first_name.capitalize()

            if self.last_name:
                self.last_name = self.last_name.capitalize()

            super(CustomUser, self).save(*args, **kwargs)
        except utils.IntegrityError as error:
            raise ValidationError(f'error: {error}')
