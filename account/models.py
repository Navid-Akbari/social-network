from django.db import models
from django.contrib.auth import password_validation
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

from .validators import USERNAME_VALIDATOR, PHONE_NUMBER_VALIDATOR, username_length_validation

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password, **extra_fields):
        if not email:
            raise ValueError('User must have an email')
        
        if not username:
            raise ValueError('User must have a username')
        
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
    
    
    def create_superuser(self, username, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must be assigned to is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must be assigned to is_superuser=True')

        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    username = models.CharField(max_length=50, validators=[USERNAME_VALIDATOR, username_length_validation], unique=True)
    email = models.EmailField(max_length=50, unique=True)
    password = models.CharField(max_length=128, validators=[password_validation.validate_password])
    phone_number = models.CharField(max_length=15, validators=[PHONE_NUMBER_VALIDATOR], blank=True, null=True, unique=True)
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=21)

    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(default=timezone.now)

    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
