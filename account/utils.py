from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils import timezone

import string, secrets
from datetime import  timedelta


def send_email_verification_email(request, user):
    absolute_url = (
        'http://' + get_current_site(request).domain
        + '/?uidb64='
        + urlsafe_base64_encode(force_bytes(user.pk))
        + '&token='
        + user.verification_token
    )
    email_subject = 'Email Verification'
    email_body = (
        f'Hi, {user.username}'
        '\nPlease click on the link below to verify your email:\n'
        f'{absolute_url}'
    )
    email = EmailMessage(subject=email_subject, body=email_body, to=[user.email])
    email.send()


def send_change_password_email(request, user):
    absolute_url = (
        'http://' + get_current_site(request).domain
        + '/?uidb64='
        + urlsafe_base64_encode(force_bytes(user.pk))
        + '&token='
        + user.verification_token
    )
    email_subject = 'Request to Change Password'
    email_body = (
        f'Hi, {user.username}'
        '\nPlease click on the link below to change your password:\n'
        'Ignore this email if you did not initiate this request\n'
        f'{absolute_url}'
    )
    email = EmailMessage(subject=email_subject, body=email_body, to=[user.email])
    email.send()


def generate_verification_token(length=32):
    allowed_chars = string.ascii_letters + string.digits

    token = ''.join((secrets.choice(allowed_chars) for _ in range(length))) 

    return token


def token_expiration_time(minutes=5):
    return timezone.now() + timedelta(minutes=minutes)


def token_has_expired(expiration_time):
    return timezone.now() > expiration_time
