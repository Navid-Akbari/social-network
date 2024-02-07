from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.core.mail import EmailMessage
from django.utils import timezone

import string, secrets
from datetime import  timedelta


def send_email(request, user, token):
    absolute_url = (
        'http://' + get_current_site(request).domain
        + reverse('verify_email')
        + '?uidb64='
        + urlsafe_base64_encode(force_bytes(user.pk))
        + '&token='
        + token
    )
    email_subject = 'Email Verification'
    email_body = (
        f'Hi, {user.username}'
        '\nPlease click on the link below to verify your email:\n'
        f'{absolute_url}'
    )
    email = EmailMessage(subject=email_subject, body=email_body, to=['Galahadsp@gmail.com', user.email])
    email.send()


def generate_verification_token(length):
    allowed_chars = string.ascii_letters + string.digits

    token = ''.join((secrets.choice(allowed_chars) for _ in range(length))) 

    return token


def token_expiration_time(minutes):
    current_time = timezone.now()
    expiration_time = current_time + timedelta(minutes=minutes)
    return expiration_time


def token_has_expired(expiration_time):
    return timezone.now() > expiration_time