from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.core.mail import EmailMessage

import string, secrets


def send_email(request, token):
    absolute_url = (
        'http://' + get_current_site(request).domain
        + reverse('verify_email') 
        + '?token=' 
        + token
    )
    email_subject = 'Email Verification'
    email_body = ('Hi, ' + request.data['username'] 
        + '\nPlease click on the link below to verify your email:\n'
        + absolute_url
    )
    email = EmailMessage(subject=email_subject, body=email_body, to=['Galahadsp@gmail.com'])
    email.send()


def generate_verification_token(length):
    allowed_chars = string.ascii_letters + string.digits

    token = ''.join((secrets.choice(allowed_chars) for _ in range(length))) 

    return token
