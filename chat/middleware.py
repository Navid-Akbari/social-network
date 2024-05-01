from urllib.parse import parse_qs

import jwt
from channels.db import database_sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed

User = get_user_model()


class JWTAuthMiddleware:
    
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        token = parse_qs(scope['query_string']).get(b'token', '')
        token = token[0].decode()

        if not token:
            return Response({'error': ['Missing Token.']}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            decoded = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded['user_id']
            scope['user'] = await self.get_user(user_id)
            return await self.app(scope, receive, send)
        except (InvalidToken, AuthenticationFailed):
            return Response({'error': ['Invalid Token.']}, status=status.HTTP_401_UNAUTHORIZED)

    @database_sync_to_async
    def get_user(self, user_id):
        try:
            user = User.objects.get(id=user_id)
            return user
        except ObjectDoesNotExist:
            return AnonymousUser()
