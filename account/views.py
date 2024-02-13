from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

import jwt
from rest_framework import status, generics, mixins
from rest_framework.decorators import APIView
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import CustomUser
from .permissions import IsOwnerOrAdmin
from .serializers import UserSerializer
from .utils import (
    generate_verification_token,
    send_email_verification_email,
    send_change_password_email,
    token_expiration_time,
    token_has_expired
)


class UserAccountManager(
        mixins.CreateModelMixin,
        mixins.ListModelMixin,
        mixins.RetrieveModelMixin,
        mixins.UpdateModelMixin,
        mixins.DestroyModelMixin,
        generics.GenericAPIView
    ):

    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)


    def get(self, request, *args, **kwargs):
        pk = kwargs.get('pk')
        if pk is not None:
            return self.retrieve(request, *args, **kwargs)
        
        return self.list(request, *args, **kwargs)


    def patch(self, request, *args, **kwargs):
        # this method shouldn't change passwords
        if 'password' in request.data:
            request.data['password'].pop()

        return self.partial_update(request, *args, **kwargs)


    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


    def get_queryset(self):
        queryset = super().get_queryset()
        filters = self.request.query_params

        try:
            for key, value in filters.items():
                queryset = queryset.filter(**{key: value})
        except Exception:
            return Response({'message': 'Invalid query parameters.'})

        return queryset


    def get_permissions(self):
        if self.request.method == 'POST':
            return [AllowAny()]
        elif self.request.method == 'GET':
            return [IsAdminUser()]
        elif self.request.method == 'PATCH' or self.request.method == 'DELETE':
            return [IsOwnerOrAdmin()]


    def get_authenticators(self):
        if self.request.method == 'POST':
            return []
        if any(method in self.request.method for method in ['GET', 'PATCH', 'DELETE']):
            return [JWTAuthentication()]



    def handle_exception(self, exception):

        if isinstance(exception, AssertionError):
            return Response(
                {'message': 'Invalid url parameter.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().handle_exception(exception)


class RequestEmailVerification(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):

        user = get_object_or_404(CustomUser, pk=request.user.id)

        if user.email_verified:
            return Response(
                {'error': 'This email has already been verified.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        if user.verification_token_expiration is not None:
            if not token_has_expired(user.verification_token_expiration):
                return Response(
                    {'error': 'An email has been sent recently.'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

        user.verification_token = generate_verification_token()
        user.verification_token_expiration = token_expiration_time(minutes=10)
        try:    
            user.save()
        except Exception:
            return Response(
                {'error:': 'There was an error while updating the user in the database.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        send_email_verification_email(request=request, user=user)
        return Response({'message': 'An email has been sent.'}, status=status.HTTP_200_OK)


class VerifyEmail(APIView):
    authentication_classes = []
    class_permissions = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'token' not in request.data or 'uidb64' not in request.data:
            return Response(
                {'error': 'Parameters are missing.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        token = request.data['token']
        uidb64 = request.data['uidb64']
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
        except Exception:
            return Response({'error': 'Bad uidb64.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = get_object_or_404(CustomUser, pk=user_id)
        except Exception:
            return Response(
                {'error': 'Bad input for user lookup.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if user.email_verified:
            return Response(
                {'error': 'This email has already been verified.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if user.verification_token_expiration is not None:
            if token_has_expired(user.verification_token_expiration):
                return Response(
                    {'error': 'The verification token has expired.'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

        if token != user.verification_token:
            return Response({'error': 'Invalid Token.'}, status=status.HTTP_400_BAD_REQUEST)

        user.email_verified = True
        user.verification_token = None
        user.verification_token_expiration = None

        try:    
            user.save()
        except Exception:
            return Response(
                {'error:': 'There was an error while updating the user in the database.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({'message': 'Email verified.'}, status=status.HTTP_200_OK)


class RequestPasswordReset(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'email' not in request.data:
            return Response({'error': 'Email missing.'}, status=status.HTTP_400_BAD_REQUEST)

        email = request.data['email']

        user = get_object_or_404(CustomUser, email=email)

        if user.verification_token_expiration is not None:
            if not token_has_expired(user.verification_token_expiration):
                return Response(
                    {'error': 'An Email has been sent recently.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        user.verification_token = generate_verification_token(length=32)
        user.verification_token_expiration = token_expiration_time(minutes=5)

        try:
            user.save()
        except Exception:
            return Response({'error': 'There was a problem updating the user.'})
        
        send_change_password_email(request, user)

        return Response(
            {'message': 'A password reset email has been sent.'},
            status=status.HTTP_200_OK
        )


class ResetPassword(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        authorization_header = request.headers.get('Authorization')

        if authorization_header:
            try:
                jwt_token = authorization_header.split()[1]
                decoded_data = jwt.decode(jwt=jwt_token, key=settings.SECRET_KEY, algorithms=["HS256"])

                try:
                    user = get_object_or_404(CustomUser, pk=decoded_data['user_id'])
                except Exception:
                    return Response({'error': 'Bad input for user lookup.'})

                if not all(key in request.data
                    for key in ['old_password', 'password1', 'password2']
                ):
                    return Response(
                        {'error': 'Missing parameters. (old_password, password1, password2)'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                if not check_password(request.data['old_password'], user.password):
                    return Response(
                        {'error': 'Old password is not correct.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                if request.data['password1'] != request.data['password2']:
                    return Response(
                        {'error': 'Passwords do not match.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                user.set_password(request.data['password1'])
                try:
                    user.save()
                except Exception:
                    return Response(
                        {'error': 'There was a problem updating the user.'},
                        status=status.HTTP_503_SERVICE_UNAVAILABLE
                    )
                
                return Response(
                    {'message': 'Password changed successfully.'},
                    status=status.HTTP_200_OK
                )

            except jwt.DecodeError as error:
                return Response(
                    {'error': f'Problem with token: {error}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        if not all(key in request.data
            for key in ['token', 'uidb64', 'password1', 'password2']
        ):
            return Response(
                {'error': 'Missing Parameters. (token, uidb64, password1, password2)'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if request.data['password1'] != request.data['password2']:
            return Response(
                {'error': 'Passwords do not match.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        token = request.data['token']
        try:
            user_id = force_str(urlsafe_base64_decode(request.data['uidb64']))
        except Exception:
            return Response({'error': 'Bad uidb64.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = get_object_or_404(CustomUser, pk=user_id)
        except Exception:
            return Response(
                {'error': 'Bad input for user lookup.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if user.verification_token_expiration is not None:
            if token_has_expired(user.verification_token_expiration):
                return Response(
                    {'error': 'Token has expired.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        if user.verification_token != token:
            return Response({'error': 'Invalid Token.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(request.data['password1'])

        try:
            user.save()
        except Exception:
            return Response(
                {'error': 'There was a problem updating the user.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)