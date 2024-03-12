from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

import jwt
from rest_framework import status
from rest_framework.decorators import APIView
from rest_framework.generics import (
    ListCreateAPIView,
    RetrieveUpdateDestroyAPIView,
    RetrieveUpdateAPIView,
    GenericAPIView
)
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from django_filters.rest_framework import DjangoFilterBackend

from .permissions import IsTheSameUserOrAdmin
from .serializers import UserSerializer, ProfileSerializer
from .models import Profile
from .utils import (
    generate_verification_token,
    send_email_verification_email,
    send_reset_password_email,
    generate_token_expiration_time,
    token_has_expired
)
from post.permissions import IsOwnerOrAdmin

User = get_user_model()


class UserListCreate(ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['username', 'first_name', 'last_name']

    def get_permissions(self):
        if self.request.method == 'POST':
            return [AllowAny()]
        elif self.request.method == 'GET':
            return [IsAdminUser()]
    
    def get_authenticators(self):
        if self.request.method == 'POST':
            return []
        if self.request.method == 'GET':
            return [JWTAuthentication()]


class UserRetrieveUpdateDestroy(RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    http_method_names = ['get', 'patch', 'delete', 'put']
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'

    def patch(self, request, *args, **kwargs):
        # this method shouldn't change passwords
        if 'password' in request.data:
            request.data.pop('password')

        return self.partial_update(request, *args, **kwargs)

    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsAdminUser()]
        if any(method in self.request.method for method in ['PATCH', 'DELETE']):
            return [IsTheSameUserOrAdmin()]

    def get_queryset(self):
        return User.objects.filter(pk=self.kwargs['pk'])


class UserRetrieveWithToken(GenericAPIView):
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ProfileRetrieveUpdate(RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    parser_classes = [MultiPartParser, FormParser]
    http_method_names = ['put', 'get']
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'

    def get_queryset(self):
        return Profile.objects.filter(user_id=self.kwargs['pk'])

class RequestEmailVerification(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):

        user = get_object_or_404(User, pk=request.user.id)

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
        user.verification_token_expiration = generate_token_expiration_time(minutes=10)
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
            user = get_object_or_404(User, pk=user_id)
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

        user = get_object_or_404(User, email=email)

        if user.verification_token_expiration is not None:
            if not token_has_expired(user.verification_token_expiration):
                return Response(
                    {'error': 'An Email has been sent recently.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        user.verification_token = generate_verification_token(length=32)
        user.verification_token_expiration = generate_token_expiration_time(minutes=5)

        try:
            user.save()
        except Exception:
            return Response({'error': 'There was a problem updating the user.'})
        
        send_reset_password_email(request, user)

        return Response(
            {'message': 'A password reset email has been sent.'},
            status=status.HTTP_200_OK
        )

"""
password reset is done in the same view but handles data in two ways:
1. If a user has lost their account password they can request an email, within the email
    is a link that supposedly takes them to a front-end view. there the uidb64 and token
    from the link have to be extracted and sent here with the passwords.
2. If a user is already logged in and has a token, the token can be sent with the passwords
    for the change to take place.
"""
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
                    user = get_object_or_404(User, pk=decoded_data['user_id'])
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
            user = get_object_or_404(User, pk=user_id)
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
