from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

from rest_framework import status, generics, mixins
from rest_framework.decorators import APIView
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import CustomUser
from .permissions import IsOwnerOrAdmin
from .serializers import UserSerializer
from .utils import (
    send_email_verification_email, 
    generate_verification_token, 
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


    def handle_exception(self, exception):

        if isinstance(exception, AssertionError):
            return Response({'message': 'Invalid url parameter.'}, status=status.HTTP_400_BAD_REQUEST)
        return super().handle_exception(exception)


class RequestEmailVerification(APIView):
    authentication_classes = [JWTAuthentication]

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

        send_email_verification_email(request=request, user=user, token=user.verification_token)
        return Response({'message': 'An email has been sent.'}, status=status.HTTP_200_OK)


class VerifyEmail(APIView):
    class_permissions = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'token' not in request.data or 'uidb64' not in request.data:
            return Response({'error': 'Parameters are missing.'}, status=status.HTTP_400_BAD_REQUEST)

        token = request.data['token']
        uidb64 = request.data['uidb64']
        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(CustomUser, id=user_id)

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
