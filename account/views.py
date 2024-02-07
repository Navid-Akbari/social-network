from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

from rest_framework.decorators import APIView
from rest_framework.response import Response
from rest_framework import status, generics, mixins
import jwt

from .serializers import UserSerializer
from .models import CustomUser
from .utils import send_email, generate_verification_token, token_expiration_time, token_has_expired


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
        pk = kwargs.get('pk')
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

class VerifyEmail(APIView):
    def post(self, request, *args, **kwargs):
        header = request.headers.get('Authorization')

        if not header:
            return Response({'error': 'Authorization header missing.'}, status=status.HTTP_400_BAD_REQUEST)

        token = header.split()[1]

        if not token:
            return Response({'error': 'Token required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
            user = get_object_or_404(CustomUser, pk=user_id)

            if user.email_verified:
                return Response({'error': 'This email has already been verified.'}, status=status.HTTP_400_BAD_REQUEST)
    
            if user.verification_code_expiration:
                if not token_has_expired(user.verification_code_expiration):
                    return Response({'error': 'An email has been sent recently.'}, status=status.HTTP_400_BAD_REQUEST)

            token = generate_verification_token(32)
            expiration_time = token_expiration_time(minutes=10)
            user.verification_code = token
            user.verification_code_expiration = expiration_time
            user.save()
            send_email(request=request, user=user, token=token)
            return Response({'message': 'An email has been sent.'}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as e:
            return Response({'error': 'Token has expired.'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as e:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        token = request.query_params.get('token')
        uidb64 = request.query_params.get('uidb64')

        if not token or not uidb64:
            return Response({'error': 'parameters are missing.'}, status=status.HTTP_400_BAD_REQUEST)

        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(CustomUser, id=user_id)

        if user.email_verified:
            return Response({'error': 'This email has already been verified.'}, status=status.HTTP_400_BAD_REQUEST)

        if token_has_expired(user.verification_code_expiration):
            user
            return Response({'error': 'The verification token has expired.'}, status=status.HTTP_400_BAD_REQUEST)

        if token != user.verification_code:
            return Response({'error': 'Invalid Token.'}, status=status.HTTP_400_BAD_REQUEST)

        user.email_verified = True
        user.verification_code = None
        user.verification_code_expiration = None
        user.save()
        return Response({'message': 'Email verified.'}, status=status.HTTP_200_OK)
