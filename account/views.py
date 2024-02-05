from django.conf import settings
from django.shortcuts import get_object_or_404

from rest_framework.decorators import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication


from .serializers import UserSerializer
from .models import CustomUser
from .utils import  send_email


class Register(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'user': serializer.data, 
                'message': 'An activation link has been sent to your email account.',
            },
                status = status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(APIView):
    pass