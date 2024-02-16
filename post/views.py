from rest_framework.generics import GenericAPIView
from rest_framework.mixins import (
    CreateModelMixin
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from account.permissions import IsOwnerOrAdmin
from .serializers import PostSerializer
from .models import Post


class PostManager(CreateModelMixin, GenericAPIView):
    authentication_classes = [JWTAuthentication]
    serializer_class = PostSerializer
    queryset = Post.objects.all()

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

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
            return [AllowAny()]
        elif self.request.method == 'PATCH' or self.request.method == 'DELETE':
            return [IsOwnerOrAdmin()]
