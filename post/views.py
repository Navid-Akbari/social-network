from rest_framework import status
from rest_framework.filters import SearchFilter
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import (
    CreateModelMixin,
    ListModelMixin,
    RetrieveModelMixin
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from django_filters.rest_framework import DjangoFilterBackend

from account.permissions import IsOwnerOrAdmin
from .serializers import PostSerializer
from .models import Post


class PostManager(
    CreateModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
    GenericAPIView
):
    authentication_classes = [JWTAuthentication]
    serializer_class = PostSerializer
    queryset = Post.objects.all().order_by('created_at')
    filter_backends = [SearchFilter]
    search_fields = ['user__username']
    pagination_class = PageNumberPagination

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        pk = kwargs.get('pk')
        if pk is not None:
            return self.retrieve(request, *args, **kwargs)

        return self.list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data={
                'body': request.data['body'],
                'user': request.user.pk
            }
        )
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def get_permissions(self):
        if self.request.method == 'POST' or self.request.method == 'GET':
            return [IsAuthenticated()]
        elif self.request.method == 'PATCH' or self.request.method == 'DELETE':
            return [IsOwnerOrAdmin()]
