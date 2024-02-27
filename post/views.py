from rest_framework import status
from rest_framework.filters import SearchFilter
from rest_framework.generics import (
    RetrieveUpdateDestroyAPIView,
    ListCreateAPIView,
    CreateAPIView,
    GenericAPIView
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from .permissions import IsOwnerOrAdmin
from .serializers import PostSerializer, LikeSerializer
from .models import Post, Like


class PostListCreate(ListCreateAPIView):
    queryset = Post.objects.all().order_by('created_at')
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination
    filter_backends = [SearchFilter]
    search_fields = ['user__username', 'user__id']

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data={
                **{'user': request.user.pk},
                **request.data
            }
        )
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class PostRetrieveUpdateDestroy(RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'


class LikeCreate(CreateAPIView, GenericAPIView):
    queryset = Like.objects.all()
    serializer_class = LikeSerializer
    http_method_names = ['post']
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data={
                **{'user': request.user.pk},
                **request.data
            }  
        )
        serializer.is_valid(raise_exception=True)

        existing_like = Like.objects.filter(
            user=request.user,
            post=serializer.validated_data['post']
        ).first()

        if existing_like:
            if existing_like.is_like == serializer.validated_data['is_like']:
                existing_like.delete()
                return Response(
                    {'message': 'Like removed successfully.'},
                    status=status.HTTP_204_NO_CONTENT
                )
            else:
                existing_like.is_like = serializer.validated_data['is_like']
                existing_like.save()
                return Response(
                    self.get_serializer(existing_like).data,
                    status=status.HTTP_201_CREATED
                )

        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class CommentCreate(CreateAPIView, GenericAPIView):