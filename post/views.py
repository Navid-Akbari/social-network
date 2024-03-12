from django.contrib.auth import get_user_model

from rest_framework import status
from rest_framework.exceptions import NotFound
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
from .serializers import PostSerializer, LikeSerializer, CommentSerializer
from .models import Post, Like, Comment

User = get_user_model()


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
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'

    def patch(self, request, *args, **kwargs):
        if 'body' in request.data:
            return super().patch(request, *args, **kwargs)

        return Response({'detail': 'Invalid request data.'}, status=status.HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        return Post.objects.filter(pk=self.kwargs['pk']).order_by('created_at')


class LikeCreate(CreateAPIView, GenericAPIView):
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


class CommentListCreate(ListCreateAPIView):
    serializer_class = CommentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination

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

    def get_queryset(self):
        post_id = self.request.query_params.get('post_id')
        user_id = self.request.query_params.get('user_id')

        if post_id:
            try:
                Post.objects.get(pk=post_id)
            except Post.DoesNotExist:
                raise NotFound('Post not found.')

            return Comment.objects.filter(post=post_id).order_by('created_at')
        

        elif user_id:
            try:
                User.objects.get(pk=user_id)
            except User.DoesNotExist:
                raise NotFound('User not found.')

            return Comment.objects.filter(user=user_id).order_by('created_at')

        else:
            raise NotFound('Invalid request parameters.')


class CommentRetrieveUpdateDestroy(RetrieveUpdateDestroyAPIView):
    serializer_class = CommentSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'
    
    def patch(self, request, *args, **kwargs):
        if 'body' in request.data:
            return super().patch(request, *args, **kwargs)

        return Response({'detail': 'Invalid request data.'}, status=status.HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        return Comment.objects.filter(pk=self.kwargs['pk']).order_by('created_at')
