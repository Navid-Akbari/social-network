from rest_framework import status
from rest_framework.filters import SearchFilter
from rest_framework.generics import RetrieveUpdateDestroyAPIView, ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from .permissions import IsOwnerOrAdmin
from .serializers import PostSerializer
from .models import Post


class PostList(ListCreateAPIView):
    queryset = Post.objects.all().order_by('created_at')
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination
    filter_backends = [SearchFilter]
    search_fields = ['user__username', 'user__id']

    # Here I have overriden the create method in order to add a user the serializer
    # receives since right now the only way to authenticate a user is through
    # JWT tokens, therefore the request does not have access to user's information.
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


class PostDetail(RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]
    lookup_field = 'pk'
    lookup_url_kwarg = 'pk'
