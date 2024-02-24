from django.urls import path

from . import views

app_name = 'post'

urlpatterns = [
    path('', views.PostList.as_view(), name='posts'),
    path('<int:pk>/', views.PostDetail.as_view(), name='posts_detail'),
    path('like/', views.LikeAPI.as_view(), name='like')
]
