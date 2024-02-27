from django.urls import path

from . import views

app_name = 'post'

urlpatterns = [
    path('', views.PostListCreate.as_view(), name='posts'),
    path('<int:pk>/', views.PostRetrieveUpdateDestroy.as_view(), name='posts_detail'),
    path('likes/', views.LikeCreate.as_view(), name='likes')
]
