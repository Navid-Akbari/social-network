from django.urls import path

from . import views

app_name = 'post'

urlpatterns = [
    path('post/', views.PostManager.as_view(), name='posts'),
    path('post/<int:pk>/', views.PostManager.as_view(), name='posts_detail'),
]