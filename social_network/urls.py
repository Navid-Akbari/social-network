from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/account/', include('account.urls')),
    path('api/post/', include('post.urls')),
    path("chat/", include("chat.urls")),
]
