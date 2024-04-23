from django.contrib.auth import get_user_model
from django.core.validators import MaxLengthValidator
from django.db import models

User = get_user_model()


class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, )
    body = models.CharField(max_length=250, blank=False)
    created_at = models.DateTimeField(auto_now_add=True, blank=False)
    last_edited = models.DateTimeField(auto_now=True, blank=False)
    likes_count = models.PositiveIntegerField(default=0)
    dislikes_count = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = [['user', 'created_at', 'body']]


class Like(models.Model):
    is_like = models.BooleanField(blank=False, null=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)

    class Meta:
        unique_together = [['post', 'user']]


class Comment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    body = models.TextField(blank=False, validators=[MaxLengthValidator(250)])
    created_at = models.DateTimeField(auto_now_add=True, blank=False)
