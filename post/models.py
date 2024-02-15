from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import models, utils

User = get_user_model()


class Post(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    body = models.CharField(max_length=250)
    created_at = models.DateTimeField(auto_now_add=True)
    last_edited = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [['user', 'created_at']]

    def save(self, *args, **kwargs):
        try:
            self.full_clean()
            super(Post, self).save(*args, **kwargs)
        except utils.IntegrityError as error:
            raise ValidationError(f'error: {error}')