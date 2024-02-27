from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

from .models import Like


@receiver([post_delete, post_save], sender=Like)
def update_post_likes_and_dislikes_count(sender, instance, **kwargs):
    post = instance.post
    if 'created' in kwargs:
        if kwargs['created']:
            if instance.is_like:
                post.likes_count += 1
            else:
                post.dislikes_count += 1
        else:
            if instance.is_like:
                post.likes_count += 1
                post.dislikes_count -= 1
            else:
                post.likes_count -= 1
                post.dislikes_count += 1
    else:
        if instance.is_like:
            post.likes_count -= 1
        else:
            post.dislikes_count -= 1
    post.save()
