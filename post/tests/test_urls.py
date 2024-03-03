from django.test import SimpleTestCase
from django.urls import reverse, resolve

from post import views


class TestUrls(SimpleTestCase):

    def test_post_list_create_url_is_resolved(self):
        url = reverse('post:posts')
        self.assertEqual(resolve(url).func.view_class, views.PostListCreate)

    def test_post_retrieve_update_destroy_is_resolved(self):
        url = reverse('post:posts_detail', kwargs={'pk': 1})
        self.assertEqual(resolve(url).func.view_class, views.PostRetrieveUpdateDestroy)

    def test_like_create_url_is_resolved(self):
        url = reverse('post:likes')
        self.assertEqual(resolve(url).func.view_class, views.LikeCreate)

    def test_comment_list_create_url_is_resolved(self):
        url = reverse('post:comments')
        self.assertEqual(resolve(url).func.view_class, views.CommentListCreate)
    
    def test_comment_retrieve_update_destroy_url_is_resolved(self):
        url = reverse('post:comments_detail', kwargs={'pk': 1})
        self.assertEqual(resolve(url).func.view_class, views.CommentRetrieveUpdateDestroy)
