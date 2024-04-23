from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.test import TestCase

from post.models import Post, Like, Comment

User = get_user_model()


class TestPostModel(TestCase):

    def setUp(self):
        self.user = User.objects.create(
            username='test',
            email='test@example.com',
            password='testing321'
        )

    def test_valid(self):
        post = Post.objects.create(
            user=self.user,
            body='test post body.',
        )

        saved_post = Post.objects.get(pk=post.pk)
        self.assertEqual(saved_post.body, 'test post body.')
        self.assertEqual(saved_post.likes_count, 0)
        self.assertEqual(saved_post.dislikes_count, 0)


class TestLikeModel(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.post = Post.objects.create(user=self.user, body='Test post body')
        Like.objects.create(user=self.user, post=self.post, is_like=True)

    def test_like_exists(self):
        like = Like.objects.get(id=1)

        self.assertTrue(isinstance(like, Like))
        self.assertTrue(like.is_like)


class TestCommentModel(TestCase):

    def setUp(self):
        self.user = User.objects.create(
            username='test',
            email='test@gmail.com',
            password='testing321'
        )
        self.post = Post.objects.create(
            user=self.user,
            body='Test post body.'
        )

    def test_valid(self):
        comment = Comment.objects.create(
            user=self.user,
            post=self.post,
            body='Test comment.'
        )

        saved_comment = Comment.objects.get(pk=comment.pk)
        self.assertEqual(saved_comment.user, self.user)
        self.assertEqual(saved_comment.post, self.post)
        self.assertEqual(saved_comment.body, 'Test comment.')

