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

    def test_create_post_valid(self):
        post = Post.objects.create(
            user=self.user,
            body='test post body.',
        )

        saved_post = Post.objects.get(pk=post.pk)
        self.assertEqual(saved_post.body, 'test post body.')
        self.assertEqual(saved_post.likes_count, 0)
        self.assertEqual(saved_post.dislikes_count, 0)


    def test_create_post_duplicate(self):
        post = Post.objects.create(
            user=self.user,
            body='test post body.',
        )

        with self.assertRaises(ValidationError) as context:
            Post.objects.create(
                user=self.user,
                body='test post body.',
                created_at=post.created_at
            )

        self.assertIn(
            'Post with this User, Created at and Body already exists.',
            str(context.exception)
        )

    def test_create_post_body_length_constraint(self):
        with self.assertRaises(ValidationError) as context:
            Post.objects.create(
                user=self.user,
                body='abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'
                'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij'
                'klmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'
                'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz',
            )

        self.assertIn(
            'Ensure this value has at most 250 characters (it has 260).',
            str(context.exception)
        )


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

    def test_like_unique_constraint(self):
        with self.assertRaises(ValidationError) as context:
            Like.objects.create(user=self.user, post=self.post, is_like=True)

        self.assertIn(
            'Like with this Post and User already exists.',
            str(context.exception)
        )


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

    def test_create_comment_valid(self):
        comment = Comment.objects.create(
            user=self.user,
            post=self.post,
            body='Test comment.'
        )

        saved_comment = Comment.objects.get(pk=comment.pk)
        self.assertEqual(saved_comment.user, self.user)
        self.assertEqual(saved_comment.post, self.post)
        self.assertEqual(saved_comment.body, 'Test comment.')

    def test_create_comment_invalid_body(self):
        with self.assertRaises(ValidationError):
            Comment.objects.create(
                user=self.user,
                post=self.post,
                body=''
            )
    
    def test_create_comment_empty_body(self):
        with self.assertRaises(ValidationError):
            Comment.objects.create(
                user=self.user,
                post=self.post,
                body=''
            )
    
    def test_create_comment_invalid_body_length(self):
        with self.assertRaises(ValidationError):
            Comment.objects.create(
                user=self.user,
                post=self.post,
                body='abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
            )
