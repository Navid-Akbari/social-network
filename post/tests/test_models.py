from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from post.models import Post

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
            created_at=timezone.now()
        )

        saved_post = Post.objects.get(pk=post.pk)
        self.assertEqual(saved_post.body, 'test post body.')

    def test_create_post_duplicate(self):
        post = Post.objects.create(
            user=self.user,
            body='test post body.',
            created_at=timezone.now()
        )

        with self.assertRaises(ValidationError) as context:
            Post.objects.create(
                user=self.user,
                body='test post body.',
                created_at=post.created_at
            )

        self.assertIn('Post with this User, Created at and Body already exists.', str(context.exception))

    def test_create_post_body_length_constraint(self):
        with self.assertRaises(ValidationError) as context:
            Post.objects.create(
                user=self.user,
                body='abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'
                'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij'
                'klmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz'
                'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz',
                created_at=timezone.now()
            )

        self.assertIn('Ensure this value has at most 250 characters (it has 260).', str(context.exception))
