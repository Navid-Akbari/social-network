from django.contrib.auth import get_user_model
from django.test import TestCase

from post.serializers import PostSerializer
from post.utils import format_serializer_errors

User = get_user_model()


class TestPostSerializer(TestCase):

    def setUp(self):
        self.user = User.objects.create(
            username='test',
            email='test@example.com',
            password='testing321'
        )

    def test_post_serializer_valid(self):
        serializer = PostSerializer(
            data={
                'body': 'Test post body.',
                'user': 1
            }
        )

        serializer.is_valid()
        post = serializer.save()
        self.assertIsNotNone(post)
        self.assertEqual(post.user.username, self.user.username)
        self.assertEqual(post.body, 'Test post body.')

    def test_post_serializer_missing_body(self):
        serializer = PostSerializer(data={'user': 1})

        self.assertFalse(serializer.is_valid())

        errors = format_serializer_errors(serializer.errors)

        self.assertEqual(errors, {'body': 'This field is required.'})

    def test_post_serializer_exceed_body_length(self):
        serializer = PostSerializer(
            data={
                'body': 'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij',
                'user': 1
            }
        )

        self.assertFalse(serializer.is_valid())
        errors = format_serializer_errors(serializer.errors)
        self.assertEqual(errors, {'body': 'Ensure this field has no more than 250 characters.'})

    def test_post_serializer_missing_user(self):
        serializer = PostSerializer(data={'body': 'Test post body.'})

        self.assertFalse(serializer.is_valid())
        errors = format_serializer_errors(serializer.errors)
        self.assertEqual(errors, {'user': 'This field is required.'})

    def test_post_serializer_invalid_user(self):
        serializer = PostSerializer(
            data={
                'body': 'Test post body.',
                'user': User.objects.create(
                    username='test1',
                    email='test1@example.com',
                    password='testing321'
                )
            }
        )

        self.assertFalse(serializer.is_valid())
        errors = format_serializer_errors(serializer.errors)
        self.assertEqual(
            errors,
            {'user': 'Incorrect type. Expected pk value, received CustomUser.'}
        )