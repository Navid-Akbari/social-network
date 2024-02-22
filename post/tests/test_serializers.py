from django.contrib.auth import get_user_model
from django.test import TestCase

from post.models import Post, Like
from post.serializers import PostSerializer, LikeSerializer

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

        self.assertTrue(serializer.is_valid())
        post = serializer.save()
        self.assertIsNotNone(post)
        self.assertEqual(post.user.username, self.user.username)
        self.assertEqual(post.body, 'Test post body.')

    def test_post_serializer_missing_body(self):
        serializer = PostSerializer(data={'user': 1})

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['body'][0],
            'This field is required.'
        )

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
        self.assertEqual(
            serializer.errors['body'][0],
            'Ensure this field has no more than 250 characters.'
        )

    def test_post_serializer_missing_user(self):
        serializer = PostSerializer(data={'body': 'Test post body.'})

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['user'][0],  'This field is required.')

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
        self.assertEqual(
            serializer.errors['user'][0],
            'Incorrect type. Expected pk value, received CustomUser.'
        )


class TestLikeSerializer(TestCase):

    def setUp(self):
        self.user = User.objects.create(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.post = Post.objects.create(
            user=self.user,
            body='Test post body.'
        )
        self.like_instance = Like.objects.create(
            user=self.user,
            post=self.post,
            is_like=True
        )
        self.user1 = User.objects.create(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.post1 = Post.objects.create(
            user=self.user1,
            body='Test1 post body'
        )

    def test_like_serializer_valid(self):
        serializer = LikeSerializer(
            data={
                'user': self.user1.pk,
                'post': self.post1.pk,
                'is_like': True
            }
        )

        self.assertTrue(serializer.is_valid())
        Like = serializer.save()
        self.assertIsNotNone(Like)
        self.assertEqual(Like.user.pk, 2)
        self.assertEqual(Like.user.username, 'test1')

    def test_like_serializer_deleting_existing_instance_upon_duplicated_request(self):
        serializer = LikeSerializer(
            data={
                'user': self.user.pk,
                'post': self.post.pk,
                'is_like': True
            }
        )

        self.assertTrue(serializer.is_valid())
        like = serializer.save()
        self.assertEqual(like['message'], 'Like removed successfully.')

    def test_like_serializer_updating_existing_instance_upon_duplicated_request(self):
        serializer = LikeSerializer(
            data={
                'user': self.user.pk,
                'post': self.post.pk,
                'is_like': False
            }
        )

        self.assertTrue(self.like_instance.is_like)
        self.assertTrue(serializer.is_valid())
        like = serializer.save()
        self.assertFalse(like.is_like)

    def test_like_serializer_invalid(self):
        serializer = LikeSerializer(
            data={
                'user': '',
                'post': self.post.pk,
                'is_like': False
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['user'][0], 'This field may not be null.')
