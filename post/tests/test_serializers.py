from django.contrib.auth import get_user_model
from django.test import TestCase

from post.models import Post, Like
from post.serializers import PostSerializer, LikeSerializer, CommentSerializer

User = get_user_model()


class TestPostSerializer(TestCase):

    def setUp(self):
        self.user = User.objects.create(
            username='test',
            email='test@example.com',
            password='testing321'
        )

    def test_valid(self):
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

    def test_missing_body(self):
        serializer = PostSerializer(data={'user': 1})

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['body'][0],
            'This field is required.'
        )

    def test_max_body_length_constraint(self):
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

    def test_missing_user(self):
        serializer = PostSerializer(data={'body': 'Test post body.'})

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['user'][0],  'This field is required.')

    def test_invalid_user_value(self):
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

    def test_valid(self):
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

    def test_empty_user(self):
        serializer = LikeSerializer(
            data={
                'user': '',
                'post': self.post.pk,
                'is_like': False
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['user'][0], 'This field may not be null.')


class TestCommentSerializer(TestCase):
        
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
    
    def test_valid(self):
        serializer = CommentSerializer(
            data = {
                'user':self.user.pk,
                'post':self.post.pk,
                'body':'Test comment body.'
            }
        )

        self.assertTrue(serializer.is_valid())
        comment = serializer.save()
        self.assertEqual(comment.user.username, 'test')
        self.assertEqual(comment.post.body, 'Test post body.')
        self.assertEqual(comment.body, 'Test comment body.')

    def test_empty_user_post_body(self):
        serializer = CommentSerializer(
            data = {
                'user':'',
                'post':'',
                'body':''
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['user'][0], 'This field may not be null.')
        self.assertEqual(serializer.errors['post'][0], 'This field may not be null.')
        self.assertEqual(serializer.errors['body'][0], 'This field may not be blank.')

    def test_user_post_not_found_and_max_body_length_constraint(self):
        serializer = CommentSerializer(
            data = {
                'user':2,
                'post':2,
                'body':'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'   
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['user'][0],
            'Invalid pk "2" - object does not exist.'
        )
        self.assertEqual(
            serializer.errors['post'][0],
            'Invalid pk "2" - object does not exist.'
        )
        self.assertEqual(
            serializer.errors['body'][0],
            'Ensure this value has at most 250 characters (it has 290).'
        )
