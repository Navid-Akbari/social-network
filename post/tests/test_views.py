import json

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken

from post.models import Post, Like, Comment

User = get_user_model()


class TestPostListCreate(APITestCase):

    def setUp(self):
        self.url = reverse('post:posts')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.user_access_token = AccessToken.for_user(user=self.user)
        for i in range(1, 21):
            Post.objects.create(
                user=self.user,
                body=f'Test{i} post body.'
            )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.user1_access_token = AccessToken.for_user(user=self.user1)
        Post.objects.create(
            user=self.user1,
            body='User1 test post body.'
        )


    def test_valid_post_request(self):
        response = self.client.post(
            self.url,
            data = {
                'body': 'Test post body.'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['user']['id'], 1)
        self.assertEqual(response.data['body'], 'Test post body.')

    def test_unauthenticated_request(self):
        response = self.client.post(
            self.url,
            data = {
                'body': 'Test post body.'
            }
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_max_body_length_constraint(self):
        response = self.client.post(
            self.url,
            data = {
                'body': 'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['body'][0],
            'Ensure this field has no more than 250 characters.'
        )

    def test_valid_get_request(self):
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['count'])
        self.assertTrue(response.data['results'])
        self.assertTrue(response.data['next'])
        self.assertIsNone(response.data['previous'])
        self.assertEqual(len(response.data['results']), 10)

    def test_url_parameters_in_get_request(self):
        response = self.client.get(
            self.url + '?search=test1',
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data['results'][0]['user']['username'],
            'test1'
        )
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['body'], 'User1 test post body.')


class TestPostRetrieveUpdateDestroy(APITestCase):
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.user_access_token = AccessToken.for_user(user=self.user)
        self.post1 = Post.objects.create(
            user=self.user,
            body='Test post body.'
        )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.user1_access_token = AccessToken.for_user(user=self.user1)
        self.post1 = Post.objects.create(
            user=self.user1,
            body='Test1 post body.'
        )

    def test_unauthenticated_request(self):
        response = self.client.patch(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            data={'body': 'Updated test1 post body.'},
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            'User does not have permission to access this object.'
        )

    def test_unauthorized_request(self):
        response = self.client.patch(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            data={'body': 'Updated test1 post body.'}
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_valid_get_request(self):
        response = self.client.get(
            reverse('post:posts_detail', kwargs={'pk': 1}),
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['user']['username'], 'test')
        self.assertEqual(response.data['body'], 'Test post body.')

    def test_user_not_found_get_request(self):
        response = self.client.get(
            reverse('post:posts_detail', kwargs={'pk': 3}),
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data['detail'], 'Not found.')

    def test_valid_patch_request(self):
        response = self.client.patch(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            data={'body': 'Updated test1 post body.'},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        updated_post = Post.objects.get(pk=2)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(updated_post.body, 'Updated test1 post body.')

    def test_empty_body_in_patch_request(self):
        response = self.client.patch(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            data={'body': ''},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['body'][0], 'This field may not be blank.')

    def test_valid_delete_request(self):
        response = self.client.delete(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}',
        )

        self.assertEqual(response.status_code, 204)


class TestLikeCreate(APITestCase):
    
    def setUp(self):
        self.url = reverse('post:likes')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)
        self.post = Post.objects.create(
            user=self.user,
            body='Test post body.'
        )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.user1_access_token = AccessToken.for_user(user=self.user1)
        self.post1 = Post.objects.create(
            user=self.user1,
            body='Test post body.'
        )
        self.like = Like.objects.create(
            user=self.user1,
            post=self.post1,
            is_like=False
        )

    def test_valid(self):
        self.assertEqual(self.post.likes_count, 0)
        self.assertEqual(self.post.dislikes_count, 0)

        response = self.client.post(
            self.url,
            data={
                'post': 1,
                'is_like': True
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 201)
        like_Instance = Like.objects.get(user=self.user)
        self.assertEqual(like_Instance.user.pk, 1)
        self.assertEqual(like_Instance.post.pk, 1)
        self.assertTrue(like_Instance.is_like)
        post = Post.objects.get(pk=1)
        self.assertEqual(post.likes_count, 1)

    def test_invalid_islike_value(self):
        response = self.client.post(
            self.url,
            data={
                'post': 1,
                'is_like': 'badData'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['is_like'][0], 'Must be a valid boolean.')

    def test_invalid_post_value(self):
        response = self.client.post(
            self.url,
            data={
                'post': 'badData',
                'is_like': True
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['post'][0],
            'Incorrect type. Expected pk value, received str.'
        )

    def test_unauthenticated_request(self):
        response = self.client.post(
            self.url,
            data={
                'post': 1,
                'is_like': True
            }
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_delete_instance_if_duplicate(self):
        self.assertEqual(self.post1.likes_count, 0)
        self.assertEqual(self.post1.dislikes_count, 1)

        response = self.client.post(
            self.url,
            data={
                'post': 2,
                'is_like': False
            },
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.data['message'], 'Like removed successfully.')
        post = Post.objects.get(pk=2)
        self.assertEqual(post.dislikes_count, 0)

    def test_update_instance_if_duplicate(self):
        self.assertEqual(self.post1.likes_count, 0)
        self.assertEqual(self.post1.dislikes_count, 1)

        response = self.client.post(
            self.url,
            data={
                'post': 2,
                'is_like': True
            },
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}'
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['is_like'], True)
        post = Post.objects.get(pk=2)
        self.assertEqual(post.likes_count, 1)
        self.assertEqual(post.dislikes_count, 0)


class TestCommentListCreate(APITestCase):

    def setUp(self):
        self.url = reverse('post:comments')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)
        self.post = Post.objects.create(
            user=self.user,
            body='Test post body.'
        )
        for i in range(0, 20):
            Comment.objects.create(
                user=self.user,
                post=self.post,
                body=f'Test{i} comment body.'
            )
        for i in range(0, 5):
            Comment.objects.create(
                user=self.user1,
                post=self.post,
                body=f'Test{i} comment body.'
            )

    def test_valid_post_request(self):
        response = self.client.post(
            self.url,
            data={
                'post': 1,
                'body': 'Test comment body.'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['post'], 1)
        self.assertEqual(response.data['user']['id'], 1)
        self.assertEqual(response.data['body'], 'Test comment body.')

    def test_invalid_post_id_post_request(self):
        response = self.client.post(
            self.url,
            data={
                'post': 2,
                'body': 'Test comment body.'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(str(response.data['post'][0]), 'Invalid pk "2" - object does not exist.')

    def test_empty_body(self):
        response = self.client.post(
            self.url,
            data={
                'post': 1,
                'body': ''
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(str(response.data['body'][0]), 'This field may not be blank.')
    
    def test_unauthenticated_post_request(self):
        response = self.client.post(
            self.url,
            data={
                'post': 1,
                'body': 'Test comment body.'
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )


    def test_valid_post_id_parameter_get_request(self):
        response = self.client.get(
            self.url + '?post_id=1',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['count'])
        self.assertTrue(response.data['results'])
        self.assertTrue(response.data['next'])
        self.assertIsNone(response.data['previous'])
        self.assertEqual(len(response.data['results']), 10)

    def test_unauthenticated_get_request(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 401)
        response_data = json.loads(response.content)
        self.assertEqual(
            response_data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_invalid_post_id_get_request(self):
        response = self.client.get(
            self.url + '?post_id=2',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(str(response.data['detail']), 'Post not found.')


    def test_valid_user_id_parameter_get_request(self):
        response = self.client.get(
            self.url + '?user_id=2',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['count'])
        self.assertTrue(response.data['results'])
        self.assertIsNone(response.data['next'])
        self.assertIsNone(response.data['previous'])
        self.assertEqual(len(response.data['results']), 5)

    def test_invalid_user_id_get_request(self):
        response = self.client.get(
            self.url + '?user_id=3',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(str(response.data['detail']), 'User not found.')
    
    def test_invalid_get_request_parameters(self):
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(str(response.data['detail']), 'Invalid request parameters.')


class TestCommentRetrieveUpdateDestroy(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.access_token1 = AccessToken.for_user(user=self.user1)
        self.post = Post.objects.create(
            user=self.user,
            body='Test post body.'
        )
        self.post1 = Post.objects.create(
            user=self.user,
            body='Test1 post body.'
        )
        self.comment = Comment.objects.create(
            user=self.user,
            post=self.post,
            body='Test comment body.'
        )

    def test_unauthenticated_request(self):
        response = self.client.patch(
            reverse('post:comments_detail', kwargs={'pk':1}),
            data={'body': 'Updated comment body.'}
        )

        self.assertEqual(response.status_code, 401)
        response_data = json.loads(response.content)
        self.assertEqual(
            response_data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_unauthorized_request(self):
        response = self.client.patch(
            reverse('post:comments_detail', kwargs={'pk':1}),
            data={'body': 'Updated comment body.'},
            HTTP_AUTHORIZATION= f'Bearer {self.access_token1}'
        )


        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            'User does not have permission to access this object.'
        )

    def test_valid_get_request(self):
        response = self.client.get(
            reverse('post:comments_detail', kwargs={'pk':1}),
            HTTP_AUTHORIZATION= f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['user']['id'], 1)
        self.assertEqual(response.data['post'], 1)
        self.assertEqual(response.data['body'], 'Test comment body.')

    def test_invalid_post_id_in_get_request(self):
        response = self.client.get(
            reverse('post:comments_detail', kwargs={'pk':3}),
            HTTP_AUTHORIZATION= f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data['detail'], 'Not found.')

    def test_invalid_comment_id_in_get_request(self):
        response = self.client.get(
            reverse('post:comments_detail', kwargs={'pk':2}),
            HTTP_AUTHORIZATION= f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data['detail'], 'Not found.')

    def test_valid_patch_request(self):
        response = self.client.patch(
            reverse('post:comments_detail', kwargs={'pk':1}),
            data={
                'body': 'Updated comment body',
            },
            HTTP_AUTHORIZATION= f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['body'], 'Updated comment body')
    
    def test_invalid_data_in_patch_request(self):
        response = self.client.patch(
            reverse('post:comments_detail', kwargs={'pk':1}),
            data={},
            HTTP_AUTHORIZATION= f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['detail'], 'Invalid request data.')

    def test_valid_delete_request(self):
        response = self.client.delete(
            reverse('post:comments_detail', kwargs={'pk':1}),
            HTTP_AUTHORIZATION= f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 204)
