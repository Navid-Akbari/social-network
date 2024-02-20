from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse

from rest_framework_simplejwt.tokens import AccessToken
import json

from post.models import Post

User = get_user_model()

class TestPostList(TestCase):

    def setUp(self):
        self.client = Client()
        self.post_url = reverse('post:posts')
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


    def test_post_list_create_valid(self):
        response = self.client.post(
            self.post_url,
            data = {
                'body': 'Test post body.'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['user']['id'], 1)
        self.assertEqual(response.data['body'], 'Test post body.')

    def test_post_list_create_without_token(self):
        response = self.client.post(
            self.post_url,
            data = {
                'body': 'Test post body.'
            },
            content_type='application/json'
        )

        response_data = json.loads(response.content)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response_data['error']['message'],
            'No permission -- see authorization schemes'
        )

    def test_post_list_create_exceed_body_length(self):
        response = self.client.post(
            self.post_url,
            data = {
                'body': 'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['body'][0],
            'Ensure this field has no more than 250 characters.'
        )

    def test_post_list_get_valid(self):
        response = self.client.get(
            self.post_url,
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['count'])
        self.assertTrue(response.data['results'])
        self.assertTrue(response.data['next'])
        self.assertIsNone(response.data['previous'])
        self.assertEqual(len(response.data['results']), 10)

    def test_post_list_get_unauthenticated(self):
        response = self.client.get(self.post_url)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_post_list_get_url_parameters(self):
        response = self.client.get(
            self.post_url + '?search=test1',
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data['results'][0]['user']['username'],
            'test1'
        )
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['body'], 'User1 test post body.')

class TestPostDetail(TestCase):
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.user_access_token = AccessToken.for_user(user=self.user)
        self.post1 = Post.objects.create(
            user=self.user,
            body='Test post body.'
        )
        self.user1 = User.objects.create(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.user1_access_token = AccessToken.for_user(user=self.user1)
        self.post1 = Post.objects.create(
            user=self.user1,
            body='Test1 post body.'
        )

    def test_post_detail_get_valid(self):
        response = self.client.get(
            reverse('post:posts_detail', kwargs={'pk': 1}),
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['user']['username'], 'test')
        self.assertEqual(response.data['user']['email'], 'test@example.com')
        self.assertEqual(response.data['body'], 'Test post body.')

    def test_post_detail_get_detail_invalid(self):
        response = self.client.get(
            reverse('post:posts_detail', kwargs={'pk': 3}),
            HTTP_AUTHORIZATION=f'Bearer {self.user_access_token}'
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data['detail'], 'Not found.')

    def test_post_detail_patch_valid(self):
        response = self.client.patch(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            data={'body': 'Updated test1 post body.'},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}',
            content_type='application/json'
        )

        updated_post = Post.objects.get(pk=2)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(updated_post.body, 'Updated test1 post body.')

    def test_post_detail_patch_invalid_data(self):
        response = self.client.patch(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            data={'body': ''},
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['body'][0], 'This field may not be blank.')

    def test_post_detail_patch_unauthenticated_request(self):
        response = self.client.patch(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            data={'body': 'Updated test1 post body.'},
            content_type='application/json'
        )

        response_data = json.loads(response.content)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response_data['error']['message'],
            'No permission -- see authorization schemes'
        )

    def test_post_detail_delete_valid(self):
        response = self.client.delete(
            reverse('post:posts_detail', kwargs={'pk': 2}),
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}',
        )

        self.assertEqual(response.status_code, 204)
    
    def test_post_detail_delete_unauthenticated(self):
        response = self.client.delete(
            reverse('post:posts_detail', kwargs={'pk': 2}),
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_post_detail_delete_invalid_arg(self):
        response = self.client.delete(
            reverse('post:posts_detail', kwargs={'pk': 3}),
            HTTP_AUTHORIZATION=f'Bearer {self.user1_access_token}',
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data['detail'], 'Not found.')
