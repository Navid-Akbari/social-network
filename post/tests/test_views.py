from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse

from rest_framework_simplejwt.tokens import AccessToken

from post.models import Post

User = get_user_model()

class TestPostManager(TestCase):

    def setUp(self):
        self.client = Client()
        self.post_url = reverse('post:posts')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.user1= User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)
        self.post = Post.objects.create(
            user=self.user1,
            body='Test post body.'
        )
        for i in range(1, 20):
            Post.objects.create(
                user=self.user,
                body=f'Test{i} post body.'
            )

    def test_post_create_valid(self):
        response = self.client.post(
            self.post_url,
            data = {
                'body': 'Test post body.'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['user']['id'], 1)
        self.assertEqual(response.data['body'], 'Test post body.')

    def test_post_create_without_token(self):
        response = self.client.post(
            self.post_url,
            data = {
                'body': 'Test post body.'
            },
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_post_create_exceed_body_length(self):
        response = self.client.post(
            self.post_url,
            data = {
                'body': 'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
            },
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}',
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['body'][0],
            'Ensure this field has no more than 250 characters.'
        )

    def test_post_manager_get_valid(self):
        response = self.client.get(
            self.post_url,
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['count'])
        self.assertTrue(response.data['results'])
        self.assertTrue(response.data['next'])
        self.assertIsNone(response.data['previous']) 

    def test_post_manager_get_unauthenticated(self):
        response = self.client.get(self.post_url)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data['detail'],
            'Authentication credentials were not provided.'
        )

    def test_post_manager_get_url_parameters(self):
        response = self.client.get(
            self.post_url + '?search=test1',
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data['results'][0]['user']['username'],
            'test1'
        )

    def test_post_manager_get_detail_valid(self):
        response = self.client.get(
            reverse('post:posts_detail', kwargs={'pk': 1}),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['user']['username'], 'test1')
        self.assertEqual(response.data['user']['email'], 'test1@example.com')
        self.assertEqual(response.data['body'], 'Test post body.')

    def test_post_manager_get_detail_invalid(self):
        response = self.client.get(
            reverse('post:posts_detail', kwargs={'pk': 22}),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token}'
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.data['detail'], 'Not found.')
