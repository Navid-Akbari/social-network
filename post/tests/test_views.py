from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse

from rest_framework_simplejwt.tokens import AccessToken

User = get_user_model()

class TestPostManager(TestCase):

    def setUp(self):
        self.client = Client()
        self.post_url = reverse('post:create_get_post')
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        self.access_token = AccessToken.for_user(user=self.user)


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

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data['user'][0],
            'User must be authenticated and a valid user instance.'
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
