import io
import os
from PIL import Image

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from account.serializers import (
    UserSerializer,
    ProfileSerializer,
    FriendRequestSerializer,
    FriendSerializer
)
from account.models import Profile
from social_network.settings import BASE_DIR, TEST_MEDIA_ROOT

User = get_user_model()

class TestUserSerializer(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )

    def test_valid_input(self):
        serializer = UserSerializer(
            data={
                'username':'test',
                'email':'test@example.com',
                'password':'testing321',
                'first_name':'tESt',
                'last_name':'tESt',
                'phone_number':'1234567890'
            }
        )

        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'test')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(check_password('testing321', user.password))
        self.assertEqual(user.first_name, 'Test')
        self.assertEqual(user.last_name, 'Test')
        self.assertEqual(user.phone_number,  '1234567890')

    def test_missing_username_email_password(self):
        serializer = UserSerializer(
            data={
                'username':'',
                'email':'',
                'password':'',
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['username'][0], 'This field may not be blank.')
        self.assertEqual(serializer.errors['email'][0], 'This field may not be blank.')
        self.assertEqual(serializer.errors['password'][0], 'This field may not be blank.')

    def test_username_password_firstname_lastname_min_length_validation(self):
        serializer = UserSerializer(
            data={
                'username':'te',
                'email':'test@example.com',
                'password':'test',
                'first_name':'te',
                'last_name':'te',
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['username'][0], 
            'This field cannot be less than 3 characters.'
        )
        self.assertEqual(
            serializer.errors['password'],
            [
                'This password is too short. It must contain at least 8 characters.',
                'This password is too common.'
            ]
        )
        self.assertEqual(
            serializer.errors['first_name'][0], 
            'This field cannot be less than 3 characters.'
        )
        self.assertEqual(
            serializer.errors['last_name'][0], 
            'This field cannot be less than 3 characters.'
        )

    def test_username_email_password_max_length_validation(self):
            serializer = UserSerializer(
                data={
                    'username':'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijk',
                    'email':'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij@example.com',
                    'password':'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                    'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                    'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                }
            )

            self.assertFalse(serializer.is_valid())
            self.assertEqual(
                serializer.errors['username'][0], 
                'Ensure this field has no more than 50 characters.'
            )
            self.assertEqual(
                serializer.errors['email'][0], 
                'Ensure this field has no more than 50 characters.'
            )
            self.assertEqual(
                serializer.errors['password'][0],
                'Ensure this field has no more than 128 characters.'
            )

    def test_username_symbols_validation(self):
        serializer = UserSerializer(
            data={
                    'username':'test@',
                    'email':'test@example.com',
                    'password':'testing321'
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['username'][0], 
            'Enter a valid username. This value may contain only letters,'
            ' numbers, and @/./+/-/_ characters.'
        )

    def test_invalid_email_format(self): 
        serializer = UserSerializer(
                data={
                    'username':'test',
                    'email':'test@example.c',
                    'password':'testing321'
                }
            )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['email'][0], 'Enter a valid email address.')

    def testadditional_valid_info_and_capitaliziation_of_firstname_lastname(self):
        serializer = UserSerializer(
            data={
                'username':'test',
                'email':'test@example.com',
                'password':'testing321',
                'first_name':'tESt',
                'last_name':'tESt',
                'phone_number':'9999999999'
            }
        )

        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'test')
        self.assertTrue(check_password('testing321', user.password))
        self.assertEqual(user.first_name, 'Test')
        self.assertEqual(user.last_name, 'Test')
        self.assertEqual(user.phone_number, '9999999999')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)

    def test_firstname_must_have_lastname(self):
        serializer = UserSerializer(
            data={
                'username':'test',
                'email':'test@example.com',
                'password':'testing321',
                'first_name':'test'
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['first_name'][0], 'last_name is missing.')
    
    def test_lastname_must_have_firstname(self):
        serializer = UserSerializer(
            data={'username':'test',
                'email':'test@example.com',
                'password':'testing321',
                'last_name':'test'
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['last_name'][0], 'first_name is missing.')

    def test_firstname_lastname_invalid_format(self):
        serializer = UserSerializer(
            data={
                'username':'test',
                'email':'test@example.com',
                'password':'testing321',
                'first_name':'test@',
                'last_name':'test@'
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['last_name'][0],
            'First name and last name can only contain letters.'
        )
        self.assertEqual(
            serializer.errors['last_name'][0],
            'First name and last name can only contain letters.'
        )

    def test_invalid_phone_number(self):
        serializer = UserSerializer(
            data={
                'username':'test',
                'email':'test@example.com',
                'password':'testing321',
                'phone_number':'95'
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['phone_number'][0],
            'Phone number must be entered in the format: "+999999999".'
            ' Up to 15 digits allowed.'
        )

    def test_username_email_unique_constraint(self):
        serializer = UserSerializer(
            data={
                'username':'test1',
                'email':'test1@example.com',
                'password':'testing321'
            }
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            serializer.errors['username'][0],
            'custom user with this username already exists.'
        )
        self.assertEqual(
            serializer.errors['email'][0],
            'custom user with this email already exists.'
        )


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT)
class TestProfileSerializer(TestCase):
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321'
        )
        with Image.open(BASE_DIR / 'account/tests/cat.jpg') as im:
            image_io = io.BytesIO()
            im.save(image_io, format='JPEG')
            image_io.seek(0)
            self.image = SimpleUploadedFile('cat.jpg', image_io.read(), content_type='image/jpeg')
        self.profile = Profile.objects.get(user=self.user)

    def test_valid(self):
        serializer = ProfileSerializer(self.profile, data={'image': self.image})

        self.assertTrue(serializer.is_valid())
        serializer.save()
        self.assertTrue(os.path.exists(TEST_MEDIA_ROOT / 'cat.jpg'))

    def tearDown(self):
        for file in ['cat.jpg']:
            if os.path.exists(TEST_MEDIA_ROOT / file):
                os.remove(TEST_MEDIA_ROOT / file)
        return super().tearDown()


class TestFriendRequestSerializer(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='test',
            email='test@gmail.com',
            password='testing321'
        )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@gmail.com',
            password='testing321'
        )

    def test_valid_input(self):
        serializer = FriendRequestSerializer(
            data={
                'from_user': self.user.pk,
                'to_user': self.user1.pk
            }
        )

        self.assertTrue(serializer.is_valid())
        friend_request = serializer.save()
        self.assertEqual(friend_request.from_user, self.user)
        self.assertEqual(friend_request.to_user, self.user1)
    
    def test_invalid_fromuser_value(self):
        serializer = FriendRequestSerializer(
            data={
                'from_user': '',
                'to_user': self.user1.pk
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['from_user'][0], 'This field may not be null.')

    def test_unique_together_constraint(self):
        first_serializer = FriendRequestSerializer(
            data={
                'from_user': self.user.pk,
                'to_user': self.user1.pk
            }
        )
        second_serializer = FriendRequestSerializer(
            data={
                'from_user': self.user.pk,
                'to_user': self.user1.pk
            }
        )

        self.assertTrue(first_serializer.is_valid())
        first_serializer.save()
        self.assertFalse(second_serializer.is_valid())
        self.assertEqual(
            second_serializer.errors['non_field_errors'][0],
            'The fields from_user, to_user must make a unique set.'
        )

    def test_user_friends_themselves(self):
        serializer = FriendRequestSerializer(
            data={
                'from_user': self.user.pk,
                'to_user': self.user.pk
            }
        )
        
        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['error'][0], 'Users cannot friend themselves.')


class TestFriendSerializer(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='test',
            email='test@gmail.com',
            password='testing321'
        )
        self.user1 = User.objects.create_user(
            username='test1',
            email='test1@gmail.com',
            password='testing321'
        )

    def test_valid(self):
        serializer = FriendSerializer(
            data={
                'first_user': self.user.pk,
                'second_user': self.user1.pk
            }
        )

        self.assertTrue(serializer.is_valid())
        friend = serializer.save()
        self.assertEqual(friend.first_user, self.user)
        self.assertEqual(friend.second_user, self.user1)

    def test_invalid_first_user_and_second_user(self):
        serializer = FriendSerializer(
            data={
                'first_user': '',
                'second_user': self.user1
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['first_user'][0], 'This field may not be null.')
        self.assertEqual(
            serializer.errors['second_user'][0],
            'Incorrect type. Expected pk value, received CustomUser.'
        )

    def test_duplicate_friend_instance(self):
        serializer = FriendSerializer(
            data={
                'first_user': self.user.pk,
                'second_user': self.user1.pk
            }
        )

        serializer1 = FriendSerializer(
            data={
                'first_user': self.user.pk,
                'second_user': self.user1.pk
            }
        )

        serializer.is_valid()
        serializer.save()
        self.assertFalse(serializer1.is_valid())
        self.assertEqual(
            serializer1.errors['non_field_errors'][0],
            'The fields first_user, second_user must make a unique set.'
        )
