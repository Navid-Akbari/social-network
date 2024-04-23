from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase, override_settings

from PIL import Image
import io
import os

from social_network.settings import BASE_DIR, TEST_MEDIA_ROOT
from account.models import Profile, FriendRequest, Friend

User = get_user_model()


class TestUserModel(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='test1',
            email='test1@example.com',
            password='testing321'
        )

    def test_valid_input(self):
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testing321'
        )

        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'testuser')
        self.assertTrue(check_password('testing321', user.password))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)

    def testadditional_valid_info_and_capitaliziation_of_firstname_lastname(self):
        user = User.objects.create_user(
            username='test',
            email='test@example.com',
            password='testing321',
            first_name='tESt',
            last_name='tESt',
            phone_number='9999999999'
        )

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
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='test',
                email='test@example.com',
                password='testing321',
                first_name='test'
            )

        self.assertEqual(dict(error.exception)['first_name'][0], 'last_name is missing.')

    def test_lastname_must_have_firstname(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='test',
                email='test@example.com',
                password='testing321',
                last_name='test'
            )

        self.assertEqual(dict(error.exception)['last_name'][0], 'first_name is missing.')

    def test_valid_superuser(self):
        user = User.objects.create_superuser(
            username='test',
            email='test@example.com',
            password='testing321'
        )

        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'test')
        self.assertTrue(check_password('testing321', user.password))
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)

    def test_false_is_staff(self):
        with self.assertRaises(ValueError) as error:
            User.objects.create_superuser(
                username='test',
                email='test@example.com',
                password='testing321',
                is_staff=False
            )

        self.assertEqual(
            error.exception.args[0], 
            'Superuser must have is_staff set to True.'
        )

    def test_false_is_superuser(self):
        with self.assertRaises(ValueError) as error:
            User.objects.create_superuser(
                username='test',
                email='test@example.com',
                password='testing321',
                is_superuser=False
            )
        
        self.assertEqual(
            error.exception.args[0], 
            'Superuser must have is_superuser set to True.'
        )


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT)
class TestProfileModel(TestCase):

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
        self.user_profile = Profile.objects.get(user=self.user)

    def test_valid_image(self):
        self.assertEqual(self.user_profile.image.name, 'default.jpg')

        self.user_profile.image = self.image
        self.user_profile.save()

        self.updated_profile = Profile.objects.get(user=self.user)
        self.assertEqual(self.updated_profile.image.name, 'cat.jpg')
        with Image.open(TEST_MEDIA_ROOT / 'cat.jpg') as im:
            self.assertTrue(im.size[0] <= 300 )
            self.assertTrue(im.size[1] <= 300 )

    def test_new_upload_deletes_old_image(self):
        self.user_profile.image = self.image
        self.user_profile.save()
        self.assertEqual(self.user_profile.image.path, os.path.join(TEST_MEDIA_ROOT / 'cat.jpg'))

        with Image.open(BASE_DIR / 'account/tests/cat.jpg') as im:
            image_io = io.BytesIO()
            im.save(image_io, format='JPEG')
            image_io.seek(0)
            image = SimpleUploadedFile('replaced_cat.jpg', image_io.read(), content_type='image/jpeg')
        self.user_profile.image = image
        self.user_profile.save()

        self.assertFalse(os.path.exists(TEST_MEDIA_ROOT / 'cat.jpg'))
        self.assertTrue(os.path.exists(TEST_MEDIA_ROOT / 'replaced_cat.jpg'))

    def tearDown(self):
        for file in ['cat.jpg', 'replaced_cat.jpg']:
            if os.path.exists(TEST_MEDIA_ROOT / file):
                os.remove(TEST_MEDIA_ROOT / file)

        return super().tearDown()


class TestFriendRequestModel(TestCase):
    def setUp(self):
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

    def test_valid_input(self):
        FriendRequest.objects.create(
            from_user=self.user,
            to_user=self.user1
        )
        friend_request = FriendRequest.objects.filter(from_user=self.user).first()

        self.assertIsNotNone(friend_request)
        self.assertEqual(friend_request.to_user, self.user1)


class TestFriendModel(TestCase):
    
    def setUp(self):
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
    
    def test_valid_input(self):
        Friend.objects.create(
            first_user=self.user,
            second_user=self.user1
        )

        friends = Friend.objects.all()

        self.assertEqual(len(friends), 1)
        self.assertEqual(friends[0].first_user, self.user)
        self.assertEqual(friends[0].second_user, self.user1)

    def test_unique_constraint(self):
        Friend.objects.create(
            first_user=self.user,
            second_user=self.user1
        )
        with self.assertRaises(IntegrityError):
            Friend.objects.create(
            first_user=self.user,
            second_user=self.user1
        )
