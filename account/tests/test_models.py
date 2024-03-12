from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.hashers import check_password
from django.contrib.auth import get_user_model
from django.test import TestCase, TransactionTestCase, override_settings

from PIL import Image
import io
import os

from social_network.settings import BASE_DIR, TEST_MEDIA_ROOT
from account.models import Profile

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

    def test_missing_username_email_password(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='',
                email='',
                password=''
            )

        self.assertEqual(dict(error.exception)['username'][0], 'This field cannot be blank.')
        self.assertEqual(dict(error.exception)['email'][0], 'This field cannot be blank.')
        self.assertEqual(dict(error.exception)['password'][0], 'This field cannot be blank.')

    def test_username_password_firstname_lastname_min_length_validation(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='as',
                email='test@example.com',
                password='test',
                first_name='te',
                last_name='te'
            )

        self.assertEqual(
            dict(error.exception)['username'][0], 
            'This field cannot be less than 3 characters.'
        )
        self.assertEqual(
            dict(error.exception)['password'][0], 
            'This password is too short. It must contain at least 8 characters.'
        )
        self.assertEqual(
            dict(error.exception)['first_name'][0], 
            'This field cannot be less than 3 characters.'
        )
        self.assertEqual(
            dict(error.exception)['last_name'][0], 
            'This field cannot be less than 3 characters.'
        )

    def test_username_email_password_max_length_validation(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijk',
                email='abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij@example.com',
                password='abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
                'abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij'
            )

        self.assertEqual(
            dict(error.exception)['username'][0], 
            'Ensure this value has at most 50 characters (it has 51).'
        )
        self.assertEqual(
            dict(error.exception)['email'][0], 
            'Ensure this value has at most 50 characters (it has 62).'
        )
        self.assertEqual(
            dict(error.exception)['password'][0], 
            'Ensure this value has at most 128 characters (it has 170).'
        )

    def test_username_symbols_validation(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='test@',
                email='test@example.com',
                password='testing321'
            )

        self.assertEqual(
            dict(error.exception)['username'][0], 
            'Enter a valid username. This value may contain only letters,'
            ' numbers, and @/./+/-/_ characters.'
        )

    def test_invalid_email_format(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='test',
                email='test@example.c',
                password='testing321'
            )

        self.assertEqual(dict(error.exception)['email'][0], 'Enter a valid email address.')

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

    def test_firstname_lastname_invalid_format(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='test',
                email='test@example.com',
                password='testing321',
                first_name='test@',
                last_name='test@'
            )

        self.assertEqual(
            dict(error.exception)['last_name'][0],
            'First name and last name can only contain letters.'
        )
        self.assertEqual(
            dict(error.exception)['last_name'][0],
            'First name and last name can only contain letters.'
        )

    def test_invalid_phone_number(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='test',
                email='test@example.com',
                password='testing321',
                phone_number='95'
            )

        self.assertEqual(
            dict(error.exception)['phone_number'][0],
            'Phone number must be entered in the format: "+999999999".'
            ' Up to 15 digits allowed.'
        )

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

    def test_username_email_unique_constraint(self):
        with self.assertRaises(ValidationError) as error:
            User.objects.create_user(
                username='test1',
                email='test1@example.com',
                password='testing321'
            )
        
        self.assertEqual(
            dict(error.exception)['username'][0],
            'Custom user with this Username already exists.'
        )
        self.assertEqual(
            dict(error.exception)['email'][0],
            'Custom user with this Email already exists.'
        )


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT)
class TestProfileModel(TransactionTestCase):

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
