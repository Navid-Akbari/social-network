from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.test import TestCase

User = get_user_model()


class TestUserModel(TestCase):

    def test_create_valid_user(self):
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testing321'
        )

        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'testuser')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)


    def test_createuser_missing_username(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='',
                email='test@example.com',
                password='testing321'
            )


    def test_createuser_username_length_validation(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='as',
                email='test@example.com',
                password='testing321'
            )


    def test_createuser_username_symbols_validation(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='test@',
                email='test@example.com',
                password='testing321'
            )


    def test_createuser_missing_email(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='test@',
                email='',
                password='testing321'
            )


    def test_createuser_invalid_email_format(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='test@',
                email='invalidEmail',
                password='testing321'
            )


    def test_createuser_missing_password(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='test@',
                email='invalidEmail',
                password=''
            )


    def test_createuser_django_default_validation(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='test@',
                email='invalidEmail',
                password='a1'
            )


    def test_createuser_with_additional_info(self):
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testing321',
            first_name='test',
            last_name='test',
            phone_number='9999999999'
        )

        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.first_name, 'Test')
        self.assertEqual(user.last_name, 'Test')
        self.assertEqual(user.phone_number, '9999999999')
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)


    def test_create_user_with_invalid_first_name(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='testuser',
                email='test@example.com',
                password='testing321',
                first_name='te',
            )


    def test_create_user_with_invalid_last_name(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='testuser',
                email='test@example.com',
                password='testing321',
                last_name='te',
            )


    def test_create_user_with_invalid_phone_number(self):
        with self.assertRaises(ValidationError):
            User.objects.create_user(
                username='testuser',
                email='test@example.com',
                password='testing321',
                phone_number='95',
            )


    def test_create_valid_superuser(self):
        user = User.objects.create_superuser(
            username='testuser',
            email='test@example.com',
            password='testing321'
        )

        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.username, 'testuser')
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)


    def test_create_superuser_with_false_is_staff(self):
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username='testuser',
                email='test@example.com',
                password='testing321',
                is_staff=False
            )
    
    
    def test_create_superuser_with_false_is_active(self):
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username='testuser',
                email='test@example.com',
                password='testing321',
                is_staff=False
            )
