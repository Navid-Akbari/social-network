from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.test import TestCase

from account.serializers import UserSerializer

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
        self.assertEqual(str(serializer.errors['username'][0]), 'This field may not be blank.')
        self.assertEqual(str(serializer.errors['email'][0]), 'This field may not be blank.')
        self.assertEqual(str(serializer.errors['password'][0]), 'This field may not be blank.')

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
            str(serializer.errors['username'][0]), 
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
            str(serializer.errors['first_name'][0]), 
            'This field cannot be less than 3 characters.'
        )
        self.assertEqual(
            str(serializer.errors['last_name'][0]), 
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
                str(serializer.errors['username'][0]), 
                'Ensure this field has no more than 50 characters.'
            )
            self.assertEqual(
                str(serializer.errors['email'][0]), 
                'Ensure this field has no more than 50 characters.'
            )
            self.assertEqual(
                str(serializer.errors['password'][0]),
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
            str(serializer.errors['username'][0]), 
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
        self.assertEqual(str(serializer.errors['email'][0]), 'Enter a valid email address.')

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
        self.assertEqual(str(serializer.errors['first_name'][0]), 'last_name is missing.')
    
    def test_lastname_must_have_firstname(self):
        serializer = UserSerializer(
            data={'username':'test',
                'email':'test@example.com',
                'password':'testing321',
                'last_name':'test'
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertEqual(str(serializer.errors['last_name'][0]), 'first_name is missing.')

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
            str(serializer.errors['last_name'][0]),
            'First name and last name can only contain letters.'
        )
        self.assertEqual(
            str(serializer.errors['last_name'][0]),
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
            str(serializer.errors['phone_number'][0]),
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
            str(serializer.errors['username'][0]),
            'custom user with this username already exists.'
        )
        self.assertEqual(
            str(serializer.errors['email'][0]),
            'custom user with this email already exists.'
        )
