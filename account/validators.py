from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError


PHONE_NUMBER_VALIDATOR = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message='Phone number must be entered in the format: "+999999999". Up to 15 digits allowed.'
)

USERNAME_VALIDATOR = RegexValidator(
    regex=r'^[\w.+-]+$',
    message='Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.'
)

NAME_VALIDATOR = RegexValidator(
    regex=r'^[a-zA-Z]+$',
    message='First name and last name can only contain letters.'
)


def name_length_validation(name):

    if len(name) < 3:
        raise ValidationError('This field cannot be less than 3 characters.')

def firstname_lastname_must_both_exist_validation(user):
    if user.first_name:
        if not user.last_name:
            raise ValidationError({'first_name': 'last_name is missing.'})
        user.first_name = user.first_name.capitalize()

    if user.last_name:
        if not user.first_name:
            raise ValidationError({'last_name': 'first_name is missing.'})
        user.last_name = user.last_name.capitalize()