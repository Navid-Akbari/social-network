from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError

PHONE_NUMBER_VALIDATOR = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
)

USERNAME_VALIDATOR = RegexValidator(
    regex=r'^[\w.@+-]+$',
    message="Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters."
)

def username_length_validation(username):
    if len(username) < 3:
        raise ValidationError('Username cannot be less than 3 characters.')