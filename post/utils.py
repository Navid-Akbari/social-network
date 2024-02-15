def format_serializer_errors(serializer_errors):
    formatted_errors = {}
    for field, messages in serializer_errors.items():
        formatted_errors[field] = ", ".join(str(message) for message in messages)
    return formatted_errors