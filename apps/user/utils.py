import threading
from drf_yasg.utils import swagger_auto_schema
from django.core.mail import send_mail
from django.conf import settings


class EmailThread(threading.Thread):
    def __init__(self, subject, message, recipient_list):
        self.subject = subject
        self.message = message
        self.recipient_list = recipient_list
        super().__init__()

    def run(self):
        send_mail(
            self.subject,
            self.message,
            settings.EMAIL_HOST_USER,
            self.recipient_list,
        )


def swagger_helper(tags, model, description=None):
    def decorators(func):
        descriptions = {
            "list": f"Retrieve a list of {model}",
            "retrieve": f"Retrieve details of a specific {model}",
            "create": f"Create a new {model}",
            "partial_update": f"Update a {model}",
            "destroy": f"Delete a {model}",
        }

        action_type = func.__name__
        if not description:
            get_description = descriptions.get(action_type, f"{action_type} {model}")
            return swagger_auto_schema(operation_id=f"{action_type} {model}", operation_description=get_description, tags=[tags])(func)
        return swagger_auto_schema(operation_id=f"{action_type} {model}", operation_description=description, tags=[tags])(func)

    return decorators
