import hashlib
import hmac
import json
import time
from drf_yasg.utils import swagger_auto_schema
from django.conf import settings
import requests


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
            return swagger_auto_schema(operation_id=f"{action_type} {model}", operation_description=get_description,
                                       tags=[tags])(func)
        return swagger_auto_schema(operation_id=f"{action_type} {model}", operation_description=description,
                                   tags=[tags])(func)

    return decorators
