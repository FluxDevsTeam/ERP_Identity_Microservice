from drf_yasg.utils import swagger_auto_schema
from .pagination import PAGINATION_PARAMS
from rest_framework.permissions import BasePermission


def swagger_helper(tags, model):
    def decorators(func):
        descriptions = {
            "list": f"Retrieve a list of {model}",
            "retrieve": f"Retrieve details of a specific {model}",
            "create": f"Create a new {model}",
            "partial_update": f"Update a {model}",
            "destroy": f"Delete a {model}",
        }

        action_type = func.__name__
        get_description = descriptions.get(action_type, f"{action_type} {model}")
        return swagger_auto_schema(manual_parameters=PAGINATION_PARAMS, operation_id=f"{action_type} {model}", operation_description=get_description, tags=[tags])(func)

    return decorators


class OR(BasePermission):
    def __init__(self, *perms):
        self.perms = perms  # Store instantiated permission objects (e.g., IsSuperuser(), IsCEO())

    def has_permission(self, request, view):
        # Use the instantiated permission objects directly
        return any(perm.has_permission(request, view) for perm in self.perms)