from rest_framework import permissions
from apps.user.models import User
from .models import Tenant, Branch
from django.conf import settings
import requests

class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class IsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'ceo'


class IsSuperuserOrCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
            request.user.is_superuser or
            request.user.role == 'ceo'
        )


class IsBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'Branch_manager'


class IsCEOorBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
                request.user.is_superuser or
                request.user.role in ['ceo', 'Branch_manager']
        )


class CanViewEditTenant(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role == 'ceo':
            return obj == request.user.tenant
        return False


class CanDeleteTenant(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role == 'ceo':
            return obj == request.user.tenant
        return False


class CanViewEditBranch(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role == 'ceo':
            return obj.tenant == request.user.tenant
        if request.user.role == 'Branch_manager':
            return obj.tenant == request.user.tenant and obj in request.user.branch.all()
        return False


class CanDeleteBranch(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role == 'ceo':
            return obj.tenant == request.user.tenant
        return False


# class HasActiveSubscription(permissions.BasePermission):
#     def has_permission(self, request, view):
#         if request.user.is_superuser:
#             return True
#         tenant_id = request.user.tenant.id if request.user.tenant else None
#         if not tenant_id:
#             print(f"HasActiveSubscription: No tenant_id for user {request.user.email}")
#             return False
#         try:
#             url = f"{settings.BILLING_MICROSERVICE_URL}/access-check/limits/"
#             headers = {"Authorization": request.META.get('HTTP_AUTHORIZATION')}
#             print(f"HasActiveSubscription: Making request to {url} with headers {headers}")
#             response = requests.get(
#                 url,
#                 headers=headers
#             )
#             response.raise_for_status()
#             data = response.json()
#             print(f"HasActiveSubscription: Received response: {data}")
#             if view.basename == 'branch':
#                 return data.get('branches_allowed', False)
#             if view.basename == 'user_management':
#                 return data.get('users_allowed', False)
#             return data.get('access', False)
#         except requests.RequestException as e:
#             print(f"HasActiveSubscription: RequestException caught: {e}")
#             return False