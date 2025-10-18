from rest_framework import permissions
from .models import User
import requests
from django.conf import settings


class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class IsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'ceo'


class IsBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'Branch_manager'


class IsCEOorBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
                request.user.is_superuser or
                request.user.role in ['ceo', 'Branch_manager']
        )


class CanViewEditUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role == 'ceo':
            return obj.tenant == request.user.tenant
        if request.user.role == 'Branch_manager':
            return obj.tenant == request.user.tenant and any(
                branch in request.user.branch.all() for branch in obj.branch.all())
        return False


class CanDeleteUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role == 'ceo':
            return obj.tenant == request.user.tenant
        return False


class HasActiveSubscription(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True
        tenant_id = request.user.tenant.id if request.user.tenant else None
        if not tenant_id:
            return False
        try:
            response = requests.get(
                f"{settings.BILLING_MICROSERVICE_URL}/access-check/limits/",
                headers={"Authorization": request.META.get('HTTP_AUTHORIZATION')}
            )
            if response.status_code != 200:
                return False
            data = response.json()
            if view.basename == 'branch':
                return data.get('branches_allowed', False)
            if view.basename == 'user_management':
                return data.get('users_allowed', False)
            return data.get('access', False)
        except requests.RequestException:
            return False
