from rest_framework import permissions
from apps.user.models import User, Tenant, Branch
from django.conf import settings
import requests

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
            response.raise_for_status()
            data = response.json()
            if view.basename == 'branch':
                return data.get('branches_allowed', False)
            if view.basename == 'user_management':
                return data.get('users_allowed', False)
            return data.get('access', False)
        except requests.RequestException:
            return False