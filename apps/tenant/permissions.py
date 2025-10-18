from rest_framework import permissions
import requests
from django.conf import settings


class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class IsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'ceo'


class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'manager'


class IsGeneralManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'general_manager'


class IsBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == 'branch_manager'


class IsCEOorManagerOrGeneralManagerOrBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
            request.user.is_superuser or
            request.user.role in ['ceo', 'manager', 'general_manager', 'branch_manager']
        )


class CanViewEditUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role in ['ceo', 'general_manager']:
            return obj.tenant == request.user.tenant
        if request.user.role in ['branch_manager', 'manager']:
            if request.user.tenant.branches.count() == 1:
                return obj.tenant == request.user.tenant
            else:
                return obj.tenant == request.user.tenant and any(
                    cell in request.user.branch.all() for cell in obj.branch.all()
                )
        return False


class CanDeleteUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role in ['ceo', 'general_manager']:
            return obj.tenant == request.user.tenant
        if request.user.role in ['branch_manager', 'manager']:
            if request.user.tenant.branches.count() == 1:
                return obj.tenant == request.user.tenant
            else:
                return obj.tenant == request.user.tenant and any(
                    cell in request.user.branch.all() for cell in obj.branch.all()
                )
        return False


class CanCreateBranch(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role in ['ceo', 'general_manager']


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
