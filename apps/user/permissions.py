from rest_framework import permissions
from .models import User


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
