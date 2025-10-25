import requests
from rest_framework import permissions
import logging
from apps.user.services import BillingService
from apps.user.models import User
from apps.user.models_auth import TempUser

logger = logging.getLogger(__name__)

class CanManageTempUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
            request.user.is_superuser or
            request.user.role.name in ['ceo', 'general_manager', 'branch_manager', 'manager']
        )

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role.name in ['ceo', 'general_manager']:
            return obj.tenant == request.user.tenant  # Access all TempUsers in tenant
        if request.user.role.name in ['branch_manager', 'manager']:
            return obj.tenant == request.user.tenant and any(
                branch in request.user.branch.all() for branch in obj.branch.all()
            )  # Only TempUsers in their branch
        return False

class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser

class IsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_ceo_role()

class HasNoRoleOrIsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        if not request.user.role or request.user.is_ceo_role():
            return True
        return False

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role.name == 'manager'

class IsGeneralManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role.name == 'general_manager'

class IsBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role.name == 'branch_manager'

class IsCEOorManagerOrGeneralManagerOrBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
            request.user.is_superuser or
            request.user.role.name in ['ceo', 'manager', 'general_manager', 'branch_manager']
        )

class CanViewEditUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role.name in ['ceo', 'general_manager']:
            return obj.tenant == request.user.tenant  # Access all Users in tenant
        if request.user.role.name in ['branch_manager', 'manager']:
            return obj.tenant == request.user.tenant and any(
                branch in request.user.branch.all() for branch in obj.branch.all()
            )  # Only Users in their branch
        return False

class CanDeleteUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if request.user.role.name in ['ceo', 'general_manager']:
            return obj.tenant == request.user.tenant  # Delete all Users in tenant
        if request.user.role.name in ['branch_manager', 'manager']:
            return obj.tenant == request.user.tenant and any(
                branch in request.user.branch.all() for branch in obj.branch.all()
            )  # Delete only Users in their branch
        return False

class CanCreateBranch(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role.name in ['ceo', 'general_manager']

class HasActiveSubscription(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            logger.info("HasActiveSubscription.has_permission: Superuser bypass, returning True")
            return True
        tenant_id = request.user.tenant.id if request.user.tenant else None
        if not tenant_id:
            logger.warning("HasActiveSubscription.has_permission: No tenant_id, returning False")
            return False
        try:
            logger.info(
                f"HasActiveSubscription.has_permission: Checking for tenant_id={tenant_id}, view={view.basename}, action={view.action}")
            if view.basename == 'user_management' and view.action == 'create':
                current_user_count = User.objects.filter(tenant__id=tenant_id).count() + TempUser.objects.filter(tenant__id=tenant_id).count()
                can_create, message = BillingService.can_create_user(tenant_id, current_user_count, request)
                logger.info(
                    f"HasActiveSubscription.has_permission: User creation check, can_create={can_create}, message={message}")
                return can_create
            subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
            result = subscription_details.get('access', False) if subscription_details else False
            logger.info(
                f"HasActiveSubscription.has_permission: view={view.basename}, action={view.action}, access={result}")
            return result
        except requests.RequestException as e:
            logger.error(f"HasActiveSubscription.has_permission: Request failed for tenant_id={tenant_id}: {str(e)}")
            return False