from rest_framework import permissions
import requests
from django.conf import settings
import logging
from .service import BillingService  # Import BillingService for branch limit checks

# Configure logger
logger = logging.getLogger(__name__)

class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        result = request.user and request.user.is_authenticated and request.user.is_superuser
        logger.info(f"IsSuperuser.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, is_superuser={request.user.is_superuser}, result={result}")
        return result

class IsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        result = request.user and request.user.is_authenticated and getattr(request.user.role, 'name', None) == "ceo"
        logger.info(f"IsCEO.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, role={getattr(request.user.role, 'name', 'None')}, result={result}")
        return result

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        result = request.user and request.user.is_authenticated and getattr(request.user.role, 'name', None) == 'manager'
        logger.info(f"IsManager.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, role={getattr(request.user.role, 'name', 'None')}, result={result}")
        return result

class IsGeneralManager(permissions.BasePermission):
    def has_permission(self, request, view):
        result = request.user and request.user.is_authenticated and getattr(request.user.role, 'name', None) == 'general_manager'
        logger.info(f"IsGeneralManager.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, role={getattr(request.user.role, 'name', 'None')}, result={result}")
        return result

class IsBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        result = request.user and request.user.is_authenticated and getattr(request.user.role, 'name', None) == 'branch_manager'
        logger.info(f"IsBranchManager.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, role={getattr(request.user.role, 'name', 'None')}, result={result}")
        return result

class IsCEOorManagerOrGeneralManagerOrBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        result = request.user and request.user.is_authenticated and (
            request.user.is_superuser or getattr(request.user.role, 'name', None) in ['ceo', 'manager', 'general_manager', 'branch_manager']
        )
        logger.info(f"IsCEOorManagerOrGeneralManagerOrBranchManager.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, role={getattr(request.user.role, 'name', 'None')}, result={result}")
        return result

class CanViewEditUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if getattr(request.user.role, 'name', None) in ['ceo', 'general_manager']:
            return obj.tenant == request.user.tenant
        if getattr(request.user.role, 'name', None) in ['branch_manager', 'manager']:
            if request.user.tenant.branches.count() == 1:
                return obj.tenant == request.user.tenant
            else:
                return obj.tenant == request.user.tenant and any(cell in request.user.branch.all() for cell in obj.branch.all())
        return False

class CanDeleteUser(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if getattr(request.user.role, 'name', None) in ['ceo', 'general_manager']:
            return obj.tenant == request.user.tenant
        if getattr(request.user.role, 'name', None) in ['branch_manager', 'manager']:
            if request.user.tenant.branches.count() == 1:
                return obj.tenant == request.user.tenant
            else:
                return obj.tenant == request.user.tenant and any(cell in request.user.branch.all() for cell in obj.branch.all())
        return False

class CanCreateBranch(permissions.BasePermission):
    def has_permission(self, request, view):
        result = request.user and request.user.is_authenticated and getattr(request.user.role, 'name', None) in ['ceo', 'general_manager']
        logger.info(f"CanCreateBranch.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, role={getattr(request.user.role, 'name', 'None')}, result={result}")
        return result

class HasNoRoleOrIsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        result = not request.user.role or getattr(request.user.role, 'name', None) == "ceo"
        logger.info(f"HasNoRoleOrIsCEO.has_permission: user={request.user}, is_authenticated={request.user.is_authenticated}, role={getattr(request.user.role, 'name', 'None')}, result={result}")
        return result

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
            logger.info(f"HasActiveSubscription.has_permission: Checking subscription for tenant_id={tenant_id}, view={view.basename}, action={view.action}")
            if view.basename == 'branch' and view.action == 'create':
                # Check branch creation limit using BillingService
                can_create, message = BillingService.can_create_branch(tenant_id, request=request)
                logger.info(f"HasActiveSubscription.has_permission: Branch creation check, can_create={can_create}, message={message}")
                return can_create
            # General access check for other views or actions
            response = requests.get(
                f"{settings.BILLING_MICROSERVICE_URL}/api/v1/billing/access-check/",
                headers={"Authorization": request.META.get('HTTP_AUTHORIZATION')}
            )
            response.raise_for_status()  # Raise exception for bad status codes
            data = response.json()
            result = data.get('access', False)
            logger.info(f"HasActiveSubscription.has_permission: view={view.basename}, action={view.action}, access={result}, response_data={data}")
            return result
        except requests.RequestException as e:
            logger.error(f"HasActiveSubscription.has_permission: Request failed for tenant_id={tenant_id}: {str(e)}")
            return False