import logging

import requests
from rest_framework import permissions
from .service import BillingService
# No Permission model, using static permissions

logger = logging.getLogger(__name__)


class IsSuperuser(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.user.tenant.id if request.user.tenant else 'None'
        logger.info(
            f"IsSuperuser: Checking for user={request.user.email}, tenant_id={tenant_id}, view={view.basename}, action={view.action}")
        return request.user and request.user.is_authenticated and request.user.is_superuser


class IsCEO(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.user.tenant.id if request.user.tenant else 'None'
        logger.info(
            f"IsCEO: Checking for user={request.user.email}, tenant_id={tenant_id}, view={view.basename}, action={view.action}")
        return request.user and request.user.is_authenticated and request.user.is_ceo_role()


class IsCEOorManagerOrGeneralManagerOrBranchManager(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.user.tenant.id if request.user.tenant else 'None'
        logger.info(
            f"IsCEOorManager: Checking for user={request.user.email}, tenant_id={tenant_id}, view={view.basename}, action={view.action}")
        return request.user and request.user.is_authenticated and (
                request.user.is_superuser or
                (request.user.role and request.user.role in ['ceo', 'manager', 'general_manager',
                                                                  'branch_manager'])
        )


class HasActiveSubscription(permissions.BasePermission):
    def has_permission(self, request, view):
        tenant_id = request.user.tenant.id if request.user.tenant else None
        logger.info(
            f"HasActiveSubscription: Checking for user={request.user.email}, tenant_id={tenant_id}, view={view.basename}, action={view.action}")

        # Allow list and retrieve actions without subscription check
        if view.action in ['list', 'retrieve']:
            logger.info(f"HasActiveSubscription: Bypassing subscription check for action={view.action}")
            return True
        if request.user.is_superuser:
            logger.info("HasActiveSubscription: Superuser bypass")
            return True
        if not tenant_id:
            logger.warning("HasActiveSubscription: No tenant_id")
            return False

        subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
        if not subscription_details or not subscription_details.get("access"):
            logger.warning(
                f"HasActiveSubscription: Access denied or subscription unavailable for tenant_id={tenant_id}")
            return False

        try:
            if view.basename == 'role' and view.action in ['create', 'update', 'partial_update']:
                role_name = request.data.get('name')
                industry = request.data.get('industry', 'Other')
                subscription_tier = request.user.tenant.subscription.plan.tier_level if request.user.tenant.subscription else 'tier1'
                if role_name:
                    can_assign, message = BillingService.can_assign_role(
                        tenant_id, role_name, industry, subscription_tier, request
                    )
                    logger.info(f"Role assignment check: can_assign={can_assign}, message={message}")
                    return can_assign


            logger.info(f"HasActiveSubscription: Access granted for view={view.basename}, action={view.action}")
            return True
        except requests.RequestException as e:
            logger.error(f"HasActiveSubscription: Request failed for tenant_id={tenant_id}: {str(e)}")
            return False
