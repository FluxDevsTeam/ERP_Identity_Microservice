import logging
import requests
from django.conf import settings
from django.core.cache import cache
from .models import ROLES_BY_INDUSTRY, Permission

logger = logging.getLogger(__name__)


class BillingService:
    @staticmethod
    def fetch_subscription_details(tenant_id, request=None):
        cache_key = f"subscription_details_{tenant_id}"
        cached_details = cache.get(cache_key)
        if cached_details is not None:
            logger.info(f"Returning cached subscription details for tenant_id={tenant_id}")
            return cached_details

        url = f"{settings.BILLING_MICROSERVICE_URL}/api/v1/billing/access-check/"
        headers = {}
        if request and request.META.get('HTTP_AUTHORIZATION'):
            headers["Authorization"] = request.META.get('HTTP_AUTHORIZATION')

        try:
            logger.info(f"Fetching subscription details for tenant_id={tenant_id}")
            response = requests.get(url, params={"tenant_id": tenant_id}, headers=headers)
            response.raise_for_status()
            details = response.json()
            cache.set(cache_key, details, timeout=300)  # Cache for 5 minutes
            logger.info(f"Subscription details fetched and cached for tenant_id={tenant_id}")
            return details
        except requests.RequestException as e:
            logger.error(f"Error fetching subscription details for tenant_id={tenant_id}: {str(e)}")
            return None

    @staticmethod
    def can_create_user(tenant_id, current_user_count, request=None):
        subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
        if not subscription_details or not subscription_details.get("access"):
            logger.warning(f"Access denied or subscription details unavailable for tenant_id={tenant_id}")
            return False, "Access denied or subscription details unavailable."

        max_users = subscription_details["plan"].get("max_users", 0)
        if current_user_count >= max_users:
            logger.warning(
                f"User creation limit reached for tenant_id={tenant_id}, current_user_count={current_user_count}, max_users={max_users}"
            )
            return False, "User creation limit reached for the current subscription plan."

        logger.info(
            f"User can be created for tenant_id={tenant_id}, current_user_count={current_user_count}, max_users={max_users}"
        )
        return True, "User can be created."

    @staticmethod
    def can_assign_role(tenant_id, role_name, industry, subscription_tier, request=None):
        subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
        if not subscription_details or not subscription_details.get("access"):
            logger.warning(f"Access denied or subscription details unavailable for tenant_id={tenant_id}")
            return False, "Access denied or subscription details unavailable."

        plan_industry = subscription_details["plan"].get("industry", "Other")
        plan_tier = subscription_details["plan"].get("tier_level", "tier1")
        role_config = ROLES_BY_INDUSTRY.get(plan_industry, {}).get(role_name) or \
                      ROLES_BY_INDUSTRY.get("Other", {}).get(role_name)

        if not role_config:
            logger.warning(f"Role {role_name} not available for industry {plan_industry}")
            return False, f"Role '{role_name}' is not available for industry '{plan_industry}'."

        required_tier = role_config.get("tier_req", "tier1")
        if plan_tier != subscription_tier or subscription_tier not in [required_tier, "tier2", "tier3", "tier4"]:
            logger.warning(f"Role {role_name} requires tier {required_tier}, but tenant has {subscription_tier}")
            return False, f"Role '{role_name}' requires a higher subscription tier ({required_tier})."

        if industry != plan_industry and industry != "Other":
            logger.warning(f"Role {role_name} industry {industry} does not match plan industry {plan_industry}")
            return False, f"Role '{role_name}' industry '{industry}' does not match subscription industry '{plan_industry}'."

        logger.info(
            f"Role {role_name} can be assigned for tenant_id={tenant_id}, industry={industry}, tier={subscription_tier}"
        )
        return True, "Role can be assigned."

    @staticmethod
    def can_assign_permission(tenant_id, permission_codename, request=None):
        subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
        if not subscription_details or not subscription_details.get("access"):
            logger.warning(f"Access denied or subscription details unavailable for tenant_id={tenant_id}")
            return False, "Access denied or subscription details unavailable."

        plan_industry = subscription_details["plan"].get("industry", "Other")
        try:
            permission = Permission.objects.get(codename=permission_codename)
            if permission.industry != plan_industry and plan_industry != "Other":
                logger.warning(
                    f"Permission {permission_codename} industry {permission.industry} does not match plan industry {plan_industry}"
                )
                return False, f"Permission '{permission_codename}' industry '{permission.industry}' does not match subscription industry '{plan_industry}'."
            return True, "Permission can be assigned."
        except Permission.DoesNotExist:
            logger.warning(f"Permission {permission_codename} not found")
            return False, f"Permission '{permission_codename}' does not exist."
