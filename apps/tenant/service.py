import logging
import requests
from django.conf import settings
from .models import Branch, Tenant

# Configure logger
logger = logging.getLogger(__name__)

class BillingService:
    @staticmethod
    def fetch_subscription_details(tenant_id, request=None):
        """
        Fetch subscription details from the billing microservice, passing the JWT token if provided.
        """
        url = f"{settings.BILLING_MICROSERVICE_URL}/api/v1/billing/access-check/"
        headers = {}
        if request and request.META.get('HTTP_AUTHORIZATION'):
            headers["Authorization"] = request.META.get('HTTP_AUTHORIZATION')
        
        try:
            logger.info(f"Fetching subscription details for tenant_id={tenant_id}, url={url}")
            response = requests.get(url, params={"tenant_id": tenant_id}, headers=headers)
            response.raise_for_status()  # Raise an exception for bad status codes
            logger.info(f"Subscription details fetched successfully for tenant_id={tenant_id}")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error fetching subscription details for tenant_id={tenant_id}: {str(e)}")
            return None

    @staticmethod
    def can_create_user(tenant_id, current_user_count, request=None):
        """
        Check if a new user can be created based on subscription limits.
        """
        subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
        if not subscription_details or not subscription_details.get("access"):
            logger.warning(f"Access denied or subscription details unavailable for tenant_id={tenant_id}")
            return False, "Access denied or subscription details unavailable."

        max_users = subscription_details["plan"].get("max_users", 0)
        if current_user_count >= max_users:
            logger.warning(f"User creation limit reached for tenant_id={tenant_id}, current_user_count={current_user_count}, max_users={max_users}")
            return False, "User creation limit reached for the current subscription plan."

        logger.info(f"User can be created for tenant_id={tenant_id}, current_user_count={current_user_count}, max_users={max_users}")
        return True, "User can be created."

    @staticmethod
    def can_create_branch(tenant_id, request=None):
        """
        Check if a new branch can be created based on subscription limits and current branch count.
        """
        subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
        if not subscription_details or not subscription_details.get("access"):
            logger.warning(f"Access denied or subscription details unavailable for tenant_id={tenant_id}")
            return False, "Access denied or subscription details unavailable."

        max_branches = subscription_details["plan"].get("max_branches", 0)
        try:
            tenant = Tenant.objects.get(id=tenant_id)
            current_branch_count = Branch.objects.filter(tenant=tenant).count()
        except Tenant.DoesNotExist:
            logger.error(f"Tenant not found for tenant_id={tenant_id}")
            return False, "Tenant not found."

        if current_branch_count >= max_branches:
            logger.warning(f"Branch creation limit reached for tenant_id={tenant_id}, current_branch_count={current_branch_count}, max_branches={max_branches}")
            return False, "Branch creation limit reached for the current subscription plan."

        logger.info(f"Branch can be created for tenant_id={tenant_id}, current_branch_count={current_branch_count}, max_branches={max_branches}")
        return True, "Branch can be created."