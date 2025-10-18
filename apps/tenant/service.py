import requests
from django.conf import settings


class BillingService:
    @staticmethod
    def fetch_subscription_details(tenant_id):
        url = f"{settings.BILLING_MICROSERVICE_URL}/api/v1/billing/access-check/"
        response = requests.get(url, params={"tenant_id": tenant_id})

        if response.status_code == 200:
            return response.json()
        else:
            return None

    @staticmethod
    def can_create_user(tenant_id, current_user_count):
        subscription_details = BillingService.fetch_subscription_details(tenant_id)
        if not subscription_details or not subscription_details.get("access"):
            return False, "Access denied or subscription details unavailable."

        max_users = subscription_details["plan"].get("max_users", 0)
        if current_user_count >= max_users:
            return False, "User creation limit reached for the current subscription plan."

        return True, "User can be created."

    @staticmethod
    def can_create_branch(tenant_id, current_branch_count):
        subscription_details = BillingService.fetch_subscription_details(tenant_id)
        if not subscription_details or not subscription_details.get("access"):
            return False, "Access denied or subscription details unavailable."

        max_branches = subscription_details["plan"].get("max_branches", 0)
        if current_branch_count >= max_branches:
            return False, "Branch creation limit reached for the current subscription plan."

        return True, "Branch can be created."