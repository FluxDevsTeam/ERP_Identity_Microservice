import logging
import requests
from django.conf import settings
from datetime import datetime, timedelta
import jwt

logger = logging.getLogger(__name__)


class BillingService:
    @staticmethod
    def fetch_subscription_details(tenant_id, request=None):
        url = f"{settings.BILLING_MICROSERVICE_URL}/api/v1/billing/access-check/"
        headers = {}
        if request and request.META.get('HTTP_AUTHORIZATION'):
            headers["Authorization"] = request.META.get('HTTP_AUTHORIZATION')

        try:
            logger.info(f"Fetching subscription details for tenant_id={tenant_id}, url={url}")
            response = requests.get(url, params={"tenant_id": tenant_id}, headers=headers)
            response.raise_for_status()
            logger.info(f"Subscription details fetched successfully for tenant_id={tenant_id}")
            return response.json()
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
                f"User creation limit reached for tenant_id={tenant_id}, current_user_count={current_user_count}, max_users={max_users}")
            return False, "User creation limit reached for the current subscription plan."

        logger.info(
            f"User can be created for tenant_id={tenant_id}, current_user_count={current_user_count}, max_users={max_users}")
        return True, "User can be created."

    @staticmethod
    def can_create_branch(tenant_id, current_branch_count, request=None):
        subscription_details = BillingService.fetch_subscription_details(tenant_id, request)
        if not subscription_details or not subscription_details.get("access"):
            logger.warning(f"Access denied or subscription details unavailable for tenant_id={tenant_id}")
            return False, "Access denied or subscription details unavailable."

        max_branches = subscription_details["plan"].get("max_branches", 0)
        from apps.tenant.models import Branch, Tenant
        try:
            tenant = Tenant.objects.get(id=tenant_id)
            current_branch_count = Branch.objects.filter(tenant=tenant).count()
        except Tenant.DoesNotExist:
            logger.error(f"Tenant not found for tenant_id={tenant_id}")
            return False, "Tenant not found."

        if current_branch_count >= max_branches:
            logger.warning(
                f"Branch creation limit reached for tenant_id={tenant_id}, current_branch_count={current_branch_count}, max_branches={max_branches}")
            return False, "Branch creation limit reached for the current subscription plan."

        logger.info(
            f"Branch can be created for tenant_id={tenant_id}, current_branch_count={current_branch_count}, max_branches={max_branches}")
        return True, "Branch can be created."


def generate_microservice_token(service_name="identity-ms", expires_in=300):
    payload = {
        'type': 'microservice',
        'service': service_name,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=expires_in)
    }
    token = jwt.encode(payload, settings.SUPPORT_JWT_SECRET_KEY, algorithm='HS256')
    return token


def send_email_via_service(email_data):
    token = generate_microservice_token()
    headers = {
        'Support-Microservice-Auth': token,
        'Content-Type': 'application/json'
    }
    support_service_url = settings.SUPPORT_MICROSERVICE_URL
    email_service_url = f"{support_service_url}/api/v1/email-service/send-email/"

    logger.info(f"Sending email to {email_data['user_email']} via email service at {email_service_url}")
    try:
        response = requests.post(
            email_service_url,
            json=email_data,
            headers=headers,
            timeout=30
        )
        logger.info(f"Email service response status: {response.status_code}, body: {response.text}")
        if response.status_code == 200:
            logger.info("Email queued successfully")
            return response.json()
        else:
            logger.error(f"Email service error: {response.text}")
            return {
                'error': 'Failed to send email',
                'status_code': response.status_code,
                'details': response.text
            }
    except requests.RequestException as e:
        logger.error(f"Request to email service failed: {str(e)}")
        return {
            'error': 'Connection to email service failed',
            'details': str(e)
        }
