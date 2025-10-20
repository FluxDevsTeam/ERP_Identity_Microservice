import jwt
import requests
from datetime import datetime, timedelta
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
        """
        Check if a new branch can be created based on the subscription plan.
        """
        subscription_details = BillingService.fetch_subscription_details(tenant_id)
        if not subscription_details or not subscription_details.get("access"):
            return False, "Access denied or subscription details unavailable."

        max_branches = subscription_details["plan"].get("max_branches", 0)
        if current_branch_count >= max_branches:
            return False, "Branch creation limit reached for the current subscription plan."

        return True, "Branch can be created."


def generate_microservice_token(service_name="identity-ms", expires_in=300):
    """
    Generate a JWT token for microservice authentication.

    Args:
        service_name (str): Name of the requesting microservice
        expires_in (int): Token expiration in seconds (default: 5 minutes)

    Returns:
        str: JWT token
    """
    payload = {
        'type': 'microservice',
        'service': service_name,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=expires_in)
    }

    token = jwt.encode(payload, settings.SUPPORT_JWT_SECRET_KEY, algorithm='HS256')
    return token


def send_email_via_service(email_data):
    """
    Send email through the email microservice.

    Args:
        email_data (dict): Email data including:
            - user_email (str): Recipient email (REQUIRED)
            - email_type (str): Type of email - must be one of: 'otp', 'confirmation', 'reset_link', 'general'
            - subject (str): Email subject (optional)
            - action (str): Action description (optional)
            - message (str): Email body (optional)
            - otp (str, optional): OTP code
            - link (str, optional): Action link
            - link_text (str, optional): Link display text

    Returns:
        dict: Response from email service
    """
    # Generate JWT token for microservice authentication
    token = generate_microservice_token()

    headers = {
        'Support-Microservice-Auth': token,
        'Content-Type': 'application/json'
    }
    support_service_url = settings.SUPPORT_MICROSERVICE_URL
    # Email service endpoint
    email_service_url = f"{support_service_url}/api/v1/email-service/send-email/"

    print(f"Sending email to {email_data['user_email']} via email service")
    print(f"Using URL: {email_service_url}")

    try:
        response = requests.post(
            email_service_url,
            json=email_data,
            headers=headers,
            timeout=30  # 30 seconds timeout
        )

        print(f"Email service response status: {response.status_code}")
        print(f"Email service response body: {response.text}")

        if response.status_code == 200:
            print("Email queued successfully")
            return response.json()
        else:
            print(f"Email service error: {response.text}")
            return {
                'error': 'Failed to send email',
                'status_code': response.status_code,
                'details': response.text
            }

    except requests.exceptions.RequestException as e:
        print(f"Request to email service failed: {str(e)}")
        return {
            'error': 'Connection to email service failed',
            'details': str(e)
        }
