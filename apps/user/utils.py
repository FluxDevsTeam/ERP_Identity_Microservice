import hashlib
import hmac
import json
import time
from drf_yasg.utils import swagger_auto_schema
from django.conf import settings
import requests


def swagger_helper(tags, model, description=None):
    def decorators(func):
        descriptions = {
            "list": f"Retrieve a list of {model}",
            "retrieve": f"Retrieve details of a specific {model}",
            "create": f"Create a new {model}",
            "partial_update": f"Update a {model}",
            "destroy": f"Delete a {model}",
        }

        action_type = func.__name__
        if not description:
            get_description = descriptions.get(action_type, f"{action_type} {model}")
            return swagger_auto_schema(operation_id=f"{action_type} {model}", operation_description=get_description, tags=[tags])(func)
        return swagger_auto_schema(operation_id=f"{action_type} {model}", operation_description=description, tags=[tags])(func)

    return decorators

def send_email_to_erp_support(user_email, email_type, subject, action, message, otp=None, link=None, link_text=None):
    """
    Send an email request to the ERP Support Microservice with HMAC authentication.
    """
    timestamp = str(int(time.time()))
    data = {
        'user_email': user_email,
        'email_type': email_type,
        'subject': subject,
        'action': action,
        'message': message,
        'otp': otp,
        'link': link,
        'link_text': link_text
    }
    # Ensure consistent JSON serialization for HMAC
    payload = json.dumps(data, sort_keys=True, separators=(',', ':'))
    signature = hmac.new(
        settings.ERP_SUPPORT_MICROSERVICE_SECRET.encode('utf-8'),
        f"{timestamp}:{payload}".encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    headers = {
        'X-Timestamp': timestamp,
        'X-Signature': signature,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(
            f"{settings.ERP_SUPPORT_MICROSERVICE_URL}/api/v1/send-email/",
            json=data,
            headers=headers
        )
        response.raise_for_status()
        return response.json(), response.status_code
    except requests.RequestException as e:
        return {'error': str(e)}, 500
