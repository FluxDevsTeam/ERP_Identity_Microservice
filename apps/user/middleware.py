import requests
from django.conf import settings
from django.http import JsonResponse

class SubscriptionCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        allowed_paths = [
            '/google-auth/google-auth/',
            '/login/',
            '/signup/',
            '/signup/verify-otp/',
            '/signup/resend-otp/',
            '/forgot-password/request-forgot-password/',
            '/forgot-password/verify-otp/',
            '/forgot-password/set-new-password/',
            '/forgot-password/resend-otp/',
            '/profile/request-email-change/',
            '/profile/resend-email-change-otp/',
            '/profile/verify-email-change/',
            '/profile/request-profile-change/',
            '/profile/verify-profile-change/',
            '/password/request-password-change/',
            '/password/resend-otp/',
            '/password/verify-password-change/',
            '/refresh-token/',
            '/logout/',
        ]
        if request.path in allowed_paths:
            return self.get_response(request)

        # For authenticated users, check subscription status
        if request.user.is_authenticated and not request.user.is_superuser:
            tenant_id = request.user.tenant.id if request.user.tenant else None
            if tenant_id:
                try:
                    response = requests.get(
                        f"{settings.BILLING_MICROSERVICE_URL}/access-check/",
                        headers={"Authorization": request.META.get('HTTP_AUTHORIZATION')}
                    )
                    if response.status_code != 200 or not response.json().get('access'):
                        return JsonResponse(
                            {"message": "Access denied due to inactive or missing subscription."},
                            status=403
                        )
                except requests.RequestException:
                    return JsonResponse(
                        {"message": "Unable to verify subscription status."},
                        status=503
                    )
            else:
                # Users without a tenant have limited access (freemium)
                if request.path not in ['/profile/', '/logout/']:
                    return JsonResponse(
                        {"message": "Access denied: User not associated with a tenant."},
                        status=403
                    )
        return self.get_response(request)