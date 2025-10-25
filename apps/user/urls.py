from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ForgotPasswordViewSet
from .views_auth import UserSignupViewSet, UserLoginViewSet, GoogleAuthViewSet, LogoutViewSet, UsernameAvailabilityView
from .views_user_management import UserManagementViewSet, TempUserViewSet

# Router for ViewSets (auto-generates endpoints for list, create, retrieve, update, destroy, and custom actions)
router = DefaultRouter()
router.register('management', UserManagementViewSet, basename='management')  # UserManagementViewSet

urlpatterns = [
    # Non-viewset manual paths (unchanged)
    # UserSignupViewSet
    path('signup/', UserSignupViewSet.as_view({'post': 'create'}), name='user_signup'),
    path('signup/verify-otp/', UserSignupViewSet.as_view({'post': 'verify'}), name='user_signup_verify_otp'),
    path('signup/resend-otp/', UserSignupViewSet.as_view({'post': 'resend_otp'}), name='user_signup_resend_otp'),

    # UserLoginViewSet
    path('login/', UserLoginViewSet.as_view({'post': 'create'}), name='login'),
    path('login/refresh-token/', UserLoginViewSet.as_view({'post': 'refresh_token'}), name='refresh_token'),

    # LogoutViewSet
    path('logout/', LogoutViewSet.as_view({'post': 'logout'}), name='logout'),

    # ForgotPasswordViewSet
    path('forgot-password/request-forgot-password/', ForgotPasswordViewSet.as_view({'post': 'request_forgot_password'}), name='forgot_password_request'),
    path('forgot-password/set-new-password/', ForgotPasswordViewSet.as_view({'post': 'set_new_password'}), name='forgot_password_set_new_password'),
    path('forgot-password/verify-otp/', ForgotPasswordViewSet.as_view({'post': 'verify_otp'}), name='forgot_password_verify_otp'),
    path('forgot-password/resend-otp/', ForgotPasswordViewSet.as_view({'post': 'resend_otp'}), name='forgot_password_resend_otp'),

    path('temp-user/management/', TempUserViewSet.as_view({'get': 'list'}), name='list_temp_users'),
    path('temp-user/management/<uuid:pk>/', TempUserViewSet.as_view({'get': 'retrieve', 'delete': 'destroy'}), name='temp_user_detail'),


    # GoogleAuthViewSet
    path('google-auth/', GoogleAuthViewSet.as_view({'post': 'google_auth'}), name='google_auth'),

    # UsernameAvailabilityView
    path('check-username/', UsernameAvailabilityView.as_view({'post': 'create'}), name='check_username'),

    # ViewSets via router (auto-handles UserManagementViewSet and TempUserViewSet)
    path('api/v1/', include(router.urls)),  # Mount at /api/v1/ for consistency
]