from django.urls import path
from .views import (
    UserSignupViewSet,
    UserLoginViewSet,
    LogoutViewSet,
    UserProfileViewSet,
    ForgotPasswordViewSet,
    PasswordChangeRequestViewSet,
    GoogleAuthViewSet,
    UserManagementViewSet
)

urlpatterns = [
    # UserSignupViewSet
    path('signup/', UserSignupViewSet.as_view({'post': 'create'}), name='user_signup'),
    path('signup/verify-otp/', UserSignupViewSet.as_view({'post': 'verify'}), name='verify_otp'),
    path('signup/resend-otp/', UserSignupViewSet.as_view({'post': 'resend_otp'}), name='resend_otp'),

    # UserLoginViewSet
    path('login/', UserLoginViewSet.as_view({'post': 'create'}), name='login'),
    path('login/refresh-token/', UserLoginViewSet.as_view({'post': 'refresh_token'}), name='refresh_token'),

    # LogoutViewSet
    path('logout/', LogoutViewSet.as_view({'post': 'logout'}), name='logout'),

    # UserProfileViewSet
    path('profile/', UserProfileViewSet.as_view({'get': 'retrieve'}), name='user_profile'),
    path('profile/request-email-change/', UserProfileViewSet.as_view({'post': 'request_email_change'}), name='request_email_change'),
    path('profile/resend-email-change-otp/', UserProfileViewSet.as_view({'post': 'resend_email_change_otp'}), name='resend_email_change_otp'),
    path('profile/verify-email-change/', UserProfileViewSet.as_view({'post': 'verify_email_change'}), name='verify_email_change'),
    path('profile/request-profile-change/', UserProfileViewSet.as_view({'post': 'request_profile_change'}), name='request_profile_change'),
    path('profile/verify-profile-change/', UserProfileViewSet.as_view({'post': 'verify_profile_change'}), name='verify_profile_change'),
    path('profile/delete-account/', UserProfileViewSet.as_view({'post': 'delete_account'}), name='delete_account'),

    # ForgotPasswordViewSet
    path('forgot-password/request-forgot-password/', ForgotPasswordViewSet.as_view({'post': 'request_forgot_password'}), name='request_forgot_password'),
    path('forgot-password/set-new-password/', ForgotPasswordViewSet.as_view({'post': 'set_new_password'}), name='set_new_password'),
    path('forgot-password/verify-otp/', ForgotPasswordViewSet.as_view({'post': 'verify_otp'}), name='verify_otp'),
    path('forgot-password/resend-otp/', ForgotPasswordViewSet.as_view({'post': 'resend_otp'}), name='resend_otp'),

    # PasswordChangeRequestViewSet
    path('password-change/request-password-change/', PasswordChangeRequestViewSet.as_view({'post': 'request_password_change'}), name='request_password_change'),
    path('password-change/resend-otp/', PasswordChangeRequestViewSet.as_view({'post': 'resend_otp'}), name='resend_otp'),
    path('password-change/verify-password-change/', PasswordChangeRequestViewSet.as_view({'post': 'verify_password_change'}), name='verify_password_change'),

    # GoogleAuthViewSet
    path('google-auth/google-auth/', GoogleAuthViewSet.as_view({'post': 'google_auth'}), name='google_auth'),
    path('google-auth/set-google-auth-password/', GoogleAuthViewSet.as_view({'post': 'set_google_auth_password'}), name='set_google_auth'),

    # UserManagementViewSet
    path('users/', UserManagementViewSet.as_view({'get': 'list', 'post': 'create'}), name='user_management_list_create'),
    path('users/<int:pk>/', UserManagementViewSet.as_view({'get': 'retrieve', 'patch': 'partial_update', 'delete': 'destroy'}), name='user_management_detail'),
]