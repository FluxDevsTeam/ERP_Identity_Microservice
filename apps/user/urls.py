from django.urls import path
from .views import ForgotPasswordViewSet, PasswordChangeRequestViewSet
from .views_auth import UserSignupViewSet, UserLoginViewSet, GoogleAuthViewSet, LogoutViewSet
from .views_user_management import UserManagementViewSet

urlpatterns = [
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

    # PasswordChangeRequestViewSet
    path('password-change/request-password-change/', PasswordChangeRequestViewSet.as_view({'post': 'request_password_change'}), name='password_change_request'),
    path('password-change/resend-otp/', PasswordChangeRequestViewSet.as_view({'post': 'resend_otp'}), name='password_change_resend_otp'),
    path('password-change/verify-password-change/', PasswordChangeRequestViewSet.as_view({'post': 'verify_password_change'}), name='password_change_verify_otp'),

    # GoogleAuthViewSet
    path('google-auth/', GoogleAuthViewSet.as_view({'post': 'google_auth'}), name='google_auth'),

    # UserManagementViewSet
    path('management/', UserManagementViewSet.as_view({'get': 'list', 'post': 'create'}), name='user_management_list_create'),
    path('management/<str:pk>/', UserManagementViewSet.as_view({'get': 'retrieve', 'patch': 'partial_update', 'delete': 'destroy'}), name='user_management_detail'),
]