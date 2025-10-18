from django.contrib.auth import get_user_model
import random
import datetime
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import AuthenticationFailed
from .serializers import (
    ResendOtpPasswordSerializer, VerifyOtpPasswordSerializer, SetNewPasswordSerializer,
    PasswordChangeSerializer, VerifyPasswordChangeSerializer, RequestForgotPasswordSerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import swagger_helper
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models_auth import PasswordChangeRequest, ForgotPasswordRequest
from django.conf import settings
from .permissions import IsCEO, IsCEOorManagerOrGeneralManagerOrBranchManager

User = get_user_model()


class ForgotPasswordViewSet(viewsets.ModelViewSet):
    queryset = ForgotPasswordRequest.objects.all()
    permission_classes = [IsCEO]

    def get_serializer_class(self):
        if self.action == 'request_forgot_password':
            return RequestForgotPasswordSerializer
        if self.action == 'resend_otp':
            return ResendOtpPasswordSerializer
        if self.action == 'verify_otp':
            return VerifyOtpPasswordSerializer
        if self.action == 'set_new_password':
            return SetNewPasswordSerializer

    @swagger_helper("ForgotPassword", "Request a password reset")
    @action(detail=False, methods=['post'], url_path='request-forgot-password')
    def request_forgot_password(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"data": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_400_BAD_REQUEST)

        frontend_base_route = settings.FRONTEND_PATH
        reset_url = f"{frontend_base_route}/change-password/?email={email}"
        ForgotPasswordRequest.objects.filter(user=user).delete()
        ForgotPasswordRequest.objects.create(user=user)

        # if not is_celery_healthy():
        #     send_email_synchronously(
        #         user_email=email,
        #         email_type="reset_link",
        #         subject="Password Reset Request",
        #         action="Password Reset",
        #         message="You have requested to reset your password. Click the link below to proceed. This link will expire in 10 minutes. If you did not make this request, please contact support immediately.",
        #         link=reset_url,
        #         link_text="Reset Password"
        #     )
        # else:
        #     send_generic_email_task.apply_async(
        #         kwargs={
        #             'user_email': email,
        #             'email_type': "reset_link",
        #             'subject': "Password Reset Request",
        #             'action': "Password Reset",
        #             'message': "You have requested to reset your password. Click the link below to proceed. This link will expire in 10 minutes. If you did not make this request, please contact support immediately.",
        #             'link': reset_url,
        #             'link_text': "Reset Password"
        #         }
        #     )

        return Response({"data": "A password reset link has been sent to your email."}, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Set a new password")
    @action(detail=False, methods=['post'], url_path='set-new-password')
    def set_new_password(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not email or not new_password or not confirm_password:
            return Response({"data": "Email, new_password, and confirm_password are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 8:
            return Response({"data": "Password must be at least 8 characters long."},
                            status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({"data": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_400_BAD_REQUEST)

        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        expiration_time = forgot_password_request.created_at + datetime.timedelta(minutes=10)
        if timezone.now() > expiration_time:
            return Response({"data": "The reset link has expired. Please request a new one."},
                            status=status.HTTP_400_BAD_REQUEST)

        ForgotPasswordRequest.objects.filter(user=user).delete()
        otp = random.randint(100000, 999999)

        # if not is_celery_healthy():
        #     send_email_synchronously(
        #         user_email=email,
        #         email_type="otp",
        #         subject="Forgot Password OTP",
        #         action="Password Reset",
        #         message="Use the OTP below to reset your password.",
        #         otp=otp
        #     )
        # else:
        #     send_generic_email_task.apply_async(
        #         kwargs={
        #             'user_email': email,
        #             'email_type': "otp",
        #             'subject': "Forgot Password OTP",
        #             'action': "Password Reset",
        #             'message': "Use the OTP below to reset your password.",
        #             'otp': otp
        #         }
        #     )
        hashed_new_password = make_password(new_password)
        ForgotPasswordRequest.objects.create(user=user, otp=otp, new_password=hashed_new_password)

        return Response({"data": "An OTP has been sent to your email."}, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Verify OTP for password reset")
    @action(detail=False, methods=['post'], url_path='verify-otp')
    def verify_otp(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({"data": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_ceo_role():
            return Response({"data": "Only CEOs can verify OTP for password reset."}, status=status.HTTP_403_FORBIDDEN)

        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)

        if str(forgot_password_request.otp) != str(otp):
            return Response({"data": "Incorrect OTP."}, status=status.HTTP_400_BAD_REQUEST)

        otp_age = (timezone.now() - forgot_password_request.created_at).total_seconds()
        if otp_age > 300:
            return Response({"data": "OTP has expired. Please request a new one."},
                            status=status.HTTP_400_BAD_REQUEST)

        user.password = forgot_password_request.new_password
        if not user.is_verified:
            user.is_verified = True
        user.save()

        forgot_password_request.delete()

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # if not is_celery_healthy():
        #     send_email_synchronously(
        #         user_email=user.email,
        #         email_type="confirmation",
        #         subject="Password Reset Successful",
        #         action="Password Reset",
        #         message="Your password has been successfully reset. You are now securely logged into your account. If you did not authorize this change, please contact support immediately."
        #     )
        # else:
        #     send_generic_email_task.apply_async(
        #         kwargs={
        #             'user_email': user.email,
        #             'email_type': "confirmation",
        #             'subject': "Password Reset Successful",
        #             'action': "Password Reset",
        #             'message': "Your password has been successfully reset. You are now securely logged into your account. If you did not authorize this change, please contact support immediately."
        #         }
        #     )

        return Response({
            'message': 'Password reset successful.',
            'access_token': access_token,
            'refresh_token': str(refresh)
        }, status=status.HTTP_201_CREATED)

    @swagger_helper("ForgotPassword", "Resend OTP for password reset")
    @action(detail=False, methods=['post'], url_path='resend-otp')
    def resend_otp(self, request):
        email = request.data.get('email')

        if not email:
            return Response({"data": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_ceo_role():
            return Response({"data": "Only CEOs can resend OTP for password reset."}, status=status.HTTP_403_FORBIDDEN)

        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)

        otp = random.randint(100000, 999999)
        forgot_password_request.otp = otp
        forgot_password_request.created_at = timezone.now()
        forgot_password_request.save()

        # if not is_celery_healthy():
        #     send_email_synchronously(
        #         user_email=email,
        #         email_type="otp",
        #         subject="Forgot Password OTP - Resent",
        #         action="Password Reset",
        #         message="Use the OTP below to reset your password.",
        #         otp=otp
        #     )
        # else:
        #     send_generic_email_task.apply_async(
        #         kwargs={
        #             'user_email': email,
        #             'email_type': "otp",
        #             'subject': "Forgot Password OTP - Resent",
        #             'action': "Password Reset",
        #             'message': "Use the OTP below to reset your password.",
        #             'otp': otp
        #         }
        #     )
        # return Response({"data": "A new OTP has been sent to your email and the expiration time has been extended."},
        #                 status=status.HTTP_200_OK)


class PasswordChangeRequestViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsCEOorManagerOrGeneralManagerOrBranchManager]
    queryset = PasswordChangeRequest.objects.all()

    def get_serializer_class(self):
        if self.action == 'request_password_change':
            return PasswordChangeSerializer
        if self.action == 'verify_password_change':
            return VerifyPasswordChangeSerializer

    @swagger_helper("ChangePassword", "Request password change")
    @action(detail=False, methods=['post'], url_path='request-password-change')
    def request_password_change(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not old_password:
            return Response({"data": "Old password is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(old_password):
            return Response({"data": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if old_password == new_password:
            return Response({"data": "New password cannot be the same as the old password."},
                            status=status.HTTP_400_BAD_REQUEST)

        if not new_password or not confirm_password:
            return Response({"data": "Both new_password and confirm_password are required."},
                            status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({"data": "Passwords do not match."},
                            status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 8:
            return Response({"data": "Password must be at least 8 characters long."},
                            status=status.HTTP_400_BAD_REQUEST)

        PasswordChangeRequest.objects.filter(user=user).delete()
        otp = random.randint(100000, 999999)
        hashed_new_password = make_password(new_password)

        # if not is_celery_healthy():
        #     send_email_synchronously(
        #         user_email=user.email,
        #         email_type="otp",
        #         subject="Password Change OTP",
        #         action="Password Change",
        #         message="You have requested to change your password. Use the OTP below to proceed. If you did not make this request, please contact support immediately.",
        #         otp=otp
        #     )
        # else:
        #     send_generic_email_task.apply_async(
        #         kwargs={
        #             'user_email': user.email,
        #             'email_type': "otp",
        #             'subject': "Password Change OTP",
        #             'action': "Password Change",
        #             'message': "You have requested to change your password. Use the OTP below to proceed. If you did not make this request, please contact support immediately.",
        #             'otp': otp
        #         }
        #     )

        PasswordChangeRequest.objects.create(user=user, otp=otp, new_password=hashed_new_password)

        return Response({"data": "An OTP has been sent to your email."}, status=status.HTTP_200_OK)

    @swagger_helper("ChangePassword", "Resend OTP")
    @action(detail=False, methods=['post'], url_path='resend-otp')
    def resend_otp(self, request):
        user = request.user
        password_change_request = PasswordChangeRequest.objects.filter(user=user).first()

        if not password_change_request:
            return Response({"data": "No pending password change request found."}, status=status.HTTP_400_BAD_REQUEST)

        otp = random.randint(100000, 999999)
        password_change_request.otp = otp
        password_change_request.created_at = timezone.now()
        password_change_request.save()

        # if not is_celery_healthy():
        #     send_email_synchronously(
        #         user_email=user.email,
        #         email_type="otp",
        #         subject="Password Change OTP - Resent",
        #         action="Password Change",
        #         message="Use the OTP below to change your password.",
        #         otp=otp
        #     )
        # else:
        #     send_generic_email_task.apply_async(
        #         kwargs={
        #             'user_email': user.email,
        #             'email_type': "otp",
        #             'subject': "Password Change OTP - Resent",
        #             'action': "Password Change",
        #             'message': "Use the OTP below to change your password.",
        #             'otp': otp
        #         }
        #     )
        return Response({"data": "A new OTP has been sent to your email."}, status=status.HTTP_200_OK)

    @swagger_helper("ChangePassword", "Verify password change")
    @action(detail=False, methods=['post'], url_path='verify-password-change')
    def verify_password_change(self, request):
        otp = request.data.get('otp')

        if not otp:
            return Response({"data": "OTP is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        password_change_request = PasswordChangeRequest.objects.filter(user=user).first()

        if not password_change_request:
            return Response({"data": "No pending password change request found."}, status=status.HTTP_400_BAD_REQUEST)

        if str(password_change_request.otp) != str(otp):
            return Response({"data": "Incorrect OTP."}, status=status.HTTP_400_BAD_REQUEST)

        otp_age = (timezone.now() - password_change_request.created_at).total_seconds()
        if otp_age > 300:
            return Response({"data": "OTP has expired. Please request a new one."},
                            status=status.HTTP_400_BAD_REQUEST)

        user.password = password_change_request.new_password
        user.save()

        password_change_request.delete()

        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                raise AuthenticationFailed('Refresh token is invalid or expired.')

        # if not is_celery_healthy():
        #     send_email_synchronously(
        #         user_email=user.email,
        #         email_type="confirmation",
        #         subject="Password Changed Successfully",
        #         action="Password Change",
        #         message="Your password has been successfully changed. If you did not authorize this change, please contact support immediately."
        #     )
        # else:
        #     send_generic_email_task.apply_async(
        #         kwargs={
        #             'user_email': user.email,
        #             'email_type': "confirmation",
        #             'subject': "Password Changed Successfully",
        #             'action': "Password Change",
        #             'message': "Your password has been successfully changed. If you did not authorize this change, please contact support immediately."
        #         }
        #     )

        return Response({"data": "Password changed successfully. You have been logged out."})