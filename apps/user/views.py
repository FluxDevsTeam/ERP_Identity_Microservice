from django.contrib.auth import get_user_model
import random
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from django.contrib.auth.hashers import make_password, check_password
from .serializers import (
    ResendOtpPasswordSerializer, VerifyOtpPasswordSerializer, SetNewPasswordSerializer, RequestForgotPasswordSerializer
)
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import swagger_helper
from rest_framework.permissions import IsAuthenticated, OR
from rest_framework.response import Response
from .models_auth import ForgotPasswordRequest
from django.conf import settings
from .services import send_email_via_service

User = get_user_model()


class ForgotPasswordViewSet(viewsets.GenericViewSet):
    # No permission_classes to allow public access
    queryset = ForgotPasswordRequest.objects.all()

    def get_serializer_class(self):
        if self.action == 'request_forgot_password':
            return RequestForgotPasswordSerializer
        if self.action == 'verify_otp':
            return VerifyOtpPasswordSerializer
        if self.action == 'set_new_password':
            return SetNewPasswordSerializer
        if self.action == 'resend_otp':
            return ResendOtpPasswordSerializer
        return RequestForgotPasswordSerializer

    @swagger_helper("ForgotPassword", "Request an OTP to verify email for password reset.")
    @action(detail=False, methods=['post'], url_path='request-forgot-password')
    def request_forgot_password(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)

        # Check if user has no tenant, is a CEO, or is a superuser
        if user.tenant and not (user.is_ceo_role() or user.is_superuser):
            return Response({
                "data": "You cannot reset your password directly. Please contact your organization head to change your account details."
            }, status=status.HTTP_403_FORBIDDEN)

        # Delete any existing ForgotPasswordRequest
        ForgotPasswordRequest.objects.filter(user=user).delete()

        # Generate and store OTP
        otp = str(random.randint(100000, 999999))
        ForgotPasswordRequest.objects.create(
            user=user,
            otp=make_password(otp),
            created_at=timezone.now(),
            is_verified=False
        )

        # Send OTP email
        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Password Reset OTP',
            'action': 'Email Verification',
            'message': 'You have requested to reset your password. Use the OTP below to verify your email and proceed. If you did not make this request, please contact support immediately.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-otp/?email={email}",
            'link_text': 'Verify Email'
        })
        return Response({"data": "An OTP has been sent to your email for verification."}, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Verify OTP to confirm email for password reset.")
    @action(detail=False, methods=['post'], url_path='verify-otp')
    def verify_otp(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)

        # Check if user has no tenant, is a CEO, or is a superuser
        if user.tenant and not (user.is_ceo_role() or user.is_superuser):
            return Response({
                "data": "You cannot reset your password directly. Please contact your organization head to change your account details."
            }, status=status.HTTP_403_FORBIDDEN)

        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)

        if not check_password(otp, forgot_password_request.otp):
            return Response({"data": "Incorrect OTP."}, status=status.HTTP_400_BAD_REQUEST)

        if (timezone.now() - forgot_password_request.created_at).total_seconds() > 300:
            return Response({"data": "OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark OTP as verified
        forgot_password_request.is_verified = True
        forgot_password_request.save()

        return Response({
            "data": "OTP verified successfully. Please set your new password."
        }, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Set a new password after OTP verification.")
    @action(detail=False, methods=['post'], url_path='set-new-password')
    def set_new_password(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        new_password = serializer.validated_data['new_password']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)

        # Check if user has no tenant, is a CEO, or is a superuser
        if user.tenant and not (user.is_ceo_role() or user.is_superuser):
            return Response({
                "data": "You cannot reset your password directly. Please contact your organization head to change your account details."
            }, status=status.HTTP_403_FORBIDDEN)

        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)

        if not forgot_password_request.is_verified:
            return Response({"data": "OTP not verified. Please verify the OTP first."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Set new password
        user.set_password(new_password)
        if not user.is_verified:
            user.is_verified = True
        user.save()

        # Delete the ForgotPasswordRequest
        forgot_password_request.delete()

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Send confirmation email
        send_email_via_service({
            'user_email': user.email,
            'email_type': 'confirmation',
            'subject': 'Password Reset Successful',
            'action': 'Password Reset',
            'message': 'Your password has been successfully reset. You are now securely logged into your account. If you did not authorize this change, please contact support immediately.'
        })
        return Response({
            'message': 'Password reset successful.',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        }, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Resend OTP for email verification.")
    @action(detail=False, methods=['post'], url_path='resend-otp')
    def resend_otp(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)

        # Check if user has no tenant, is a CEO, or is a superuser
        if user.tenant and not (user.is_ceo_role() or user.is_superuser):
            return Response({
                "data": "You cannot reset your password directly. Please contact your organization head to change your account details."
            }, status=status.HTTP_403_FORBIDDEN)

        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)

        # Generate and save new OTP
        otp = str(random.randint(100000, 999999))
        forgot_password_request.otp = make_password(otp)
        forgot_password_request.created_at = timezone.now()
        forgot_password_request.is_verified = False  # Reset verification status
        forgot_password_request.save()

        # Send new OTP email
        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Password Reset OTP - Resent',
            'action': 'Email Verification',
            'message': 'Use the OTP below to verify your email and proceed with password reset.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-otp/?email={email}",
            'link_text': 'Verify Email'
        })
        return Response({"data": "A new OTP has been sent to your email for verification."}, status=status.HTTP_200_OK)


# class PasswordChangeRequestViewSet(viewsets.ModelViewSet):
#     permission_classes = [IsAuthenticated, OR(IsSuperuser(), IsCEO)]
#     queryset = PasswordChangeRequest.objects.all()
#
#     def get_serializer_class(self):
#         if self.action == 'request_password_change':
#             return PasswordChangeSerializer
#         if self.action == 'verify_password_change':
#             return VerifyPasswordChangeSerializer
#         if self.action == 'resend_otp':
#             return ResendOtpPasswordSerializer
#
#     @swagger_helper("ChangePassword", "Request password change")
#     @action(detail=False, methods=['post'], url_path='request-password-change')
#     def request_password_change(self, request):
#         user = request.user
#         if not (user.is_ceo_role() or user.is_superuser):
#             return Response({"data": "Only CEOs or superusers can change their password."},
#                             status=status.HTTP_403_FORBIDDEN)
#
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#
#         old_password = serializer.validated_data['old_password']
#         new_password = serializer.validated_data['new_password']
#
#         if not user.check_password(old_password):
#             return Response({"data": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)
#
#         if old_password == new_password:
#             return Response({"data": "New password cannot be the same as the old password."},
#                             status=status.HTTP_400_BAD_REQUEST)
#
#         PasswordChangeRequest.objects.filter(user=user).delete()
#         otp = str(random.randint(100000, 999999))
#         hashed_new_password = make_password(new_password)
#
#         PasswordChangeRequest.objects.create(
#             user=user,
#             otp=make_password(otp),
#             new_password=hashed_new_password,
#             requested_by=user,
#             created_at=timezone.now()
#         )
#
#         send_email_via_service({
#             'user_email': user.email,
#             'email_type': 'otp',
#             'subject': 'Password Change OTP',
#             'action': 'Password Change',
#             'message': 'You have requested to change your password. Use the OTP below to proceed. If you did not make this request, please contact support immediately.',
#             'otp': otp,
#             'link': f"{settings.FRONTEND_PATH}/change-password/?email={user.email}",
#             'link_text': 'Change Password'
#         })
#
#         return Response({"data": "An OTP has been sent to your email."}, status=status.HTTP_200_OK)
#
#     @swagger_helper("ChangePassword", "Resend OTP")
#     @action(detail=False, methods=['post'], url_path='resend-otp')
#     def resend_otp(self, request):
#         user = request.user
#         if not (user.is_ceo_role() or user.is_superuser):
#             return Response({"data": "Only CEOs or superusers can resend OTP for password change."},
#                             status=status.HTTP_403_FORBIDDEN)
#
#         password_change_request = PasswordChangeRequest.objects.filter(user=user).first()
#         if not password_change_request:
#             return Response({"data": "No pending password change request found."}, status=status.HTTP_400_BAD_REQUEST)
#
#         otp = str(random.randint(100000, 999999))
#         password_change_request.otp = make_password(otp)
#         password_change_request.created_at = timezone.now()
#         password_change_request.save()
#
#         send_email_via_service({
#             'user_email': user.email,
#             'email_type': 'otp',
#             'subject': 'Password Change OTP - Resent',
#             'action': 'Password Change',
#             'message': 'Use the OTP below to change your password.',
#             'otp': otp,
#             'link': f"{settings.FRONTEND_PATH}/change-password/?email={user.email}",
#             'link_text': 'Change Password'
#         })
#
#         return Response({"data": "A new OTP has been sent to your email."}, status=status.HTTP_200_OK)
#
#     @swagger_helper("ChangePassword", "Verify password change")
#     @action(detail=False, methods=['post'], url_path='verify-password-change')
#     def verify_password_change(self, request):
#         user = request.user
#         if not (user.is_ceo_role() or user.is_superuser):
#             return Response({"data": "Only CEOs or superusers can verify password change."},
#                             status=status.HTTP_403_FORBIDDEN)
#
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         otp = serializer.validated_data['otp']
#
#         password_change_request = PasswordChangeRequest.objects.filter(user=user).first()
#         if not password_change_request:
#             return Response({"data": "No pending password change request found."}, status=status.HTTP_400_BAD_REQUEST)
#
#         if not check_password(otp, password_change_request.otp):
#             return Response({"data": "Incorrect OTP."}, status=status.HTTP_400_BAD_REQUEST)
#
#         if (timezone.now() - password_change_request.created_at).total_seconds() > 300:
#             return Response({"data": "OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
#
#         user.set_password(password_change_request.new_password)
#         user.save()
#         password_change_request.delete()
#
#         refresh_token = request.data.get('refresh_token')
#         if refresh_token:
#             try:
#                 token = RefreshToken(refresh_token)
#                 token.blacklist()
#             except Exception:
#                 raise AuthenticationFailed('Refresh token is invalid or expired.')
#
#         send_email_via_service({
#             'user_email': user.email,
#             'email_type': 'confirmation',
#             'subject': 'Password Changed Successfully',
#             'action': 'Password Change',
#             'message': 'Your password has been successfully changed. If you did not authorize this change, please contact support immediately.'
#         })
#
#         return Response({"data": "Password changed successfully. You have been logged out."}, status=status.HTTP_200_OK)
