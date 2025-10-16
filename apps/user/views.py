from django.contrib.auth import get_user_model
import random
import datetime
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import AuthenticationFailed
from .serializers import (
    UserSignupSerializer, LoginSerializer, ViewUserProfileSerializer,
    ResendOtpPasswordSerializer, VerifyOtpPasswordSerializer, SetNewPasswordSerializer,
    RefreshTokenSerializer, EmailChangeSerializer,
    VerifyEmailChangeSerializer, ProfileChangeSerializer, VerifyProfileChangeSerializer,
    PasswordChangeSerializer, VerifyPasswordChangeSerializer, RequestForgotPasswordSerializer,
    UserSignupSerializerVerify, UserSignupResendOTPSerializer, LogoutSerializer,
    GoogleAuthSerializer, DeleteAccountSerializer,
    UserCreateSerializer, UserListSerializer, UserUpdateSerializer, CustomRefreshTokenSerializer,
    CustomTokenObtainPairSerializer
)
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import swagger_helper
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import EmailChangeRequest, PasswordChangeRequest, ForgotPasswordRequest, NameChangeRequest, User
from django.utils.timezone import now
from .tasks import is_celery_healthy, send_email_synchronously, send_generic_email_task
from django.utils.functional import SimpleLazyObject
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from .permissions import IsCEO, IsBranchManager, IsCEOorBranchManager, CanViewEditUser, CanDeleteUser, HasActiveSubscription
from apps.tenant.models import Branch, Tenant
from apps.tenant.serializers import BranchSerializer
from .service import BillingService
import requests

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

        frontend_base_route = SimpleLazyObject(lambda: settings.FRONTEND_PATH)
        reset_url = f"{frontend_base_route}/change-password/?email={email}"
        ForgotPasswordRequest.objects.filter(user=user).delete()
        ForgotPasswordRequest.objects.create(user=user)

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="reset_link",
                subject="Password Reset Request",
                action="Password Reset",
                message="You have requested to reset your password. Click the link below to proceed. This link will expire in 10 minutes. If you did not make this request, please contact support immediately.",
                link=reset_url,
                link_text="Reset Password"
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "reset_link",
                    'subject': "Password Reset Request",
                    'action': "Password Reset",
                    'message': "You have requested to reset your password. Click the link below to proceed. This link will expire in 10 minutes. If you did not make this request, please contact support immediately.",
                    'link': reset_url,
                    'link_text': "Reset Password"
                }
            )

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

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="otp",
                subject="Forgot Password OTP",
                action="Password Reset",
                message="Use the OTP below to reset your password.",
                otp=otp
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "otp",
                    'subject': "Forgot Password OTP",
                    'action': "Password Reset",
                    'message': "Use the OTP below to reset your password.",
                    'otp': otp
                }
            )
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

        if user.role != 'ceo':
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

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=user.email,
                email_type="confirmation",
                subject="Password Reset Successful",
                action="Password Reset",
                message="Your password has been successfully reset. You are now securely logged into your account. If you did not authorize this change, please contact support immediately."
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': user.email,
                    'email_type': "confirmation",
                    'subject': "Password Reset Successful",
                    'action': "Password Reset",
                    'message': "Your password has been successfully reset. You are now securely logged into your account. If you did not authorize this change, please contact support immediately."
                }
            )

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

        if user.role != 'ceo':
            return Response({"data": "Only CEOs can resend OTP for password reset."}, status=status.HTTP_403_FORBIDDEN)

        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)

        otp = random.randint(100000, 999999)
        forgot_password_request.otp = otp
        forgot_password_request.created_at = timezone.now()
        forgot_password_request.save()

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="otp",
                subject="Forgot Password OTP - Resent",
                action="Password Reset",
                message="Use the OTP below to reset your password.",
                otp=otp
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "otp",
                    'subject': "Forgot Password OTP - Resent",
                    'action': "Password Reset",
                    'message': "Use the OTP below to reset your password.",
                    'otp': otp
                }
            )
        return Response({"data": "A new OTP has been sent to your email and the expiration time has been extended."},
                        status=status.HTTP_200_OK)


class PasswordChangeRequestViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsCEO]
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

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=user.email,
                email_type="otp",
                subject="Password Change OTP",
                action="Password Change",
                message="You have requested to change your password. Use the OTP below to proceed. If you did not make this request, please contact support immediately.",
                otp=otp
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': user.email,
                    'email_type': "otp",
                    'subject': "Password Change OTP",
                    'action': "Password Change",
                    'message': "You have requested to change your password. Use the OTP below to proceed. If you did not make this request, please contact support immediately.",
                    'otp': otp
                }
            )

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

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=user.email,
                email_type="otp",
                subject="Password Change OTP - Resent",
                action="Password Change",
                message="Use the OTP below to change your password.",
                otp=otp
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': user.email,
                    'email_type': "otp",
                    'subject': "Password Change OTP - Resent",
                    'action': "Password Change",
                    'message': "Use the OTP below to change your password.",
                    'otp': otp
                }
            )
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

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=user.email,
                email_type="confirmation",
                subject="Password Changed Successfully",
                action="Password Change",
                message="Your password has been successfully changed. If you did not authorize this change, please contact support immediately."
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': user.email,
                    'email_type': "confirmation",
                    'subject': "Password Changed Successfully",
                    'action': "Password Change",
                    'message': "Your password has been successfully changed. If you did not authorize this change, please contact support immediately."
                }
            )

        return Response({"data": "Password changed successfully. You have been logged out."},
                        status=status.HTTP_200_OK)


class UserSignupViewSet(viewsets.ModelViewSet):
    def get_serializer_class(self):
        if self.action == 'verify':
            return UserSignupSerializerVerify
        if self.action == 'resend_otp':
            return UserSignupResendOTPSerializer
        if self.action == 'create':
            return UserSignupSerializer

    @swagger_helper("Signup", "User signup with email and password")
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        phone_number = serializer.validated_data['phone_number']

        user = User.objects.filter(email=email).first()

        if user:
            if not user.is_verified:
                otp = random.randint(100000, 999999)
                user.otp = otp
                print(otp)  #this is a temporary bypass
                user.otp_created_at = now()
                user.save()

                # if not is_celery_healthy():
                #     send_email_synchronously(
                #         user_email=email,
                #         email_type="otp",
                #         subject="Verify Your Email",
                #         action="Email Verification",
                #         message="Use the OTP below to verify your email address.",
                #         otp=otp
                #     )
                # else:
                #     send_generic_email_task.apply_async(
                #         kwargs={
                #             'user_email': email,
                #             'email_type': "otp",
                #             'subject': "Verify Your Email",
                #             'action': "Email Verification",
                #             'message': "Use the OTP below to verify your email address.",
                #             'otp': otp
                #         }
                #     )

                return Response({"data": "User already exists but is not verified. OTP resent."},
                                status=status.HTTP_200_OK)
            else:
                return Response({"data": "User already exists and is verified."}, status=status.HTTP_400_BAD_REQUEST)

        otp = random.randint(100000, 999999)
        User.objects.create(
            first_name=serializer.validated_data['first_name'],
            last_name=serializer.validated_data['last_name'],
            email=email,
            password=make_password(password),
            phone_number=phone_number,
            otp=otp,
            otp_created_at=now(),
            role='ceo'  # Default role for new signups
        )

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="otp",
                subject="Verify Your Email",
                action="Email Verification",
                message="Use the OTP below to verify your email address.",
                otp=otp
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "otp",
                    'subject': "Verify Your Email",
                    'action': "Email Verification",
                    'message': "Use the OTP below to verify your email address.",
                    'otp': otp
                }
            )

        return Response({"data": "Signup successful. OTP sent to your email."}, status=status.HTTP_201_CREATED)

    @swagger_helper("Signup", "Verify OTP for user signup")
    @action(detail=False, methods=['post'], url_path='verify-otp')
    def verify(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user.is_verified:
            return Response({"data": "User is already verified."}, status=status.HTTP_400_BAD_REQUEST)

        if str(user.otp) != otp:
            return Response({"data": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        if now() - user.otp_created_at > datetime.timedelta(minutes=5):
            return Response({"data": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        user.is_verified = True
        user.otp = None
        user.save()

        tenant = Tenant.objects.create(
            name=f"{user.first_name}'s Organization",
            created_by=user
        )
        user.tenant = tenant
        user.save()

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="confirmation",
                subject="Signup Successful",
                action="Signup",
                message="You have finished the signup verification for KidsDesignCompany. Welcome!"
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "confirmation",
                    'subject': "Signup Successful",
                    'action': "Signup",
                    'message': "You have finished the signup verification for KidsDesignCompany. Welcome!"
                }
            )

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            'message': 'Signup successful.',
            'access_token': access_token,
            'refresh_token': str(refresh),
        }, status=status.HTTP_200_OK)

    @swagger_helper("Signup", "Resend OTP for user signup verification")
    @action(detail=False, methods=['post'], url_path='resend-otp')
    def resend_otp(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user.is_verified:
            return Response({"data": "User is already verified."}, status=status.HTTP_400_BAD_REQUEST)

        otp = random.randint(100000, 999999)
        user.otp = otp
        user.otp_created_at = now()
        user.save()

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="otp",
                subject="Resend OTP",
                action="Email Verification",
                message="Use the OTP below to verify your email address.",
                otp=otp
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "otp",
                    'subject': "Resend OTP",
                    'action': "Email Verification",
                    'message': "Use the OTP below to verify your email address.",
                    'otp': otp
                }
            )
        return Response({"data": "OTP resent to your email."}, status=status.HTTP_200_OK)

class UserLoginViewSet(viewsets.ModelViewSet):
    def get_serializer_class(self):
        if self.action == 'create':
            return LoginSerializer
        if self.action == 'refresh_token':
            return RefreshTokenSerializer
        return LoginSerializer

    @swagger_helper("Login", "User login with email and password")
    def create(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({'message': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_verified:
            return Response({'message': 'Please verify your email first'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({'message': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)

        # Use CustomTokenObtainPairSerializer
        token_serializer = CustomTokenObtainPairSerializer(data={'email': email, 'password': password})
        token_serializer.is_valid(raise_exception=True)
        tokens = token_serializer.validated_data

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="confirmation",
                subject="Login Successful",
                action="Login",
                message="You have successfully logged in to KidsDesignCompany. Welcome!"
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "confirmation",
                    'subject': "Login Successful",
                    'action': "Login",
                    'message': "You have successfully logged in to KidsDesignCompany. Welcome!"
                }
            )

        return Response({
            'message': 'Login successful.',
            'access_token': str(tokens['access']),
            'refresh_token': str(tokens['refresh']),
            'user': tokens['user']
        }, status=status.HTTP_200_OK)

    @swagger_helper("Login", "Refresh access token to get a new access token")
    @action(detail=False, methods=['post'], url_path='refresh-token')
    def refresh_token(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']
            try:
                token = RefreshToken(refresh_token)
                token.verify()
                # Optionally use CustomRefreshTokenSerializer for refresh token
                user = User.objects.get(id=token['user_id'])
                new_token = CustomRefreshTokenSerializer.get_token(user)
                return Response({
                    'message': 'Access token generated successfully.',
                    'access_token': str(new_token.access_token)
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'message': 'Invalid or expired refresh token'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "logout":
            return LogoutSerializer

    @swagger_helper("Logout", "User logout. Invalidates the refresh token")
    @action(detail=False, methods=['post'])
    def logout(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"detail": "Logout successful."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": "Error during logout.", "data": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class GoogleAuthViewSet(viewsets.ModelViewSet):
    def get_serializer_class(self):
        return GoogleAuthSerializer

    @swagger_helper("Google Auth", "Authenticate user with Google OAuth2 ID token")
    @action(detail=False, methods=['post'], url_path='google-auth')
    def google_auth(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        id_token_str = serializer.validated_data['id_token']

        try:
            idinfo = id_token.verify_oauth2_token(
                id_token_str,
                requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            email = idinfo['email']
            email_verified = idinfo['email_verified']
            if not email_verified:
                return Response({
                    'message': 'Email not verified with Google'
                }, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.filter(email=email).first()

            if not user:
                return Response({
                    'message': 'No user found with this email. Please contact your administrator to create an account.'
                }, status=status.HTTP_400_BAD_REQUEST)

            if not user.is_verified:
                user.is_verified = True
                user.save()

            # Use CustomRefreshTokenSerializer to generate token
            refresh = CustomRefreshTokenSerializer.get_token(user)
            access_token = str(refresh.access_token)

            if not is_celery_healthy():
                send_email_synchronously(
                    user_email=email,
                    email_type="confirmation",
                    subject="Login Successful",
                    action="Google Login",
                    message="You have successfully logged in to KidsDesignCompany using Google. Welcome!"
                )
            else:
                send_generic_email_task.apply_async(
                    kwargs={
                        'user_email': email,
                        'email_type': "confirmation",
                        'subject': "Login Successful",
                        'action': "Google Login",
                        'message': "You have successfully logged in to KidsDesignCompany using Google. Welcome!"
                    }
                )

            return Response({
                'message': 'Google authentication successful.',
                'access_token': access_token,
                'refresh_token': str(refresh),
                'user': {
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': user.role
                }
            }, status=status.HTTP_200_OK)

        except ValueError as e:
            return Response({
                'message': 'Invalid ID token',
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'message': 'Authentication failed',
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class UserManagementViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    # permission_classes = [IsAuthenticated, IsCEOorBranchManager, HasActiveSubscription]
    permission_classes = [IsAuthenticated, IsCEOorBranchManager]
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['email', 'first_name', 'last_name']
    filterset_fields = ['role', 'tenant', 'branch', 'is_verified']

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        if self.action in ['list', 'retrieve']:
            return UserListSerializer
        if self.action == 'update' or self.action == 'partial_update':
            return UserUpdateSerializer
        return UserListSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return User.objects.all()
        if user.role == 'ceo':
            return User.objects.filter(tenant=user.tenant)
        if user.role == 'Branch_manager':
            return User.objects.filter(tenant=user.tenant, branch__in=user.branch.all())
        return User.objects.none()

    def get_permissions(self):
        if self.action in ['create', 'list']:
            return [IsAuthenticated(), IsCEOorBranchManager()]
            # return [IsAuthenticated(), IsCEOorBranchManager(), HasActiveSubscription()]
        if self.action in ['retrieve', 'update', 'partial_update']:
            return [IsAuthenticated(), CanViewEditUser()]
        if self.action == 'destroy':
            return [IsAuthenticated(), CanDeleteUser()]
        return [IsAuthenticated()]

    @swagger_helper("User Management", "Create a new user. Requires authentication (JWT) and CEO/Branch Manager role.")
    def create(self, request, *args, **kwargs):
        tenant_id = request.user.tenant.id
        current_user_count = User.objects.filter(tenant=request.user.tenant).count()
        can_create, message = BillingService.can_create_user(tenant_id, current_user_count)

        if not can_create:
            return Response({"detail": message}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        # Check branch-specific limits for Branch Managers
        branch_ids = serializer.validated_data.get('branch', [])
        if request.user.role == 'Branch_manager' and branch_ids:
            try:
                response = requests.get(
                    f"{settings.BILLING_MICROSERVICE_URL}/access-check/limits/",
                    headers={"Authorization": request.META.get('HTTP_AUTHORIZATION')}
                )
                response.raise_for_status()
                data = response.json()
                branch_limits = {b['branch_id']: b for b in data.get('branch_limits', [])}
                for branch_id in branch_ids:
                    branch_limit = branch_limits.get(branch_id)
                    if not branch_limit or not branch_limit['users_allowed']:
                        return Response({
                            "error": f"Cannot add user to branch {branch_id}. Maximum users reached."
                        }, status=status.HTTP_403_FORBIDDEN)
            except requests.RequestException:
                return Response({"error": "Unable to verify subscription limits."},
                                status=status.HTTP_503_SERVICE_UNAVAILABLE)

        user = serializer.save()
        return Response({"data": "User created successfully."}, status=status.HTTP_201_CREATED)

    @swagger_helper("User Management",
                    "List all users filtered by role, tenant, branch, and verification status. Supports search.")
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_helper("User Management", "Retrieve a single user's details.")
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @swagger_helper("User Management", "Update a user's details. Partial updates are supported.")
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=instance.email,
                email_type="confirmation",
                subject="Profile Updated",
                action="User Update",
                message=f"Your profile has been updated by {request.user.email}."
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': instance.email,
                    'email_type': "confirmation",
                    'subject': "Profile Updated",
                    'action': "User Update",
                    'message': f"Your profile has been updated by {request.user.email}."
                }
            )

        return Response({"data": "User updated successfully."}, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Update a user's details. Partial updates are supported.")
    def partial_update(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    @swagger_helper("User Management", "Delete a user from the system.")
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        email = instance.email
        instance.delete()

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="confirmation",
                subject="Account Deleted",
                action="User Deletion",
                message=f"Your account has been deleted by {request.user.email}."
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "confirmation",
                    'subject': "Account Deleted",
                    'action': "User Deletion",
                    'message': f"Your account has been deleted by {request.user.email}."
                }
            )

        return Response({"data": "User deleted successfully."}, status=status.HTTP_200_OK)
