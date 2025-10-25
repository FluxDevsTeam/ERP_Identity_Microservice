from django.contrib.auth import get_user_model
import random
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    UserSignupSerializer, LoginSerializer, RefreshTokenSerializer, UserSignupSerializerVerify,
    UserSignupResendOTPSerializer, LogoutSerializer, GoogleAuthSerializer,
    CustomRefreshTokenSerializer, CustomTokenObtainPairSerializer,
    RequestForgotPasswordSerializer, SetNewPasswordSerializer, UsernameAvailabilitySerializer,
    VerifyOtpPasswordSerializer,
    ResendOtpPasswordSerializer
)
from .utils import swagger_helper
from rest_framework.permissions import IsAuthenticated, OR
from rest_framework.response import Response
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from apps.user.services import send_email_via_service
from apps.user.permissions import IsCEO, IsSuperuser
from apps.user.models_auth import ForgotPasswordRequest, TempUser

User = get_user_model()


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
        temp_user = serializer.save()
        return Response({"message": "Signup successful. OTP sent to your email."}, status=status.HTTP_201_CREATED)  # Fixed key

    @swagger_helper("Signup", "Verify OTP for user signup")
    @action(detail=False, methods=['post'], url_path='verify-otp')
    def verify(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(result, status=status.HTTP_200_OK)

    @swagger_helper("Signup", "Resend OTP for user signup verification")
    @action(detail=False, methods=['post'], url_path='resend-otp')
    def resend_otp(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(result, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], url_path='check-username')
    def check_username(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({'available': False, 'error': 'Username is required.'}, status=status.HTTP_400_BAD_REQUEST)
        exists = User.objects.filter(username__iexact=username).exists() or \
                 TempUser.objects.filter(username__iexact=username).exists()
        if exists:
            return Response({'available': False, 'error': 'Username is already taken.'},
                            status=status.HTTP_400_BAD_REQUEST)
        return Response({'available': True}, status=status.HTTP_200_OK)


class UserLoginViewSet(viewsets.ModelViewSet):
    def get_serializer_class(self):
        if self.action == 'create':
            return LoginSerializer
        if self.action == 'refresh_token':
            return RefreshTokenSerializer
        return LoginSerializer

    @swagger_helper("Login", "User login with email/username and password")
    def create(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        send_email_via_service({
            'user_email': user.email,
            'email_type': 'confirmation',
            'subject': 'Login Successful',
            'action': 'Login',
            'message': 'You have successfully logged in. If this wasn\'t you, please contact support immediately.'
        })
        token_serializer = CustomTokenObtainPairSerializer(
            data={'email': user.email, 'password': request.data['password']}
        )
        token_serializer.is_valid(raise_exception=True)
        tokens = token_serializer.validated_data
        return Response({
            'message': 'Login successful.',
            'access_token': str(tokens['access']),
            'refresh_token': str(tokens['refresh'])
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
                user = User.objects.get(id=token['user_id'])
                new_token = CustomTokenObtainPairSerializer.get_token(user)
                return Response({
                    'message': 'Access token generated successfully.',
                    'access_token': str(new_token.access_token)
                }, status=status.HTTP_200_OK)
            except Exception:
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
            user = None
            try:
                user_id = token["user_id"]
                user = User.objects.get(id=user_id)
            except Exception:
                pass
            if user:
                send_email_via_service({
                    'user_email': user.email,
                    'email_type': 'confirmation',
                    'subject': 'Logout Successful',
                    'action': 'Logout',
                    'message': 'You have successfully logged out.'
                })
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
            idinfo = id_token.verify_oauth2_token(id_token_str, requests.Request(), settings.GOOGLE_CLIENT_ID)
            email = idinfo['email']
            email_verified = idinfo['email_verified']
            if not email_verified:
                return Response({'message': 'Email not verified with Google'}, status=status.HTTP_400_BAD_REQUEST)
            user = User.objects.filter(email=email).first()
            if not user:
                return Response({
                    'message': 'No user found with this email. Please contact your administrator to create an account.'
                }, status=status.HTTP_400_BAD_REQUEST)
            if not user.is_verified:
                user.is_verified = True
                user.save()
            refresh = CustomRefreshTokenSerializer.get_token(user)
            access_token = str(refresh.access_token)
            send_email_via_service({
                'user_email': user.email,
                'email_type': 'confirmation',
                'subject': 'Google Login Successful',
                'action': 'Google Login',
                'message': 'You have successfully logged in using Google OAuth. If this wasn\'t you, please contact support immediately.'
            })
            return Response({
                'message': 'Google authentication successful.',
                'access_token': access_token,
                'refresh_token': str(refresh),
                'user': {
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': user.role.name if user.role else None
                }
            }, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({'message': 'Invalid ID token', 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': 'Authentication failed', 'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class UsernameAvailabilityView(viewsets.ModelViewSet):
    serializer_class = UsernameAvailabilitySerializer

    @swagger_helper("Username Availability", "Check Username Availability")
    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        exists = User.objects.filter(username__iexact=username).exists() or \
                 TempUser.objects.filter(username__iexact=username).exists()
        if exists:
            return Response({'available': False, 'error': 'Username is already taken.'}, status=200)
        return Response({'available': True}, status=200)


class ForgotPasswordViewSet(viewsets.ModelViewSet):
    queryset = ForgotPasswordRequest.objects.all()
    permission_classes = [OR(IsSuperuser(), IsCEO)]

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
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)
        if not (user.is_ceo_role() or user.is_superuser):
            return Response({"data": "Only CEOs or superusers can reset their password."},
                            status=status.HTTP_403_FORBIDDEN)
        ForgotPasswordRequest.objects.filter(user=user).delete()
        otp = str(random.randint(100000, 999999))
        ForgotPasswordRequest.objects.create(
            user=user,
            otp=make_password(otp),
            created_at=timezone.now()
        )
        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Password Reset OTP',
            'action': 'Password Reset',
            'message': 'Use the OTP below to reset your password.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/change-password/?email={email}",
            'link_text': 'Reset Password'
        })
        return Response({"data": "An OTP has been sent to your email."}, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Set a new password")
    @action(detail=False, methods=['post'], url_path='set-new-password')
    def set_new_password(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        new_password = serializer.validated_data['new_password']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)
        if not (user.is_ceo_role() or user.is_superuser):
            return Response({"data": "Only CEOs or superusers can reset their password."},
                            status=status.HTTP_403_FORBIDDEN)
        ForgotPasswordRequest.objects.filter(user=user).delete()
        otp = str(random.randint(100000, 999999))
        hashed_new_password = make_password(new_password)
        ForgotPasswordRequest.objects.create(
            user=user,
            otp=make_password(otp),
            new_password=hashed_new_password,
            created_at=timezone.now()
        )
        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Forgot Password OTP',
            'action': 'Password Reset',
            'message': 'Use the OTP below to reset your password.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/change-password/?email={email}",
            'link_text': 'Reset Password'
        })
        return Response({"data": "An OTP has been sent to your email."}, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Verify OTP for password reset")
    @action(detail=False, methods=['post'], url_path='verify-otp')
    def verify_otp(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)
        if not (user.is_ceo_role() or user.is_superuser):
            return Response({"data": "Only CEOs or superusers can reset their password."},
                            status=status.HTTP_403_FORBIDDEN)
        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(otp, forgot_password_request.otp):
            return Response({"data": "Incorrect OTP."}, status=status.HTTP_400_BAD_REQUEST)
        if (timezone.now() - forgot_password_request.created_at).total_seconds() > 300:
            return Response({"data": "OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(forgot_password_request.new_password)
        if not user.is_verified:
            user.is_verified = True
        user.save()
        forgot_password_request.delete()
        refresh = RefreshToken.for_user(user)
        send_email_via_service({
            'user_email': user.email,
            'email_type': 'confirmation',
            'subject': 'Password Reset Successful',
            'action': 'Password Reset',
            'message': 'Your password has been successfully reset. You are now securely logged into your account.'
        })
        return Response({
            'message': 'Password reset successful.',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh)
        }, status=status.HTTP_200_OK)

    @swagger_helper("ForgotPassword", "Resend OTP for password reset")
    @action(detail=False, methods=['post'], url_path='resend-otp')
    def resend_otp(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"data": "No user found with this email."}, status=status.HTTP_404_NOT_FOUND)
        if not (user.is_ceo_role() or user.is_superuser):
            return Response({"data": "Only CEOs or superusers can reset their password."},
                            status=status.HTTP_403_FORBIDDEN)
        forgot_password_request = ForgotPasswordRequest.objects.filter(user=user).first()
        if not forgot_password_request:
            return Response({"data": "No pending forgot password request found."}, status=status.HTTP_400_BAD_REQUEST)
        otp = str(random.randint(100000, 999999))
        forgot_password_request.otp = make_password(otp)
        forgot_password_request.created_at = timezone.now()
        forgot_password_request.save()
        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Forgot Password OTP - Resent',
            'action': 'Password Reset',
            'message': 'Use the OTP below to reset your password.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/change-password/?email={email}",
            'link_text': 'Reset Password'
        })
        return Response({"data": "A new OTP has been sent to your email."}, status=status.HTTP_200_OK)
