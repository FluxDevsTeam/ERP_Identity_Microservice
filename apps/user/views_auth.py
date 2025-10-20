from django.contrib.auth import get_user_model
import random
import datetime
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from django.contrib.auth.hashers import make_password, check_password
from .serializers import (UserSignupSerializer, LoginSerializer, RefreshTokenSerializer, UserSignupSerializerVerify, UserSignupResendOTPSerializer, LogoutSerializer, GoogleAuthSerializer, CustomRefreshTokenSerializer, CustomTokenObtainPairSerializer)

from rest_framework_simplejwt.tokens import RefreshToken
from .utils import swagger_helper
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from apps.tenant.models import Tenant
from apps.role.models import Role
import requests
from .service import send_email_via_service
from rest_framework.views import APIView

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

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        phone_number = serializer.validated_data['phone_number']

        user = User.objects.filter(email=email).first()

        if user:
            if not user.is_verified:
                otp = random.randint(100000, 999999)
                user.set_otp(otp)
                user.otp_created_at = timezone.now()
                user.save()

                send_email_via_service({
                    'user_email': email,
                    'email_type': 'otp',
                    'subject': 'Verify Your Email',
                    'action': 'Email Verification',
                    'message': 'Use the OTP below to verify your email address.',
                    'otp': otp,
                    'link': f"{settings.FRONTEND_PATH}/verify-account/?email={user.email}",
                    'link_text': 'Verify Account'
                })

                return Response({"data": "User already exists but is not verified. OTP resent."},
                                status=status.HTTP_200_OK)
            else:
                return Response({"data": "User already exists and is verified."}, status=status.HTTP_400_BAD_REQUEST)

        otp = random.randint(100000, 999999)
        user = User.objects.create(
            first_name=serializer.validated_data['first_name'],
            last_name=serializer.validated_data['last_name'],
            email=email,
            password=make_password(password),
            phone_number=phone_number,
            otp=make_password(str(otp)),
            otp_created_at=timezone.now()
        )

        if user and not user.is_verified:
            otp = random.randint(100000, 999999)
            user.set_otp(otp)
            user.otp_created_at = timezone.now()
            user.is_verified = False
            user.save()
            verification_url = f"{settings.FRONTEND_PATH}/verify-account/?email={user.email}"
            send_email_via_service({
                'user_email': user.email,
                'email_type': 'otp',
                'subject': 'Verify Your Email',
                'action': 'Email Verification',
                'message': 'Use the OTP below to verify your email address.',
                'otp': otp,
                'link': verification_url,
                'link_text': 'Verify Account'
            })

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

        if not check_password(otp, user.otp):
            return Response({"data": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() - user.otp_created_at > datetime.timedelta(minutes=5):
            return Response({"data": "OTP has expired."}, status=status.HTTP_400_BAD_REQUEST)

        user.is_verified = True
        user.otp = None
        user.save()

        # tenant = Tenant.objects.create(
        #     name=f"{user.first_name}'s Organization",
        #     created_by=user
        # )
        # user.tenant = tenant
        # user.save()

        send_email_via_service({
            'user_email': email,
            'email_type': 'confirmation',
            'subject': 'Signup Successful',
            'action': 'Signup',
            'message': 'You have finished the signup verification for KidsDesignCompany. Welcome!'
        })

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
        user.set_otp(otp)
        user.otp_created_at = timezone.now()
        user.save()

        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Resend OTP',
            'action': 'Email Verification',
            'message': 'Use the OTP below to verify your email address.',
            'otp': otp
        })
        return Response({"data": "OTP resent to your email."}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], url_path='check-username')
    def check_username(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({'available': False, 'error': 'Username is required.'}, status=400)
        exists = User.objects.filter(username__iexact=username).exists()
        if exists:
            return Response({'available': False, 'error': 'Username is already taken.'}, status=200)
        return Response({'available': True}, status=200)


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
        # Send login successful email
        send_email_via_service({
            'user_email': user.email,
            'email_type': 'confirmation',
            'subject': 'Login Successful',
            'action': 'Login',
            'message': 'You have successfully logged in. If this wasn\'t you, please contact support immediately.'
        })
        # Generate tokens using SimpleJWT
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
            # Try to identify user by refresh token (optional, skip if fails)
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

            refresh = CustomRefreshTokenSerializer.get_token(user)
            access_token = str(refresh.access_token)
            # Send Google auth login email
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
            return Response({
                'message': 'Invalid ID token',
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'message': 'Authentication failed',
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class UsernameAvailabilityView(APIView):
    @swagger_helper("Username Availability", "Check Username Availability")
    def post(self, request):
        username = request.data.get('username', '').strip()
        if not username:
            return Response({'available': False, 'error': 'Username is required.'}, status=400)
        exists = User.objects.filter(username__iexact=username).exists()
        if exists:
            return Response({'available': False, 'error': 'Username is already taken.'}, status=200)
        return Response({'available': True}, status=200)