import random
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from apps.user.models_auth import TempUser
from apps.user.services import send_email_via_service
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

User = get_user_model()


def validate_username_uniqueness(username):
    if username:
        if User.objects.filter(username__iexact=username).exists() or TempUser.objects.filter(
                username__iexact=username).exists():
            raise serializers.ValidationError("Username is already taken.")
    return username


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['tenant'] = str(user.tenant.id) if user.tenant else None
        token['role'] = user.role.name if user.role else None
        token['is_superuser'] = user.is_superuser
        token['branches'] = [str(branch.id) for branch in user.branch.all()] if user.branch.exists() else []
        token['email'] = user.email
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        data['user'] = {
            'email': user.email,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role.name if user.role else None
        }
        return data


class CustomRefreshTokenSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = RefreshToken.for_user(user)
        token['tenant'] = str(user.tenant.id) if user.tenant else None
        token['tenant_name'] = str(user.tenant.name) if user.tenant else None
        token['role'] = user.role.name if user.role else None
        token['is_superuser'] = user.is_superuser
        token['branches'] = [str(branch.id) for branch in user.branch.all()] if user.branch.exists() else []
        token['email'] = user.email
        token['username'] = user.username
        return token


class RequestForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class SetNewPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    new_password = serializers.CharField(write_only=True, required=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, required=True, min_length=8)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs


class VerifyOtpPasswordSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, required=True)
    email = serializers.EmailField(required=True)


class ResendOtpPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class EmailChangeSerializer(serializers.Serializer):
    new_email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)


# class VerifyEmailChangeSerializer(serializers.Serializer):
#     otp = serializers.CharField(max_length=6, required=True)
#
#
# class ViewUserProfileSerializer(serializers.ModelSerializer):
#     branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)
#     role = serializers.SlugRelatedField(slug_field='name', read_only=True)
#
#     class Meta:
#         model = User
#         fields = ['id', 'first_name', 'last_name', 'email', 'username', 'phone_number', 'branch', 'role']
#

class UserSignupSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=15, required=False, allow_blank=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, min_length=8)
    verify_password = serializers.CharField(write_only=True, required=True, min_length=8)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)

    def validate_username(self, value):
        if value:  # Only validate if provided
            validate_username_uniqueness(value)
        return value

    def validate(self, data):
        if data['password'] != data['verify_password']:
            raise serializers.ValidationError("Passwords do not match.")
        # Consolidated: Username check only here (remove from field if redundant)
        username = data.get('username')
        if username:
            validate_username_uniqueness(username)
        return data

    def create(self, data):
        email = data['email']
        # Updated: Only block if verified User exists; clean up old TempUser if present (abandoned signup)
        if User.objects.filter(email=email, is_verified=True).exists():
            raise serializers.ValidationError("Email is already in use. Please login or use a different email.")

        # Atomic block to prevent race conditions on delete + create
        with transaction.atomic():
            # Clean up any existing unverified TempUser for this email (prevents duplicates, allows retry)
            TempUser.objects.filter(email=email).delete()

            temp_user = TempUser.objects.create(
                email=email,
                username=data.get('username', ''),  # Default to '' if blank
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', ''),
                phone_number=data.get('phone_number', ''),
                password=make_password(data['password'])
            )

        otp = str(random.randint(100000, 999999))  # Fixed: Use randint
        temp_user.set_otp(otp)
        temp_user.save()
        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Verify Your Email',
            'action': 'Email Verification',
            'message': 'Use the OTP below to verify your email address.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-account/?email={email}",
            'link_text': 'Verify Account'
        })
        return temp_user


class UserSignupSerializerVerify(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    email = serializers.EmailField()

    def validate(self, data):
        email = data['email']
        otp = data['otp']
        try:
            # Use select_for_update to lock the TempUser row during validation (prevents concurrent verifies)
            temp_user = TempUser.objects.select_for_update().get(email=email)
        except TempUser.DoesNotExist:
            raise serializers.ValidationError("No pending signup found for this email.")
        if not temp_user.check_otp(otp):
            raise serializers.ValidationError("Invalid OTP.")
        if (timezone.now() - temp_user.otp_created_at).total_seconds() > 300:
            raise serializers.ValidationError("OTP has expired.")
        data['temp_user'] = temp_user  # Pass to create for reuse
        return data

    @transaction.atomic  # Atomic for entire create to ensure delete after User creation
    def create(self, data):
        email = data['email']
        temp_user = data['temp_user']  # From validate

        # Safety check: Ensure no verified User already exists for this email
        if User.objects.filter(email=email, is_verified=True).exists():
            temp_user.delete()  # Clean up pending TempUser
            raise serializers.ValidationError("Account already verified. Please login with your credentials.")

        # Create the verified User
        user = User.objects.create(
            email=temp_user.email,
            username=temp_user.username,
            first_name=temp_user.first_name,
            last_name=temp_user.last_name,
            phone_number=temp_user.phone_number,
            password=temp_user.password,
            is_verified=True  # Ensures the user is verified
        )

        # Delete the pending TempUser record (safe within atomic)
        temp_user.delete()

        send_email_via_service({
            'user_email': email,
            'email_type': 'confirmation',
            'subject': 'Signup Successful',
            'action': 'Signup',
            'message': 'You have finished the signup verification. Welcome!'
        })
        refresh = RefreshToken.for_user(user)

        has_tenant = bool(user.tenant)
        complete_onboarding = bool(user.is_ceo_role() and user.branch.exists())
        if not has_tenant and not complete_onboarding:
            onboarding = "stage1"
        elif has_tenant != complete_onboarding:
            onboarding = "stage2"
        else:
            onboarding = "stage3"

        return {
            'message': 'Signup successful.',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'onboarding': onboarding,
            'is_superuser': user.is_superuser
        }


class UserSignupResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        email = data['email']
        if not TempUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("No pending signup found for this email.")
        return data

    def create(self, data):
        email = data['email']
        temp_user = TempUser.objects.get(email=email)
        otp = str(random.randint(100000, 999999))
        temp_user.set_otp(otp)
        temp_user.save()
        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Resend OTP',
            'action': 'Email Verification',
            'message': 'Use the OTP below to verify your email address.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-account/?email={email}",
            'link_text': 'Verify Account'
        })
        return {'message': 'OTP resent to your email.'}


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=150, required=True)
    password = serializers.CharField(write_only=True, min_length=6, required=True)

    def validate(self, attrs):
        identifier = attrs['identifier']
        password = attrs['password']

        if '@' in identifier:
            try:
                user = User.objects.get(email=identifier)
                if not user.check_password(password):
                    raise serializers.ValidationError("Invalid credentials.")
                attrs['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")
        else:
            try:
                user = User.objects.get(username=identifier)
                if not user.check_password(password):
                    raise serializers.ValidationError("Invalid credentials.")
                attrs['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")

        if not attrs['user'].is_verified:
            raise serializers.ValidationError("Please verify your email first.")
        return attrs


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        try:
            token = RefreshToken(value)
            token.verify()
            return value
        except Exception:
            raise serializers.ValidationError("Invalid or expired refresh token")


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        try:
            token = RefreshToken(value)
            token.verify()
            return value
        except Exception:
            raise serializers.ValidationError("Invalid or expired refresh token")


class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField(required=True)


class SetGoogleAuthPasswordSerializer(serializers.Serializer):
    id_token = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, min_length=8)


class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)


class UsernameAvailabilitySerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, required=True)
