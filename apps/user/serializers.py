import random
import re

import django.contrib.auth.hashers
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from .models import User
from apps.tenant.models import Branch
from django.contrib.auth.hashers import make_password
import requests
from django.conf import settings

User = get_user_model()

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['tenant'] = str(user.tenant.id) if user.tenant else None
        token['role'] = user.role
        token['is_superuser'] = user.is_superuser
        token['branches'] = [str(branch.id) for branch in user.branch.all()] if user.branch.exists() else []
        token['email'] = user.email
        token['username'] = user.username  # Added: For staff identification
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        data['user'] = {
            'email': user.email,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role
        }
        return data


class CustomRefreshTokenSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = RefreshToken.for_user(user)
        token['tenant'] = str(user.tenant.id) if user.tenant else None
        token['tenant_name'] = str(user.tenant.name) if user.tenant else None
        token['role'] = user.role
        token['is_superuser'] = user.is_superuser
        token['branches'] = [str(branch.id) for branch in user.branch.all()] if user.branch.exists() else []
        token['email'] = user.email  # Add only email
        token['username'] = user.username  # Added: For staff
        return token


# Forgot Password Serializers
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


# User Profile Serializers
class EmailChangeSerializer(serializers.Serializer):
    new_email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)


class VerifyEmailChangeSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, required=True)


class ViewUserProfileSerializer(serializers.ModelSerializer):
    branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'username', 'phone_number', 'branch', 'role']  # Added username


class ProfileChangeSerializer(serializers.Serializer):
    new_first_name = serializers.CharField(required=False, min_length=2)
    new_last_name = serializers.CharField(required=False, min_length=2)
    new_phone_number = serializers.CharField(required=False, min_length=11)


class VerifyProfileChangeSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)


# Password Change Serializers
class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, required=True, min_length=8)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs


class VerifyPasswordChangeSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, required=True)


# User Signup Serializers (CEO-only, unchanged)
class UserSignupSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=False)
    last_name = serializers.CharField(max_length=100, required=False)
    phone_number = serializers.CharField(max_length=15, required=False)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    verify_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        if data['password'] != data['verify_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data


class UserSignupSerializerVerify(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    email = serializers.EmailField()


class UserSignupResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


# Unified Login Serializer (Supports CEO email/password or Staff username/password + branch_id)
class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=150, required=True)  # Email for CEO, username for staff
    password = serializers.CharField(write_only=True, min_length=6, required=True)
    branch_id = serializers.UUIDField(required=False)  # Required for staff, ignored for CEO

    def validate(self, attrs):
        identifier = attrs['identifier']
        password = attrs['password']
        branch_id = attrs.get('branch_id')

        if '@' in identifier:  # CEO login via email
            if branch_id is not None:
                raise serializers.ValidationError({"branch_id": "Branch ID not required for CEO login."})
            try:
                user = User.objects.get(email=identifier)
                if user.role != 'ceo':
                    raise serializers.ValidationError("Only CEOs can log in with email.")
                if not user.check_password(password):
                    raise serializers.ValidationError("Invalid credentials.")
                attrs['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")
        else:  # Staff login via username + branch_id
            if not branch_id:
                raise serializers.ValidationError({"branch_id": "Branch ID is required for staff login."})
            try:
                user = User.objects.filter(username=identifier, branch__id=branch_id).first()
                if not user or user.check_password(password) is False:
                    raise serializers.ValidationError("Invalid credentials.")
                if user.role == 'ceo':
                    raise serializers.ValidationError("CEOs must log in with email.")
                attrs['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")

        if not attrs['user'].is_verified:
            raise serializers.ValidationError("Please verify your email first.")

        return attrs


# Refresh Token Serializer
class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        try:
            token = RefreshToken(value)
            token.verify()
            return value
        except Exception as e:
            raise serializers.ValidationError("Invalid or expired refresh token")


# Logout Serializer
class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        try:
            token = RefreshToken(value)
            token.verify()
            return value
        except Exception as e:
            raise serializers.ValidationError("Invalid or expired refresh token")


# Google Auth Serializer (CEO-only, unchanged)
class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField(required=True)


# Delete Account Serializer
class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)


# User Management Serializers
class UserCreateSerializer(serializers.ModelSerializer):
    branch = serializers.PrimaryKeyRelatedField(
        queryset=Branch.objects.all(), many=True, required=False
    )
    password = serializers.CharField(write_only=True, required=False)  # Changed to required=False
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)  # Added: For staff

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'tenant', 'password', 'username']  # Added username
        read_only_fields = ['tenant']

    def validate_password(self, value):
        if value:
            if len(value) < 8:
                raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate(self, data):
        user = self.context['request'].user
        if not user.is_authenticated:
            raise serializers.ValidationError("User must be authenticated.")

        if user.is_superuser:
            return data

        if user.role not in ['ceo', 'Branch_manager']:
            raise serializers.ValidationError("Only CEOs or Branch Managers can create users.")

        tenant = user.tenant
        if not tenant:
            raise serializers.ValidationError("User is not associated with a tenant.")

        role = data.get('role', 'employee')
        username = data.get('username')
        branch_ids = [b.id for b in data.get('branch', [])]

        data['tenant'] = tenant
        data['created_by'] = user
        data['updated_by'] = user

        if role == 'ceo':
            if username:
                raise serializers.ValidationError("CEOs do not use usernames.")
            data['username'] = None
            data['branch'] = []  # CEOs are tenant-level
            # Optional: Enforce one CEO per tenant if needed
            if User.objects.filter(tenant=tenant, role='ceo').exists():
                raise serializers.ValidationError("Only one CEO allowed per tenant.")
        else:  # Staff (Branch_manager or employee)
            if not username:
                raise serializers.ValidationError("Username is required for staff.")
            if not branch_ids:
                raise serializers.ValidationError("At least one branch is required for staff.")
            if user.role == 'Branch_manager':
                user_branches = user.branch.all()
                for branch_id in branch_ids:
                    if not user_branches.filter(id=branch_id).exists():
                        raise serializers.ValidationError(
                            f"Branch Manager is not authorized to assign users to branch {branch_id}."
                        )
            # Enforce username uniqueness per selected branches
            existing_users = User.objects.filter(
                username=username,
                branch__id__in=branch_ids,
                tenant=tenant  # Within same tenant
            ).exclude(pk=getattr(self.instance, 'pk', None))
            if existing_users.exists():
                raise serializers.ValidationError("Username already exists in one of the selected branches.")

        return data

    def create(self, data):
        password = data.pop('password', None)
        if not password:
            # Generate a random 12-character alphanumeric password
            password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=12))
        data['password'] = make_password(password)
        user = super().create(data)
        user.is_verified = True
        user.save()
        # Send temporary password email
        from .tasks import is_celery_healthy, send_email_synchronously, send_generic_email_task
        if not is_celery_healthy():
            send_email_synchronously(
                user_email=user.email,
                email_type="confirmation",
                subject="Account Created",
                action="User Creation",
                message=f"Your account has been created for {user.tenant.name}. Your temporary password is: {password}. Please log in and change your password."
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': user.email,
                    'email_type': "confirmation",
                    'subject': "Account Created",
                    'action': "User Creation",
                    'message': f"Your account has been created for {user.tenant.name}. Your temporary password is: {password}. Please log in and change your password."
                }
            )
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    branch = serializers.PrimaryKeyRelatedField(
        queryset=Branch.objects.all(), many=True, required=False
    )
    password = serializers.CharField(write_only=True, required=False)
    is_active = serializers.BooleanField(required=False)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)  # Added

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'tenant', 'password',
                  'is_active', 'username']  # Added username
        read_only_fields = ['tenant']

    def validate_password(self, value):
        if value:  # Only validate if password is provided
            if len(value) < 8:
                raise serializers.ValidationError("Password must be at least 8 characters long.")
            if not re.search(r'[A-Z]', value):
                raise serializers.ValidationError("Password must contain at least one uppercase letter.")
            if not re.search(r'[a-z]', value):
                raise serializers.ValidationError("Password must contain at least one lowercase letter.")
            if not re.search(r'[0-9]', value):
                raise serializers.ValidationError("Password must contain at least one digit.")
        return value

    def validate(self, data):
        user = self.context['request'].user
        if user.is_superuser:
            return data
        if user.role not in ['ceo', 'Branch_manager']:
            raise serializers.ValidationError("Only CEOs or Branch Managers can update users.")
        data['updated_by'] = user
        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)
        return super().update(instance, validated_data)


class UserListSerializer(serializers.ModelSerializer):
    branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'is_verified']  # Added username