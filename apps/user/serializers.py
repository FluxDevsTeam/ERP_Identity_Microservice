# apps/user/serializers.py
import random

from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

# from .models import User
User = get_user_model()


def validate_username_uniqueness(username):
    if username:
        try:
            user = User.objects.get(username__iexact=username)
            raise serializers.ValidationError("Username is already taken.")
        except User.DoesNotExist:
            pass
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


class VerifyEmailChangeSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, required=True)


class ViewUserProfileSerializer(serializers.ModelSerializer):
    branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)
    role = serializers.SlugRelatedField(slug_field='name', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'username', 'phone_number', 'branch', 'role']


class ProfileChangeSerializer(serializers.Serializer):
    new_first_name = serializers.CharField(required=False, min_length=2)
    new_last_name = serializers.CharField(required=False, min_length=2)
    new_phone_number = serializers.CharField(required=False, min_length=11)


class VerifyProfileChangeSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)


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


class UserSignupSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100, required=False)
    last_name = serializers.CharField(max_length=100, required=False)
    phone_number = serializers.CharField(max_length=15, required=False)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    verify_password = serializers.CharField(write_only=True, min_length=8)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)

    def validate_username(self, value):
        return validate_username_uniqueness(value)

    def validate(self, data):
        if data['password'] != data['verify_password']:
            raise serializers.ValidationError("Passwords do not match.")
        # Validate username uniqueness (redundant with field, but double check)
        if data.get('username'):
            validate_username_uniqueness(data['username'])
        return data


class UserSignupSerializerVerify(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    email = serializers.EmailField()


class UserSignupResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=150, required=True)
    password = serializers.CharField(write_only=True, min_length=6, required=True)
    branch_id = serializers.UUIDField(required=False)

    def validate(self, attrs):
        identifier = attrs['identifier']
        password = attrs['password']
        branch_id = attrs.get('branch_id')

        if '@' in identifier:  # Login via email
            try:
                user = User.objects.get(email=identifier)
                if not user.check_password(password):
                    raise serializers.ValidationError("Invalid credentials.")
                attrs['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")
        else:  # Login via username
            if not branch_id:
                raise serializers.ValidationError({"branch_id": "Branch ID is required for username login."})
            try:
                user = User.objects.filter(username=identifier, branch__id=branch_id).first()
                if not user or not user.check_password(password):
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
        except Exception as e:
            raise serializers.ValidationError("Invalid or expired refresh token")


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        try:
            token = RefreshToken(value)
            token.verify()
            return value
        except Exception as e:
            raise serializers.ValidationError("Invalid or expired refresh token")


class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField(required=True)


class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)