import django.contrib.auth.hashers
from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from .models import User, Branch
from django.contrib.auth.hashers import make_password

User = get_user_model()


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
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number', 'branch', 'role']


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


# User Signup Serializers
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


# Login Serializer
class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=50, min_length=6, write_only=True)
    email = serializers.EmailField(max_length=50, min_length=2)

    class Meta:
        model = User
        fields = ['email', 'password']


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


# Google Auth Serializer
class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField(required=True)


# Delete Account Serializer
class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)


# User Management Serializers
class UserCreateSerializer(serializers.ModelSerializer):
    branch = serializers.PrimaryKeyRelatedField(queryset=Branch.objects.all(), many=True)
    password = serializers.CharField(write_only=True, required=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default='employee')

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'password']

    def validate(self, data):
        request = self.context.get('request')
        user = request.user

        if user.role == 'branch_manager':
            if data['role'] in ['ceo', 'branch_manager']:
                raise serializers.ValidationError(
                    "Branch Manager cannot create users with 'ceo' or 'branch_manager' roles.")
            for branch in data['branch']:
                if branch not in user.branch.all():
                    raise serializers.ValidationError("Branch Manager can only assign users to their own branches.")

        if user.role == 'ceo':
            for branch in data['branch']:
                if branch.tenant != user.tenant:
                    raise serializers.ValidationError("CEO can only assign users to branches within their tenant.")

        return data

    def create(self, validated_data):
        branches = validated_data.pop('branch')
        password = validated_data.pop('password')
        user = User.objects.create(
            **validated_data,
            password=make_password(password),
            tenant=self.context['request'].user.tenant
        )
        user.branch.set(branches)
        return user


class UserListSerializer(serializers.ModelSerializer):
    branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'is_verified']


class UserUpdateSerializer(serializers.ModelSerializer):
    branch = serializers.PrimaryKeyRelatedField(queryset=Branch.objects.all(), many=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=False)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone_number', 'role', 'branch']

    def validate(self, data):
        request = self.context.get('request')
        user = request.user

        if user.role == 'branch_manager':
            if 'role' in data and data['role'] in ['ceo', 'branch_manager']:
                raise serializers.ValidationError("Branch Manager cannot assign 'ceo' or 'branch_manager' roles.")
            if 'branch' in data:
                for branch in data['branch']:
                    if branch not in user.branch.all():
                        raise serializers.ValidationError("Branch Manager can only assign users to their own branches.")

        if user.role == 'ceo' and 'branch' in data:
            for branch in data['branch']:
                if branch.tenant != user.tenant:
                    raise serializers.ValidationError("CEO can only assign users to branches within their tenant.")

        return data
