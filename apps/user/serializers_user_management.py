import random
import re  # Still imported but unused now

from django.db import transaction
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.conf import settings
from apps.tenant.models import Branch
from apps.user.models_auth import TempUser, PasswordChangeRequest
from apps.user.services import send_email_via_service, BillingService
from apps.role.models import ROLE_CHOICES

User = get_user_model()


class TempUserSerializer(serializers.ModelSerializer):
    role = serializers.CharField(read_only=True)
    branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)
    created_by = serializers.SlugRelatedField(slug_field='email', read_only=True)
    is_verified = serializers.BooleanField(default=False, read_only=True)

    class Meta:
        model = TempUser
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone_number', 'role', 'branch',
                  'is_verified', 'created_at', 'created_by']


class UserCreateSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, min_length=8)
    verify_password = serializers.CharField(write_only=True, required=True, min_length=8)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)
    first_name = serializers.CharField(max_length=30, required=False)
    last_name = serializers.CharField(max_length=30, required=False)
    phone_number = serializers.CharField(max_length=15, required=False)
    role = serializers.ChoiceField(choices=ROLE_CHOICES, required=False)
    branch = serializers.PrimaryKeyRelatedField(many=True, queryset=Branch.objects.all(), required=False)

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate_username(self, value):
        if value:
            if User.objects.filter(username__iexact=value).exists() or TempUser.objects.filter(
                    username__iexact=value).exists():
                raise serializers.ValidationError("Username is already taken.")
        return value

    def validate(self, data):
        if data['password'] != data['verify_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        request = self.context.get('request')
        user = request.user
        if not user.is_authenticated:
            raise serializers.ValidationError("User must be authenticated.")

        tenant = user.tenant
        if not tenant:
            raise serializers.ValidationError("User must be associated with a tenant.")

        if not user.is_superuser and user.role and user.role not in ['ceo', 'branch_manager', 'general_manager']:
            raise serializers.ValidationError("Only CEOs, Branch Managers, or General Managers can create users.")

        email = data['email']
        # Check for verified User to prevent duplicates
        if User.objects.filter(email=email, is_verified=True).exists():
            raise serializers.ValidationError({"email": "Email is already in use by a verified user."})

        # Validate user creation limit
        current_user_count = User.objects.filter(tenant=tenant).count() + TempUser.objects.filter(tenant=tenant).count()
        can_create, message = BillingService.can_create_user(tenant.id, current_user_count, request)
        if not can_create:
            raise serializers.ValidationError({"non_field_errors": message})

        # Fetch subscription details
        subscription_details = BillingService.fetch_subscription_details(tenant.id, request)
        if not subscription_details or not subscription_details.get('access'):
            raise serializers.ValidationError("Tenant has no active subscription. Cannot create users.")

        industry = subscription_details['plan']['industry']
        tier = subscription_details['plan']['tier_level']

        # Validate role
        role = data.get('role')
        if role is None:
            data['role'] = 'employee'
        else:
            # Check if role exists in ROLES_BY_INDUSTRY for the industry
            from apps.role.models import ROLES_BY_INDUSTRY
            if industry not in ROLES_BY_INDUSTRY or role not in ROLES_BY_INDUSTRY[industry]:
                raise serializers.ValidationError({
                    "role": f"Role '{role}' not available for industry '{industry}'."
                })
            role_data = ROLES_BY_INDUSTRY[industry][role]
            if role_data['tier_req'] != tier:
                raise serializers.ValidationError({"role": f"Role '{role}' requires tier '{role_data['tier_req']}', but tenant has '{tier}'."})

        role = data['role']

        # Validate branches
        branches = data.get('branch', [])
        if role == 'ceo':
            # CEOs do not use usernames or branches
            if branches:
                raise serializers.ValidationError("CEOs cannot be assigned to branches.")
            if User.objects.filter(tenant=tenant, role='ceo').exists():
                raise serializers.ValidationError("Only one CEO allowed per tenant.")
            data['username'] = None
            data['branch'] = []
        else:
            if not branches:
                raise serializers.ValidationError("At least one branch is required for staff.")
            for branch in branches:
                if branch.tenant_id != tenant.id:
                    raise serializers.ValidationError(
                        {"branch": f"Branch {branch.name} does not belong to the tenant."})
            if user.role in ['branch_manager', 'manager']:
                user_branches = user.branch.all()
                for branch in branches:
                    if not user_branches.filter(id=branch.id).exists():
                        raise serializers.ValidationError(
                            f"Branch Manager is not authorized to assign users to branch {branch.name}."
                        )

        data['tenant'] = tenant
        data['created_by'] = user
        return data

    def create(self, validated_data):
        validated_data.pop('verify_password')
        branches = validated_data.pop('branch', [])
        password = validated_data.pop('password')
        role = validated_data.get('role')
        tenant = validated_data['tenant']
        created_by = validated_data['created_by']
        email = validated_data['email']

        # Atomic block to prevent race conditions
        with transaction.atomic():
            # Delete any existing TempUser for this email
            TempUser.objects.filter(email=email).delete()

            # Create new TempUser
            temp_user = TempUser.objects.create(
                email=email,
                username=validated_data.get('username', ''),
                first_name=validated_data.get('first_name', ''),
                last_name=validated_data.get('last_name', ''),
                phone_number=validated_data.get('phone_number', ''),
                password=make_password(password),
                role=role,  # Now string
                tenant=tenant,
                created_by=created_by
            )
            temp_user.branch.set(branches)
            otp = str(random.randint(100000, 999999))
            temp_user.set_otp(otp)
            temp_user.save()

        send_email_via_service({
            'user_email': email,
            'email_type': 'otp',
            'subject': 'Verify Your Account',
            'action': 'User Creation Verification',
            'message': f'Your account has been created by {created_by.email}. Use the OTP below to verify your email.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-user/?email={email}",
            'link_text': 'Verify Account'
        })
        return temp_user


class UserVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(max_length=6, required=True)

    def validate(self, data):
        email = data['email']
        otp = data['otp']
        try:
            # Lock TempUser to prevent concurrent verification
            temp_user = TempUser.objects.select_for_update().get(email=email)
        except TempUser.DoesNotExist:
            raise serializers.ValidationError("No pending user found for this email.")
        if not temp_user.check_otp(otp):
            raise serializers.ValidationError("Invalid OTP.")
        if (timezone.now() - temp_user.otp_created_at).total_seconds() > 300:
            raise serializers.ValidationError("OTP has expired.")
        # Safety check: Ensure no verified User exists
        if User.objects.filter(email=email, is_verified=True).exists():
            temp_user.delete()
            raise serializers.ValidationError("Account already verified for this email.")
        data['temp_user'] = temp_user  # Pass to create
        return data

    @transaction.atomic
    def create(self, validated_data):
        temp_user = validated_data['temp_user']
        email = temp_user.email

        # Create the verified User
        user = User.objects.create(
            email=temp_user.email,
            username=temp_user.username,
            first_name=temp_user.first_name,
            last_name=temp_user.last_name,
            phone_number=temp_user.phone_number,
            password=temp_user.password,
            role=temp_user.role,  # Now string
            tenant=temp_user.tenant,
            created_by=temp_user.created_by,
            is_verified=True
        )
        user.branch.set(temp_user.branch.all())
        temp_user.delete()

        send_email_via_service({
            'user_email': email,
            'email_type': 'confirmation',
            'subject': 'Account Verified',
            'action': 'User Creation',
            'message': 'Your account has been successfully verified. Welcome!'
        })
        return user


class UserResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, data):
        email = data['email']
        if not TempUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("No pending user found for this email.")
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
            'action': 'User Creation Verification',
            'message': f'Use the OTP below to verify your email.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-user/?email={email}",
            'link_text': 'Verify Account'
        })
        return {'message': 'OTP resent to your email.'}


class UserUpdateSerializer(serializers.ModelSerializer):
    role = serializers.ChoiceField(choices=ROLE_CHOICES, required=False)
    branch = serializers.PrimaryKeyRelatedField(many=True, queryset=Branch.objects.all(), required=False)
    password = serializers.CharField(write_only=True, required=False, min_length=8)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)
    is_active = serializers.BooleanField(required=False)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'password', 'username',
                  'is_active']
        read_only_fields = ['email']

    def validate_password(self, value):
        if value and len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate_username(self, value):
        if value:
            existing = User.objects.filter(username__iexact=value).exclude(id=self.instance.id)
            if existing.exists() or TempUser.objects.filter(username__iexact=value).exists():
                raise serializers.ValidationError("Username is already taken.")
        return value

    def validate(self, data):
        request = self.context.get('request')
        user = request.user
        if not user.is_authenticated:
            raise serializers.ValidationError("User must be authenticated.")
        if not user.is_superuser and user.role and user.role not in ['ceo', 'branch_manager', 'general_manager']:
            raise serializers.ValidationError("Only CEOs, Branch Managers, or General Managers can update users.")

        tenant = user.tenant
        if not tenant:
            raise serializers.ValidationError("User must be associated with a tenant.")

        # Ensure updating the same tenant's user
        if self.instance.tenant != tenant:
            raise serializers.ValidationError("Cannot update users outside your tenant.")

        # Fetch subscription details instead of accessing tenant.subscription
        subscription_details = BillingService.fetch_subscription_details(tenant.id, request)
        if not subscription_details or not subscription_details.get('access'):
            raise serializers.ValidationError("Tenant has no active subscription. Cannot update users.")

        industry = subscription_details['plan']['industry']
        tier = subscription_details['plan']['tier_level']

        role = data.get('role')
        if role:
            # Ensure role exists in ROLES_BY_INDUSTRY for the industry
            from apps.role.models import ROLES_BY_INDUSTRY
            if industry not in ROLES_BY_INDUSTRY or role not in ROLES_BY_INDUSTRY[industry]:
                raise serializers.ValidationError({
                    "role": f"Role '{role}' not available for industry '{industry}'."
                })
            role_data = ROLES_BY_INDUSTRY[industry][role]
            if role_data['tier_req'] != tier:
                raise serializers.ValidationError({"role": f"Role '{role}' requires tier '{role_data['tier_req']}', but tenant has '{tier}'."})

        branches = data.get('branch', [])
        role = role or self.instance.role  # Use existing if not changing
        if role == 'ceo':
            # CEOs do not use usernames or branches
            if branches:
                raise serializers.ValidationError("CEOs cannot be assigned to branches.")
            if self.instance and self.instance.role != 'ceo' and User.objects.filter(tenant=tenant, role='ceo').exists():
                raise serializers.ValidationError("Only one CEO allowed per tenant.")
            data['username'] = None
            data['branch'] = []
        else:
            if not branches and self.instance.branch.exists():
                raise serializers.ValidationError("At least one branch is required for staff.")
            for branch in branches:
                if branch.tenant_id != tenant.id:
                    raise serializers.ValidationError(
                        {"branch": f"Branch {branch.name} does not belong to the tenant."})
            if user.role in ['branch_manager', 'manager']:
                user_branches = user.branch.all()
                for branch in branches:
                    if not user_branches.filter(id=branch.id).exists():
                        raise serializers.ValidationError(
                            f"Branch Manager is not authorized to assign users to branch {branch.name}."
                        )

        data['updated_by'] = user
        return data

    def update(self, instance, validated_data):
        branches = validated_data.pop('branch', None)
        password = validated_data.pop('password', None)
        instance = super().update(instance, validated_data)
        if branches is not None:
            instance.branch.set(branches)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class UserListSerializer(serializers.ModelSerializer):
    role = serializers.CharField(read_only=True)
    branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)
    created_by = serializers.SlugRelatedField(slug_field='email', read_only=True)
    updated_by = serializers.SlugRelatedField(slug_field='email', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'is_verified',
                  'is_active', 'created_at', 'created_by', 'updated_at', 'updated_by']


class UserCustomPermissionsSerializer(serializers.ModelSerializer):
    custom_permissions = serializers.JSONField()

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'role', 'custom_permissions']
        read_only_fields = ['id', 'email', 'first_name', 'last_name', 'role']


class AdminPasswordChangeSerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=True)
    new_password = serializers.CharField(write_only=True, required=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, required=True, min_length=8)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        request = self.context.get('request')
        if not request.user.is_superuser and not request.user.is_ceo_role():
            raise serializers.ValidationError("Only CEOs or superusers can change passwords.")
        try:
            user = User.objects.get(id=data['user_id'])
            if user.tenant != request.user.tenant:
                raise serializers.ValidationError("Cannot change password for users outside your tenant.")
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        return data

    def create(self, validated_data):
        user = User.objects.get(id=validated_data['user_id'])
        request = self.context.get('request')
        otp = str(random.randint(100000, 999999))
        PasswordChangeRequest.objects.filter(user=user, is_verified=False).delete()
        password_change_request = PasswordChangeRequest.objects.create(
            user=user,
            new_password=make_password(validated_data['new_password']),
            otp=make_password(otp),
            requested_by=request.user,
            created_at=timezone.now()
        )

        send_email_via_service({
            'user_email': request.user.email,
            'email_type': 'otp',
            'subject': 'Password Change Verification',
            'action': 'Password Change',
            'message': f'You requested to change the password for {user.email}. Use the OTP below to verify.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-password-change/?user_id={user.id}",
            'link_text': 'Verify Password Change'
        })
        return {'message': 'Password change request created. Verify with OTP sent to your email.'}


class AdminVerifyPasswordChangeSerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=True)
    otp = serializers.CharField(max_length=6, required=True)

    def validate(self, data):
        request = self.context.get('request')
        if not request.user.is_superuser and not request.user.is_ceo_role():
            raise serializers.ValidationError("Only CEOs or superusers can verify password changes.")
        try:
            password_change_request = PasswordChangeRequest.objects.get(
                user__id=data['user_id'],
                requested_by=request.user,
                is_verified=False
            )
        except PasswordChangeRequest.DoesNotExist:
            raise serializers.ValidationError("No pending password change request found.")
        if not check_password(data['otp'], password_change_request.otp):
            raise serializers.ValidationError("Invalid OTP.")
        if (timezone.now() - password_change_request.created_at).total_seconds() > 300:
            raise serializers.ValidationError("OTP has expired.")
        return data

    def create(self, validated_data):
        password_change_request = PasswordChangeRequest.objects.get(
            user__id=validated_data['user_id'],
            is_verified=False
        )
        user = password_change_request.user
        user.set_password(password_change_request.new_password)
        user.save()
        password_change_request.is_verified = True
        password_change_request.save()

        send_email_via_service({
            'user_email': user.email,
            'email_type': 'confirmation',
            'subject': 'Password Changed',
            'action': 'Password Change',
            'message': 'Your password has been successfully changed.'
        })
        return {'message': 'Password changed successfully.'}


class ResendPasswordChangeOTPSerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=True)

    def validate(self, data):
        request = self.context.get('request')
        if not request.user.is_superuser and not request.user.is_ceo_role():
            raise serializers.ValidationError("Only CEOs or superusers can resend OTP for password changes.")
        try:
            password_change_request = PasswordChangeRequest.objects.get(
                user__id=data['user_id'],
                requested_by=request.user,
                is_verified=False
            )
        except PasswordChangeRequest.DoesNotExist:
            raise serializers.ValidationError("No pending password change request found.")
        return data

    def create(self, validated_data):
        password_change_request = PasswordChangeRequest.objects.get(
            user__id=validated_data['user_id'],
            is_verified=False
        )
        otp = str(random.randint(100000, 999999))
        password_change_request.otp = make_password(otp)
        password_change_request.created_at = timezone.now()
        password_change_request.save()

        send_email_via_service({
            'user_email': password_change_request.requested_by.email,
            'email_type': 'otp',
            'subject': 'Resend Password Change OTP',
            'action': 'Password Change',
            'message': f'You requested to change the password for {password_change_request.user.email}. Use the OTP below to verify.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/verify-password-change/?user_id={password_change_request.user.id}",
            'link_text': 'Verify Password Change'
        })
        return {'message': 'OTP resent to your email.'}