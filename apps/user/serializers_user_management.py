import random
import re
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from apps.tenant.models import Branch
from apps.role.models import Role
User = get_user_model()


class UserCreateSerializer(serializers.ModelSerializer):
    branch = serializers.PrimaryKeyRelatedField(queryset=Branch.objects.all(), many=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), required=False)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'tenant', 'password',
                  'username']
        read_only_fields = ['tenant']

    def validate_password(self, value):
        if value and len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate_username(self, value):
        if value:
            user = User.objects.filter(username__iexact=value)
            if user.exists():
                raise serializers.ValidationError("Username is already taken.")
        return value

    def validate(self, data):
        user = self.context['request'].user
        if not user.is_authenticated:
            raise serializers.ValidationError("User must be authenticated.")

        if user.is_superuser:
            if not data.get('role'):
                default_role, _ = Role.objects.get_or_create(name='employee', industry='Other')
                data['role'] = default_role
            return data

        if user.role and user.role.name not in ['ceo', 'branch_manager']:
            raise serializers.ValidationError("Only CEOs or Branch Managers can create users.")

        tenant = user.tenant
        if not tenant:
            raise serializers.ValidationError("User is not associated with a tenant.")

        role = data.get('role', Role.objects.get(name='employee', industry='Other'))
        username = data.get('username')
        branch_ids = [b.id for b in data.get('branch', [])]

        data['tenant'] = tenant
        data['created_by'] = user
        data['updated_by'] = user

        # Validate role against tenant's industry and tier
        industry = tenant.subscription.plan.industry if tenant.subscription else 'Other'
        tier = tenant.subscription.plan.tier_level if tenant.subscription else 'tier1'
        if role.industry != industry and role.industry != 'Other':
            raise serializers.ValidationError(f"Role '{role.name}' is not valid for industry '{industry}'.")
        if tier not in role.subscription_tiers:
            raise serializers.ValidationError(f"Role '{role.name}' is not available for tier '{tier}'.")

        if role.is_ceo_role:
            if username:
                raise serializers.ValidationError("CEOs do not use usernames.")
            data['username'] = None
            data['branch'] = []
            if User.objects.filter(tenant=tenant, role__is_ceo_role=True).exists():
                raise serializers.ValidationError("Only one CEO allowed per tenant.")
        else:
            # username is now optional for staff.
            # Remove the requirement for username for staff below:
            # if not username:
            #     raise serializers.ValidationError("Username is required for staff.")
            if branch_ids == []:
                raise serializers.ValidationError("At least one branch is required for staff.")
            if user.role and user.role.name == 'branch_manager':
                user_branches = user.branch.all()
                for branch_id in branch_ids:
                    if not user_branches.filter(id=branch_id).exists():
                        raise serializers.ValidationError(
                            f"Branch Manager is not authorized to assign users to branch {branch_id}."
                        )
            username = data.get('username')
            if username:
                user = User.objects.filter(username__iexact=username)
                if user.exists():
                    raise serializers.ValidationError("Username is already taken.")

        return data

    def create(self, data):
        password = data.pop('password', None)
        if not password:
            raise serializers.ValidationError("Password must be provided.")
        data['password'] = make_password(password)
        user = super().create(data)
        user.is_verified = True
        user.save()
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    branch = serializers.PrimaryKeyRelatedField(queryset=Branch.objects.all(), many=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    is_active = serializers.BooleanField(required=False)
    username = serializers.CharField(max_length=150, required=False, allow_blank=True)
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), required=False)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'tenant', 'password',
                  'is_active', 'username']
        read_only_fields = ['tenant']

    def validate_password(self, value):
        if value:
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
        if user.role and user.role.name not in ['ceo', 'branch_manager']:
            raise serializers.ValidationError("Only CEOs or Branch Managers can update users.")
        data['updated_by'] = user
        if 'role' in data:
            tenant = user.tenant
            industry = tenant.subscription.plan.industry if tenant.subscription else 'Other'
            tier = tenant.subscription.plan.tier_level if tenant.subscription else 'tier1'
            role = data['role']
            if role.industry != industry and role.industry != 'Other':
                raise serializers.ValidationError(f"Role '{role.name}' is not valid for industry '{industry}'.")
            if tier not in role.subscription_tiers:
                raise serializers.ValidationError(f"Role '{role.name}' is not available for tier '{tier}'.")
        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)
        return super().update(instance, validated_data)


class UserListSerializer(serializers.ModelSerializer):
    branch = serializers.SlugRelatedField(many=True, slug_field='name', read_only=True)
    role = serializers.SlugRelatedField(slug_field='name', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'phone_number', 'role', 'branch', 'is_verified']
