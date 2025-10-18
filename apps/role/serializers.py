# roles/serializers.py
from rest_framework import serializers
from .models import Permission, Role, UserPermission
from users.models import User  # Assuming users app has User
from django.contrib.auth import get_user_model


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'codename', 'name', 'description', 'subscription_tiers', 'industry', 'category']


class PermissionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['codename', 'name', 'description', 'subscription_tiers', 'industry', 'category']

    def validate(self, data):
        # Ensure subscription_tiers are valid
        from .models import TIER_CHOICES
        valid_tiers = [choice[0] for choice in TIER_CHOICES]
        for tier in data.get('subscription_tiers', []):
            if tier not in valid_tiers:
                raise serializers.ValidationError(
                    f"Invalid tier '{tier}'. Must be one of: {valid_tiers}"
                )
        return data


class RoleSerializer(serializers.ModelSerializer):
    default_permissions = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'is_ceo_role', 'subscription_tiers', 'industry', 'default_permissions']


class RoleCreateSerializer(serializers.ModelSerializer):
    default_permissions = serializers.PrimaryKeyRelatedField(
        queryset=Permission.objects.all(), many=True, required=False
    )

    class Meta:
        model = Role
        fields = ['name', 'description', 'is_ceo_role', 'subscription_tiers', 'industry', 'default_permissions']

    def validate(self, data):
        # Ensure subscription_tiers are valid
        from .models import TIER_CHOICES
        valid_tiers = [choice[0] for choice in TIER_CHOICES]
        for tier in data.get('subscription_tiers', []):
            if tier not in valid_tiers:
                raise serializers.ValidationError(
                    f"Invalid tier '{tier}'. Must be one of: {valid_tiers}"
                )
        # Validate default_permissions match industry
        industry = data.get('industry')
        for perm in data.get('default_permissions', []):
            if perm.industry != industry and industry != "Other":
                raise serializers.ValidationError(
                    f"Permission '{perm.name}' industry '{perm.industry}' does not match role industry '{industry}'."
                )
        return data

    def create(self, data):
        default_permissions = data.pop('default_permissions', [])
        role = Role.objects.create(**data)
        if default_permissions:
            role.default_permissions.set(default_permissions)
        return role


class UserPermissionSerializer(serializers.ModelSerializer):
    permission = PermissionSerializer(read_only=True)
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = UserPermission
        fields = ['id', 'user', 'permission', 'granted', 'assigned_by', 'assigned_at']


class UserPermissionCreateSerializer(serializers.ModelSerializer):
    permission = serializers.PrimaryKeyRelatedField(queryset=Permission.objects.all())
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = UserPermission
        fields = ['user', 'permission', 'granted']

    def validate(self, data):
        request = self.context['request']
        user = request.user
        permission = data['permission']
        selected_user = data['user']
        # Ensure only managing own tenant users
        if selected_user.tenant != user.tenant:
            raise serializers.ValidationError("Cannot assign permissions to users outside your tenant.")
        # Ensure permission matches industry
        if selected_user.tenant and selected_user.tenant.subscription:
            user_industry = selected_user.tenant.subscription.plan.industry
            if permission.industry != user_industry and user_industry != "Other":
                raise serializers.ValidationError(
                    f"Permission '{permission.name}' does not match user's industry '{user_industry}'."
                )
        data['assigned_by'] = user
        return data

    def create(self, data):
        assigned_by = data.pop('assigned_by')
        return UserPermission.objects.create(assigned_by=assigned_by, **data)


class UserPermissionListSerializer(serializers.ModelSerializer):
    permission = PermissionSerializer(read_only=True)
    user = serializers.StringRelatedField(read_only=True)  # Username or email
    assigned_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = UserPermission
        fields = ['id', 'user', 'permission', 'granted', 'assigned_by', 'assigned_at']