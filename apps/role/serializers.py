from rest_framework import serializers
from .models import Role, Permission, UserPermission
from .service import BillingService
from django.contrib.auth import get_user_model

User = get_user_model()

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'codename', 'name', 'description', 'subscription_tiers', 'industry', 'category']

class RoleSerializer(serializers.ModelSerializer):
    default_permissions = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'is_ceo_role', 'subscription_tiers', 'industry', 'default_permissions']

    def validate(self, data):
        request = self.context.get('request')
        if not request.user.is_authenticated:
            raise serializers.ValidationError("User must be authenticated.")

        # Allow superusers to bypass tenant checks
        if request.user.is_superuser:
            return data

        tenant = request.user.tenant
        if not tenant:
            raise serializers.ValidationError("User must be associated with a tenant.")

        subscription = tenant.subscription
        if not subscription or not subscription.plan:
            raise serializers.ValidationError("Tenant must have an active subscription plan.")

        role_name = data.get('name')
        industry = data.get('industry', 'Other')
        subscription_tier = subscription.plan.tier_level

        can_assign, message = BillingService.can_assign_role(
            tenant.id, role_name, industry, subscription_tier, request
        )
        if not can_assign:
            raise serializers.ValidationError({"role": message})

        return data

class UserPermissionSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField(source='user.id')
    user_email = serializers.EmailField(source='user.email', read_only=True)
    permission = serializers.SlugRelatedField(slug_field='codename', queryset=Permission.objects.all())
    assigned_by_email = serializers.EmailField(source='assigned_by.email', read_only=True)

    class Meta:
        model = UserPermission
        fields = ['id', 'user_id', 'user_email', 'permission', 'granted', 'assigned_by_email', 'assigned_at']

    def validate(self, data):
        request = self.context.get('request')
        tenant_id = request.user.tenant.id if request.user and request.user.tenant else None
        if not tenant_id:
            raise serializers.ValidationError("User must be associated with a tenant.")

        try:
            user = User.objects.get(id=data['user']['id'])
        except KeyError:
            raise serializers.ValidationError("user_id is required.")
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist.")

        if user.tenant_id != tenant_id:
            raise serializers.ValidationError("Cannot assign permissions to users outside your tenant.")

        permission_codename = data['permission'].codename
        can_assign, message = BillingService.can_assign_permission(tenant_id, permission_codename, request)
        if not can_assign:
            raise serializers.ValidationError({"permission": message})

        return data

    def create(self, validated_data):
        user = User.objects.get(id=validated_data['user']['id'])
        validated_data['assigned_by'] = self.context['request'].user
        return UserPermission.objects.create(user=user, **validated_data)