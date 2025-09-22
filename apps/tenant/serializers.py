from rest_framework import serializers
from .models import Tenant, Branch


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = ["id", "name", "industry", "created_by", "created_at", "updated_at", "status"]
        read_only_fields = ["id", "created_at", "updated_at"]


class SimpleTenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = ["id", "name", "industry", "created_at", "updated_at", "status"]


class BranchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Branch
        fields = ["id", "name", "location", "tenant", "created_at", "updated_at"]
        read_only_fields = ["id"]


class ViewBranchSerializer(serializers.ModelSerializer):
    tenant = SimpleTenantSerializer()

    class Meta:
        model = Branch
        fields = ["id", "tenant", "name", "location", "created_at", "updated_at"]
        read_only_fields = ["id"]


