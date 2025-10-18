# roles/admin.py
from django.contrib import admin
from .models import Permission, Role, UserPermission


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ['name', 'codename', 'industry', 'category', 'subscription_tiers']
    list_filter = ['industry', 'category', 'subscription_tiers']
    search_fields = ['name', 'codename', 'description']
    ordering = ['industry', 'name']


class DefaultPermissionsInline(admin.TabularInline):
    model = Role.default_permissions.through
    extra = 0


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'industry', 'is_ceo_role', 'subscription_tiers']
    list_filter = ['industry', 'is_ceo_role', 'subscription_tiers']
    search_fields = ['name', 'description']
    ordering = ['industry', 'name']
    inlines = [DefaultPermissionsInline]


@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ['user', 'permission', 'granted', 'assigned_by', 'assigned_at']
    list_filter = ['granted', 'assigned_at']
    search_fields = ['user__email', 'permission__name']
    ordering = ['-assigned_at']