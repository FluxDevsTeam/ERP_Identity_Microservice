from django.contrib import admin
from .models import NameChangeRequest, EmailChangeRequest, ForgotPasswordRequest, PasswordChangeRequest
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin

from .models_user import User

admin.site.register(NameChangeRequest)
admin.site.register(EmailChangeRequest)
admin.site.register(ForgotPasswordRequest)
admin.site.register(PasswordChangeRequest)


@admin.register(User)
class UserAdmin(DefaultUserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'role', 'tenant', 'is_staff', 'is_active', 'is_verified', 'phone_number')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'is_verified', 'role', 'tenant')
    search_fields = ('email', 'first_name', 'last_name', 'phone_number')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Information', {'fields': ('first_name', 'last_name', 'phone_number', 'role', 'tenant', 'branch')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'is_verified', 'groups', 'user_permissions')
        }),
        ('Important Dates', {'fields': ('last_login', 'created_by', 'updated_by')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'phone_number', 'role', 'tenant', 'branch', 'password', 'password2', 'is_staff', 'is_active', 'is_verified')}
         ),
    )
