import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings
from django.core.validators import MinLengthValidator
from django.utils import timezone
from django.core.exceptions import ValidationError


# Tier choices for consistency across models (e.g., used in Permission.subscription_tiers, Role.subscription_tiers)
# Values like ['tier1', 'tier2'] in JSONField should match these.
TIER_CHOICES = (
    ('tier1', 'Tier 1 - Basic'),
    ('tier2', 'Tier 2 - Pro'),
    ('tier3', 'Tier 3 - Enterprise'),
)


# Industry choices (shared across models)
INDUSTRY_CHOICES = (
    ("Finance", "Finance"),
    ("Healthcare", "Healthcare"),
    ("Production", "Production"),
    ("Education", "Education"),
    ("Technology", "Technology"),
    ("Retail", "Retail"),
    ("Hospitality", "Hospitality"),
    ("Agriculture", "Agriculture"),
    ("Transport and Logistics", "Transport and Logistics"),
    ("Real Estate", "Real Estate"),
    ("Energy and Utilities", "Energy and Utilities"),
    ("Media and Entertainment", "Media and Entertainment"),
    ("Government", "Government"),
    ("Other", "Other"),
)


class Permission(models.Model):
    """
    Custom permission model for granular access control.
    Examples: 'education.student_record', 'production.products_record',
              'finance.basic_income_expense', 'healthcare.patient_access'.
    Tied to subscription tiers and industries via fields.
    """
    codename = models.CharField(
        max_length=100,
        unique=True,
        help_text="Unique codename for the permission, e.g., 'education.student_record'"
    )
    name = models.CharField(
        max_length=100,
        help_text="Human-readable name, e.g., 'Student Record Access'"
    )
    description = models.TextField(
        blank=True,
        help_text="Detailed description of what this permission allows."
    )
    subscription_tiers = models.JSONField(
        default=list,
        blank=True,
        help_text="List of tiers this permission is available in, e.g., ['tier1', 'tier2', 'tier3'] "
                  "(must match TIER_CHOICES values)"
    )
    industry = models.CharField(
        max_length=50,
        choices=INDUSTRY_CHOICES,
        default="Other",
        help_text="Industry this permission applies to, e.g., 'Education', 'Production'"
    )
    category = models.CharField(
        max_length=50,
        blank=True,
        help_text="Group permissions, e.g., 'accounting', 'inventory', 'users'"
    )

    class Meta:
        verbose_name = "Permission"
        verbose_name_plural = "Permissions"
        ordering = ['industry', 'category', 'name']

    def clean(self):
        # Validate subscription_tiers contains only valid choices
        valid_tiers = [choice[0] for choice in TIER_CHOICES]
        for tier in self.subscription_tiers:
            if tier not in valid_tiers:
                raise ValidationError(
                    f"Invalid tier '{tier}' in subscription_tiers. Must be one of: {valid_tiers}"
                )

    def __str__(self):
        return f"{self.name} ({self.codename}) - {self.get_industry_display()}"


class Role(models.Model):
    """
    Dynamic roles with default permissions, industry-specific.
    Available roles depend on subscription tier and industry.
    E.g., 'Teacher' role (industry='Education') with 'education.student_record' permission.
    'Production Manager' role (industry='Production') with 'production.products_record' permission.
    """
    name = models.CharField(max_length=50, unique=False)  # Not unique globally; unique per industry
    description = models.TextField(blank=True)
    default_permissions = models.ManyToManyField(
        Permission,
        related_name='default_roles',
        blank=True,
        help_text="Default set of permissions granted to users with this role."
    )
    is_ceo_role = models.BooleanField(
        default=False,
        help_text="Special flag for CEO-like roles (email login, tenant-wide access)."
    )
    subscription_tiers = models.JSONField(
        default=list,
        blank=True,
        help_text="Tiers this role is available in, e.g., ['tier1', 'tier2'] "
                  "(must match TIER_CHOICES values)"
    )
    industry = models.CharField(
        max_length=50,
        choices=INDUSTRY_CHOICES,
        default="Other",
        help_text="Industry this role applies to, e.g., 'Education' for 'Teacher'"
    )

    class Meta:
        unique_together = ('name', 'industry')  # Unique per industry
        verbose_name = "Role"
        verbose_name_plural = "Roles"
        ordering = ['industry', 'name']

    def clean(self):
        # Validate subscription_tiers contains only valid choices
        valid_tiers = [choice[0] for choice in TIER_CHOICES]
        for tier in self.subscription_tiers:
            if tier not in valid_tiers:
                raise ValidationError(
                    f"Invalid tier '{tier}' in subscription_tiers. Must be one of: {valid_tiers}"
                )
        # Ensure default permissions match industry
        for perm in self.default_permissions.all():
            if perm.industry != self.industry and self.industry != "Other":
                raise ValidationError(
                    f"Default permission '{perm.name}' industry '{perm.get_industry_display()}' "
                    f"does not match role industry '{self.get_industry_display()}'."
                )

    def __str__(self):
        return f"{self.name} ({self.get_industry_display()})"

    def get_default_permissions_list(self):
        """Return list of codenames for default permissions."""
        return list(self.default_permissions.values_list('codename', flat=True))


class UserPermission(models.Model):
    """
    Per-user permission overrides.
    Allows CEO to grant/revoke specific permissions independently of role defaults.
    Filtered by user's industry (tenant's plan.industry).
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_permissions'
    )
    permission = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        help_text="Must match user's industry."
    )
    granted = models.BooleanField(
        default=True,
        help_text="True to grant, False to revoke (override role default)."
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_permissions'
    )
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'permission')  # One assignment per user-permission
        verbose_name = "User Permission"
        verbose_name_plural = "User Permissions"
        ordering = ['-assigned_at']

    def clean(self):
        # Ensure permission matches user's industry
        if self.user.tenant and self.user.tenant.subscription:
            user_industry = self.user.tenant.subscription.plan.industry
            if self.permission.industry != user_industry and user_industry != "Other":
                raise ValidationError(
                    f"Permission '{self.permission.name}' industry '{self.permission.get_industry_display()}' "
                    f"does not match user's industry '{user_industry}'."
                )

    def __str__(self):
        status = "Granted" if self.granted else "Revoked"
        return f"{self.user} - {self.permission.name} ({status})"

