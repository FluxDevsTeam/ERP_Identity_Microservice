import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings
from django.core.validators import MinLengthValidator
from django.utils import timezone
from django.core.exceptions import ValidationError
from apps.role.models import ROLE_CHOICES, Permission, ROLES_BY_INDUSTRY


class UserManager(BaseUserManager):

    def _create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            raise ValueError("Password must be provided")
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        if extra_fields.get('is_verified') is not True:
            raise ValidationError("Superuser must have is_verified=True.")

        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, blank=True, null=True, validators=[MinLengthValidator(3)], help_text="For staff login; unique per branch (enforced in serializer).")
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone_number = models.CharField(max_length=15, blank=True)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, blank=True, help_text="Assigned role; determines default permissions. Filtered by industry/tier.")
    tenant = models.ForeignKey('tenant.Tenant', on_delete=models.SET_NULL, null=True, blank=True)
    branch = models.ManyToManyField('tenant.Branch', blank=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='created_users')
    updated_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='updated_users')

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def clean(self):
        # Validate role against industry/tier (called in serializer too)
        if self.role and self.tenant and self.tenant.subscription:
            industry = self.tenant.subscription.plan.industry
            tier = self.tenant.subscription.plan.tier_level
            available_roles = self.get_available_roles(tier)
            if self.role not in [r[0] for r in available_roles]:
                raise ValidationError(f"Role '{self.role}' is not available for industry '{industry}' and tier '{tier}'.")

    def __str__(self):
        return self.username or self.email

    def is_ceo_role(self):
        """Check if role is CEO (for login/permissions logic)."""
        return self.role == 'ceo'

    def get_industry(self):
        """Get user's industry from tenant's subscription plan."""
        if self.tenant and self.tenant.subscription:
            return self.tenant.subscription.plan.industry
        return "Other"

    def get_default_permissions(self):
        """
        Get default permissions based on role and industry.
        Returns list of codenames.
        """
        industry = self.get_industry()
        if self.role == 'ceo':
            # CEO gets all available permissions for tier/industry
            tier = self.tenant.subscription.plan.tier_level if self.tenant and self.tenant.subscription else 'tier1'
            return [p.codename for p in Permission.objects.filter(industry=industry, subscription_tiers__contains=[tier])]
        elif self.role in ROLES_BY_INDUSTRY.get(industry, {}):
            return ROLES_BY_INDUSTRY[industry][self.role]['default_perms']
        return []  # No defaults for invalid role

    def get_effective_permissions(self):
        """
        Compute effective permissions for this user, filtered by industry.
        - Start with role defaults.
        - Apply grants/revokes from UserPermission (industry-matched).
        Returns list of codenames.
        """
        default_codes = set(self.get_default_permissions())

        # Apply user-specific overrides (only those matching industry)
        user_industry = self.get_industry()
        for up in self.user_permissions.filter(permission__industry=user_industry):
            if up.granted:
                default_codes.add(up.permission.codename)
            else:
                default_codes.discard(up.permission.codename)

        return sorted(list(default_codes))

    def has_permission(self, codename):
        """Check if user has a specific permission (industry-aware)."""
        if codename in self.get_effective_permissions():
            return True
        # Fallback: Check Django's permission system if needed
        return super().has_permission(codename)

    def get_available_roles(self, subscription_tier):
        """
        Get available roles (choices) for this tenant's tier and industry.
        Includes base roles + industry-specific filtered by tier.
        Returns list of (value, label) tuples for ChoiceField.
        """
        if self.is_superuser:
            return ROLE_CHOICES
        industry = self.get_industry()
        available = [('ceo', 'CEO'), ('employee', 'Employee')]  # Base always
        if subscription_tier == 'tier1':
            available.append(('manager', 'Manager'))
        elif subscription_tier in ['tier2', 'tier3', 'tier4']:
            available += [('branch_manager', 'Branch Manager'), ('general_manager', 'General Manager')]
        industry_roles = ROLES_BY_INDUSTRY.get(industry, {})
        for role_value, role_info in industry_roles.items():
            if role_info['tier_req'] == 'tier1' or (subscription_tier == 'tier2' and role_info['tier_req'] in ['tier1', 'tier2']) or (subscription_tier == 'tier3' and role_info['tier_req'] in ['tier1', 'tier2', 'tier3']) or (subscription_tier == 'tier4' and role_info['tier_req'] in ['tier1', 'tier2', 'tier3', 'tier4']):
                available.append((role_value, role_value.title().replace('_', ' ')))
        return available


# Existing request models (unchanged)
class NameChangeRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="name_change_request")
    new_first_name = models.CharField(max_length=150, null=True, blank=True)
    new_last_name = models.CharField(max_length=150, null=True, blank=True)
    new_phone_number = models.CharField(max_length=150, null=True, blank=True)
    otp = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Name Change Request for {self.user.email} - {self.new_first_name} {self.new_last_name}"


class EmailChangeRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_change_request")
    new_email = models.EmailField(unique=True)
    otp = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Email Change Request for {self.user.email} to {self.new_email}"


class ForgotPasswordRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    otp = models.IntegerField(null=True, blank=True)
    new_password = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ForgotPasswordRequest for {self.user.email}"


class PasswordChangeRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_change_requests')
    otp = models.CharField(max_length=6)
    new_password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Password change request for {self.user.username or self.user.email}"