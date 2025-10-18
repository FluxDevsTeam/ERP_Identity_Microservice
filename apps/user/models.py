import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings
from django.core.validators import MinLengthValidator
from django.utils import timezone
from django.core.exceptions import ValidationError


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
    """
    Updated User model with dynamic roles and per-user permissions.
    - CEO roles: Login with email/password. username=None, branch=[] (tenant-level).
    - Staff roles: Login with username/password + branch_id. Username unique per branch.
    Effective permissions: role.default_permissions + user_permissions (overrides).
    Role/permissions availability checked against subscription tier and industry.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    username = models.CharField(
        max_length=150,
        blank=True,
        null=True,
        validators=[MinLengthValidator(3)],
        help_text="For staff login; unique per branch (enforced in serializer)."
    )
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone_number = models.CharField(max_length=15, blank=True)
    role = models.ForeignKey(
        Role,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users',
        help_text="Assigned role; determines default permissions. Must match tenant's industry."
    )
    tenant = models.ForeignKey(
        'tenant.Tenant',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    branch = models.ManyToManyField('tenant.Branch', blank=True)
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_users'
    )
    updated_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='updated_users'
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def clean(self):
        # Ensure role matches tenant's industry
        if self.role and self.tenant and self.tenant.subscription:
            tenant_industry = self.tenant.subscription.plan.industry
            if self.role.industry != tenant_industry and tenant_industry != "Other":
                raise ValidationError(
                    f"Role '{self.role.name}' industry '{self.role.get_industry_display()}' "
                    f"does not match tenant's industry '{tenant_industry}'."
                )

    def __str__(self):
        return self.username or self.email

    def get_industry(self):
        """Get user's industry from tenant's subscription plan."""
        if self.tenant and self.tenant.subscription:
            return self.tenant.subscription.plan.industry
        return "Other"

    def get_effective_permissions(self):
        """
        Compute effective permissions for this user, filtered by industry.
        - Start with role defaults (industry-matched).
        - Apply grants/revokes from UserPermission (industry-matched).
        Returns list of codenames.
        """
        if not self.role or self.role.industry != self.get_industry():
            return []

        default_codes = set(self.role.get_default_permissions_list())

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
        user_industry = self.get_industry()
        if codename in self.get_effective_permissions():
            return True
        # Fallback: Check Django's permission system if needed
        return super().has_permission(codename)

    def get_available_roles(self, subscription_tier):
        """
        Get roles available for this tenant's tier and industry.
        Call this during role assignment in views/serializers.
        """
        if self.is_superuser:
            return Role.objects.all()
        user_industry = self.get_industry()
        return Role.objects.filter(
            industry=user_industry,
            models.Q(subscription_tiers__overlap=[subscription_tier]) |
            models.Q(subscription_tiers__contains=[])
        ).distinct()


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