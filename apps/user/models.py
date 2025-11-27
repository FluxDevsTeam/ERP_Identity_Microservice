import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import MinLengthValidator
from django.core.exceptions import ValidationError
from apps.role.models import ROLES_BY_INDUSTRY
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone


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
        if 'role' not in extra_fields:
            extra_fields['role'] = 'ceo'

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
    username = models.CharField(
        max_length=150, blank=True, null=True, unique=True, validators=[MinLengthValidator(3)],
        help_text="User login username. Optional, but if provided must be unique."
    )
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone_number = models.CharField(max_length=15, blank=True)
    role = models.CharField(
        max_length=50, choices=[(k, k.title().replace('_', ' ')) for k in ROLES_BY_INDUSTRY.get('Finance', {}).keys()] + [(k, k.title().replace('_', ' ')) for k in ROLES_BY_INDUSTRY.get('Healthcare', {}).keys()] + [(k, k.title().replace('_', ' ')) for k in ROLES_BY_INDUSTRY.get('Education', {}).keys()] + [(k, k.title().replace('_', ' ')) for k in ROLES_BY_INDUSTRY.get('Other', {}).keys()],
        null=True, blank=True,
        help_text="Assigned role; determines default permissions."
    )
    tenant = models.ForeignKey('tenant.Tenant', on_delete=models.SET_NULL, null=True, blank=True)
    branch = models.ManyToManyField('tenant.Branch', blank=True)
    otp = models.CharField(max_length=128, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='created_users')
    updated_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='updated_users')
    custom_permissions = models.JSONField(
        default=dict,
        blank=True,
        help_text="Custom permissions: {'granted': ['codename1'], 'revoked': ['codename2']}"
    )

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def clean(self):
        industry = self.get_industry()
        if self.role and self.tenant and industry:
            role_data = ROLES_BY_INDUSTRY.get(industry, {}).get(self.role) or ROLES_BY_INDUSTRY.get('Other', {}).get(self.role)
            if not role_data:
                raise ValidationError(f"Role '{self.role}' not available.")

    def __str__(self):
        return self.username or self.email

    def is_ceo_role(self):
        return self.role == 'ceo'

    def get_industry(self):
        if self.tenant and hasattr(self.tenant, 'industry'):
            return self.tenant.industry
        return None

    def get_default_permissions(self):
        if not self.role:
            return []
        industry = self.get_industry()
        role_data = ROLES_BY_INDUSTRY.get(industry, {}).get(self.role) or ROLES_BY_INDUSTRY.get('Other', {}).get(self.role)
        if not role_data:
            return []
        # default_perms is now directly a list of permission names
        perm_names = role_data.get('default_perms', [])
        # Convert permission names to codenames
        perms = []
        for perm_name in perm_names:
            codename = f"{industry.lower()}_{perm_name}"
            perms.append(codename)
        return perms

    def get_effective_permissions(self):
        default_codes = set(self.get_default_permissions())
        custom = self.custom_permissions or {}

        for codename in custom.get('granted', []):
            default_codes.add(codename)
        for codename in custom.get('revoked', []):
            default_codes.discard(codename)

        return sorted(list(default_codes))

    def has_permission(self, codename):
        if codename in self.get_effective_permissions():
            return True
        return super().has_permission(codename)

    def get_available_roles(self, subscription_tier):
        if self.is_superuser:
            all_roles = []
            for ind, roles in ROLES_BY_INDUSTRY.items():
                for role_name, data in roles.items():
                    all_roles.append((role_name, role_name.title().replace('_', ' ')))
            return all_roles
        industry = self.get_industry()
        available = []
        for role_name, data in ROLES_BY_INDUSTRY.get(industry, {}).items():
            if data.get('tier_req') == subscription_tier:
                available.append((role_name, role_name.title().replace('_', ' ')))
        for role_name, data in ROLES_BY_INDUSTRY.get('Other', {}).items():
            if data.get('tier_req') == subscription_tier:
                available.append((role_name, role_name.title().replace('_', ' ')))
        return available

    def set_otp(self, otp):
        self.otp = make_password(str(otp))
        self.otp_created_at = timezone.now()

    def check_otp(self, otp):
        if not self.otp:
            return False
        return check_password(str(otp), self.otp)
