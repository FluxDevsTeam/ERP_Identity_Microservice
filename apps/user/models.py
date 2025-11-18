import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import MinLengthValidator
from django.core.exceptions import ValidationError
from apps.role.models import Permission, ROLES_BY_INDUSTRY, Role
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
            default_role, _ = Role.objects.get_or_create(
                name='ceo', industry='Other', defaults={'is_ceo_role': True}
            )
            extra_fields['role'] = default_role

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
    role = models.ForeignKey(
        'role.Role', on_delete=models.SET_NULL, null=True, blank=True,
        help_text="Assigned role; determines default permissions. Filtered by industry/tier."
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

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def clean(self):
        if self.role and self.tenant and self.tenant.subscription:
            industry = self.tenant.subscription.plan.industry
            tier = self.tenant.subscription.plan.tier_level
            from apps.role.service import BillingService
            can_assign, message = BillingService.can_assign_role(
                self.tenant.id, self.role.name, self.role.industry, tier, request=None
            )
            if not can_assign:
                raise ValidationError(message)

    def __str__(self):
        return self.username or self.email

    def is_ceo_role(self):
        return bool(self.role and getattr(self.role, "is_ceo_role", False))

    def get_industry(self):
        if self.tenant and self.tenant.subscription:
            return self.tenant.subscription.plan.industry
        return "Other"

    def get_default_permissions(self):
        if not self.role:
            return []
        industry = self.get_industry()
        if self.role.is_ceo_role:
            tier = self.tenant.subscription.plan.tier_level if self.tenant and self.tenant.subscription else 'tier1'
            return [p.codename for p in
                    Permission.objects.filter(industry=industry, subscription_tiers__contains=[tier])]
        elif self.role.name in ROLES_BY_INDUSTRY.get(industry, {}):
            return ROLES_BY_INDUSTRY[industry][self.role.name]['default_perms']
        return []

    def get_effective_permissions(self):
        default_codes = set(self.get_default_permissions())
        user_industry = self.get_industry()
        for up in self.custom_user_permissions.filter(permission__industry=user_industry):
            if up.granted:
                default_codes.add(up.permission.codename)
            else:
                default_codes.discard(up.permission.codename)
        return sorted(list(default_codes))

    def has_permission(self, codename):
        if codename in self.get_effective_permissions():
            return True
        return super().has_permission(codename)

    def get_available_roles(self, subscription_tier):
        if self.is_superuser:
            return [(r.name, r.name.title().replace('_', ' ')) for r in Role.objects.all()]
        industry = self.get_industry()
        available = []
        for role in Role.objects.filter(industry__in=[industry, 'Other']):
            if role.subscription_tiers and subscription_tier in role.subscription_tiers:
                available.append((role.name, r.name.title().replace('_', ' ')))
        return available

    def set_otp(self, otp):
        self.otp = make_password(str(otp))
        self.otp_created_at = timezone.now()

    def check_otp(self, otp):
        if not self.otp:
            return False
        return check_password(str(otp), self.otp)

    def has_subscription(self, request=None):
        if not self.tenant:
            return False
        from apps.user.services import BillingService
        subscription_details = BillingService.fetch_subscription_details(self.tenant.id, request)
        return bool(subscription_details and subscription_details.get("access"))
