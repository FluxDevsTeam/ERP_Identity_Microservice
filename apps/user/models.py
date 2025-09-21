import rest_framework_simplejwt.tokens
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from rest_framework_simplejwt.tokens import RefreshToken
from apps.tenant.models import Tenant, Branch
from django.conf import settings


class NameChangeRequest(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="name_change_request")
    new_first_name = models.CharField(max_length=150, null=True, blank=True)
    new_last_name = models.CharField(max_length=150, null=True, blank=True)
    new_phone_number = models.CharField(max_length=150, null=True, blank=True)
    otp = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Name Change Request for {self.user.email} - {self.new_first_name} {self.new_last_name}"


class EmailChangeRequest(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_change_request")
    new_email = models.EmailField(unique=True)
    otp = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Email Change Request for {self.user.email} to {self.new_email}"


class ForgotPasswordRequest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    otp = models.IntegerField(null=True, blank=True)
    new_password = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"ForgotPasswordRequest for {self.user.email}"


class PasswordChangeRequest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_change_requests')
    otp = models.CharField(max_length=6)
    new_password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Password change request for {self.user.username}"


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

        if not extra_fields['is_staff']:
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields['is_superuser']:
            raise ValueError("Superuser must have is_superuser=True.")
        if not extra_fields['is_verified']:
            raise ValueError("Superuser must have is_verified=True.")

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    ROLE_CHOICES = (
        ('ceo', 'CEO'),
        ('Branch_manager', 'Branch_Manager'),
        ('admin', 'Admin'),
        ('manager', 'Manager'),
        ('employee', 'Employee'),
    )
    username = None
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    otp = models.IntegerField(null=True)
    otp_created_at = models.DateTimeField(auto_now_add=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, null=True, blank=True)
    branch = models.ManyToManyField(Branch)
    role = models.CharField(choices=ROLE_CHOICES, default="admin")
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return ({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

    def __str__(self):
        return self.email
