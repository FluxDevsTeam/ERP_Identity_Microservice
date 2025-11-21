import uuid
from django.db import models
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from apps.tenant.models import Branch, Tenant


class TempUser(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, blank=True, null=True, unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    phone_number = models.CharField(max_length=15, blank=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=50, null=True, blank=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.SET_NULL, null=True, blank=True)  # Fixed: Optional for pre-tenant signup
    branch = models.ManyToManyField(Branch, blank=True)
    otp = models.CharField(max_length=128, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        verbose_name = "Temporary User"
        verbose_name_plural = "Temporary Users"

    def __str__(self):
        return f"TempUser: {self.email}"

    def set_otp(self, otp):
        self.otp = make_password(str(otp))
        self.otp_created_at = timezone.now()

    def check_otp(self, otp):
        if not self.otp:
            return False
        return check_password(str(otp), self.otp)


class NameChangeRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="name_change_request")
    new_first_name = models.CharField(max_length=150, null=True, blank=True)
    new_last_name = models.CharField(max_length=150, null=True, blank=True)
    new_phone_number = models.CharField(max_length=150, null=True, blank=True)
    otp = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Name Change Request for {self.user.email} - {self.new_first_name} {self.new_last_name}"


class EmailChangeRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_change_request")
    new_email = models.EmailField(unique=True)
    otp = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Email Change Request for {self.user.email} to {self.new_email}"


class ForgotPasswordRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    otp = models.CharField(max_length=128, null=True, blank=True)
    new_password = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"ForgotPasswordRequest for {self.user.email}"


class PasswordChangeRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='password_change_requests')
    otp = models.CharField(max_length=128)
    new_password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                     related_name='password_change_requests_made')

    def __str__(self):
        return f"Password change request for {self.user.email} by {self.requested_by.email if self.requested_by else 'unknown'}"
