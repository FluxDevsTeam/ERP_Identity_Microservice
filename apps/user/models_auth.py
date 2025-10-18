import uuid
from django.db import models
from django.conf import settings


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
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='password_change_requests')
    otp = models.CharField(max_length=6)
    new_password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Password change request for {self.user.username or self.user.email}"
