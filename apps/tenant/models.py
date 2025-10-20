import uuid
from django.db import models
from django.conf import settings


class Tenant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    STATUS_CHOICES = (
        ("Active", "Active"),
        ("Inactive", "Inactive"),
        ("Banned", "Banned")
    )
    INDUSTRY_CHOICES = (
    ("Finance", "Finance"),
    ("Healthcare", "Healthcare"),
    ("Production", "Production"),
    ("Education", "Education"),
    ("Technology", "Technology"),
    ("Retail", "Retail"),
    ("Agriculture", "Agriculture"),
    ("Real Estate", "Real Estate"),
    ("Supermarket", "Supermarket"),
    ("Warehouse", "Warehouse"),
    )
    name = models.CharField(max_length=200)
    industry = models.CharField(max_length=100, choices=INDUSTRY_CHOICES)
    created_by = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_tenant')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=200, choices=STATUS_CHOICES, default="Active")

    def __str__(self):
        return f"tenant: {self.name}, industry: {self.industry}"


class Branch(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='branches')
    name = models.CharField(max_length=200)
    location = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Branch {self.name} - {self.tenant}"
