# apps/tenant/models.py
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Tenant(models.Model):
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
        ("Hospitality", "Hospitality"),
        ("Agriculture", "Agriculture"),
        ("Transport and Logistics", "Transport and Logistics"),
        ("Real Estate", "Real Estate"),
        ("Energy and Utilities", "Energy and Utilities"),
        ("Media and Entertainment", "Media and Entertainment"),
        ("Government", "Government"),
        ("Other", "Other")
    )
    name = models.CharField(max_length=200)
    industry = models.CharField(max_length=100, choices=INDUSTRY_CHOICES, default="Other")
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_tenants')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=200, choices=STATUS_CHOICES, default="Active")

    def __str__(self):
        return f"tenant: {self.name}, industry: {self.industry}"

class Branch(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='branches')
    name = models.CharField(max_length=200)
    location = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Branch {self.name} - {self.tenant}"