import uuid
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.cache import cache

TIER_CHOICES = (
    ('tier1', 'Tier 1 - Small Business (1-10 users, 1 branch)'),
    ('tier2', 'Tier 2 - Medium Business (11-50 users, 2-5 branches)'),
    ('tier3', 'Tier 3 - Large Enterprise (51-200 users, 6-20 branches)'),
    ('tier4', 'Tier 4 - Global Corporation (201+ users, 21+ branches)'),
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

ROLE_CHOICES = (
    ('ceo', 'CEO'),
    ('branch_manager', 'Branch Manager'),
    ('general_manager', 'General Manager'),
    ('manager', 'Manager'),
    ('employee', 'Employee'),
    ('teacher', 'Teacher'),
    ('student_admin', 'Student Admin'),
    ('production_manager', 'Production Manager'),
    ('quality_control', 'Quality Control'),
    ('accountant', 'Accountant'),
    ('auditor', 'Auditor'),
    ('doctor', 'Doctor'),
    ('nurse', 'Nurse'),
    ('sales_rep', 'Sales Representative'),
    ('sales_manager', 'Sales Manager'),
    ('cashier', 'Cashier'),
    ('shelf_stocker', 'Shelf Stocker'),
    ('forklift_operator', 'Forklift Operator'),
    ('inventory_clerk', 'Inventory Clerk'),
    ('supply_chain_coordinator', 'Supply Chain Coordinator'),
    ('warehouse_supervisor', 'Warehouse Supervisor'),
    ('admin', 'Admin'),
    ('support', 'Support Staff'),
)

ROLES_BY_INDUSTRY = {
    'Finance': {
        'accountant': {'tier_req': 'tier1', 'default_perms': ['finance.basic_income_expense']},
        'auditor': {'tier_req': 'tier3', 'default_perms': ['finance.basic_income_expense', 'finance.advanced_reports']},
        'sales_rep': {'tier_req': 'tier1', 'default_perms': ['finance.client_leads', 'finance.basic_sales_tracking']},
        'sales_manager': {'tier_req': 'tier2', 'default_perms': ['finance.client_leads', 'finance.sales_reports']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['finance.team_lead', 'finance.monthly_reconciliations']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['finance.branch_audits', 'finance.local_compliance']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['finance.overall_budget', 'finance.strategic_planning']},
    },
    'Healthcare': {
        'doctor': {'tier_req': 'tier1', 'default_perms': ['healthcare.patient_access', 'healthcare.diagnosis']},
        'nurse': {'tier_req': 'tier1', 'default_perms': ['healthcare.patient_access']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['healthcare.staff_scheduling', 'healthcare.supply_orders']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['healthcare.clinic_oversight', 'healthcare.patient_flow']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['healthcare.network_management', 'healthcare.policy_implementation']},
    },
    'Production': {
        'production_manager': {'tier_req': 'tier1', 'default_perms': ['production.products_record', 'production.inventory_basic']},
        'quality_control': {'tier_req': 'tier2', 'default_perms': ['production.products_record', 'production.quality_audit']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['production.shift_supervision', 'production.daily_reports']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['production.factory_oversight', 'production.supply_chain']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['production.company_wide_planning', 'production.compliance']},
    },
    'Education': {
        'teacher': {'tier_req': 'tier1', 'default_perms': ['education.student_record', 'education.grade_management']},
        'student_admin': {'tier_req': 'tier2', 'default_perms': ['education.student_record', 'education.attendance']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['education.basic_admin', 'education.schedule_view']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['education.school_management', 'education.staff_oversight']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['education.district_oversight', 'education.budget_approval']},
    },
    'Technology': {
        'developer': {'tier_req': 'tier1', 'default_perms': ['tech.code_review', 'tech.bug_fixing']},
        'qa_tester': {'tier_req': 'tier2', 'default_perms': ['tech.test_cases', 'tech.automation_scripts']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['tech.project_tracking', 'tech.sprint_planning']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['tech.team_leadership', 'tech.resource_allocation']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['tech.product_roadmap', 'tech.innovation_strategy']},
    },
    'Retail': {
        'sales_rep': {'tier_req': 'tier1', 'default_perms': ['retail.sales_tracking', 'retail.inventory_view']},
        'sales_manager': {'tier_req': 'tier2', 'default_perms': ['retail.sales_tracking', 'retail.inventory_management', 'retail.reports']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['retail.store_operations', 'retail.shift_planning']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['retail.multi_store_oversight', 'retail.supplier_relations']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['retail.regional_strategy', 'retail.performance_analysis']},
    },
    'Agriculture': {
        'farm_manager': {'tier_req': 'tier1', 'default_perms': ['agriculture.crop_tracking', 'agriculture.inventory']},
        'harvester': {'tier_req': 'tier1', 'default_perms': ['agriculture.harvest_record']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['agriculture.field_supervision', 'agriculture.equipment_log']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['agriculture.farm_network', 'agriculture.supply_chain']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['agriculture.sustainable_practices', 'agriculture.market_analysis']},
    },
    'Real Estate': {
        'agent': {'tier_req': 'tier1', 'default_perms': ['real_estate.property_viewing', 'real_estate.client_leads']},
        'property_manager': {'tier_req': 'tier2', 'default_perms': ['real_estate.property_maintenance', 'real_estate.tenant_management']},
        'sales_rep': {'tier_req': 'tier1', 'default_perms': ['real_estate.listing_management']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['real_estate.property_inspections', 'real_estate.contract_review']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['real_estate.branch_portfolio', 'real_estate.local_marketing']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['real_estate.investment_strategy', 'real_estate.risk_assessment']},
    },
    'Supermarket': {
        'cashier': {'tier_req': 'tier1', 'default_perms': ['supermarket.checkout_processing', 'supermarket.customer_service']},
        'shelf_stocker': {'tier_req': 'tier1', 'default_perms': ['supermarket.stock_shelving', 'supermarket.price_checking']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['supermarket.shift_scheduling', 'supermarket.daily_inventory']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['supermarket.store_oversight', 'supermarket.promotion_planning']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['supermarket.regional_operations', 'supermarket.supplier_negotiations']},
        'supply_chain_coordinator': {'tier_req': 'tier3', 'default_perms': ['supermarket.supply_optimization', 'supermarket.demand_forecasting']},
    },
    'Warehouse': {
        'forklift_operator': {'tier_req': 'tier1', 'default_perms': ['warehouse.goods_movement', 'warehouse.loading_unloading']},
        'inventory_clerk': {'tier_req': 'tier1', 'default_perms': ['warehouse.stock_counting', 'warehouse.labeling']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['warehouse.shift_coordination', 'warehouse.safety_checks']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['warehouse.facility_oversight', 'warehouse.equipment_maintenance']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['warehouse.network_efficiency', 'warehouse.compliance_audits']},
        'warehouse_supervisor': {'tier_req': 'tier3', 'default_perms': ['warehouse.order_fulfillment', 'warehouse.quality_control']},
    },
    'Other': {
        'sales_rep': {'tier_req': 'tier1', 'default_perms': ['general.sales_tracking']},
        'sales_manager': {'tier_req': 'tier2', 'default_perms': ['general.sales_reports']},
        'admin': {'tier_req': 'tier1', 'default_perms': ['general.admin_access']},
        'support': {'tier_req': 'tier1', 'default_perms': ['general.support_tickets']},
        'manager': {'tier_req': 'tier1', 'default_perms': ['general.team_lead', 'general.basic_reports']},
        'branch_manager': {'tier_req': 'tier2', 'default_perms': ['general.multi_unit_oversight', 'general.vendor_relations']},
        'general_manager': {'tier_req': 'tier2', 'default_perms': ['general.strategic_planning', 'general.performance_review']},
    },
}


class Permission(models.Model):
    codename = models.CharField(
        max_length=100,
        unique=True,
        help_text="Unique codename for the permission, e.g., 'education.student_record'",
    )
    name = models.CharField(
        max_length=100,
        help_text="Human-readable name, e.g., 'Student Record Access'",
    )
    description = models.TextField(
        blank=True,
        help_text="Detailed description of what this permission allows.",
    )
    subscription_tiers = models.JSONField(
        default=list,
        blank=True,
        help_text="List of tiers this permission is available in, e.g., ['tier1', 'tier2', 'tier3']",
    )
    industry = models.CharField(
        max_length=50,
        choices=INDUSTRY_CHOICES,
        default="Other",
        help_text="Industry this permission applies to, e.g., 'Education'",
    )
    category = models.CharField(
        max_length=50,
        blank=True,
        help_text="Group permissions, e.g., 'accounting', 'inventory', 'users'",
    )

    class Meta:
        verbose_name = "Permission"
        verbose_name_plural = "Permissions"
        ordering = ['industry', 'category', 'name']

    def clean(self):
        valid_tiers = [choice[0] for choice in TIER_CHOICES]
        for tier in self.subscription_tiers:
            if tier not in valid_tiers:
                raise ValidationError(
                    f"Invalid tier '{tier}' in subscription_tiers. Must be one of: {valid_tiers}"
                )

    def __str__(self):
        return f"{self.name} ({self.codename}) - {self.get_industry_display()}"


class Role(models.Model):
    name = models.CharField(max_length=50, choices=ROLE_CHOICES)
    description = models.TextField(blank=True)
    default_permissions = models.ManyToManyField(
        Permission,
        related_name='default_roles',
        blank=True,
        help_text="Default set of permissions granted to users with this role.",
    )
    is_ceo_role = models.BooleanField(
        default=False,
        help_text="Special flag for CEO-like roles (email login, tenant-wide access).",
    )
    subscription_tiers = models.JSONField(
        default=list,
        blank=True,
        help_text="Tiers this role is available in, e.g., ['tier1', 'tier2']",
    )
    industry = models.CharField(
        max_length=50,
        choices=INDUSTRY_CHOICES,
        default="Other",
        help_text="Industry this role applies to, e.g., 'Education' for 'Teacher'",
    )

    class Meta:
        unique_together = ('name', 'industry')
        verbose_name = "Role"
        verbose_name_plural = "Roles"
        ordering = ['industry', 'name']

    def clean(self):
        valid_tiers = [choice[0] for choice in TIER_CHOICES]
        for tier in self.subscription_tiers:
            if tier not in valid_tiers:
                raise ValidationError(
                    f"Invalid tier '{tier}' in subscription_tiers. Must be one of: {valid_tiers}"
                )
        for perm in self.default_permissions.all():
            if perm.industry != self.industry and self.industry != "Other":
                raise ValidationError(
                    f"Default permission '{perm.name}' industry '{perm.get_industry_display()}' "
                    f"does not match role industry '{self.get_industry_display()}'."
                )

    def __str__(self):
        return f"{self.name} ({self.get_industry_display()})"

    def get_default_permissions_list(self):
        cache_key = f"role_permissions_{self.id}"
        cached_perms = cache.get(cache_key)
        if cached_perms is not None:
            return cached_perms
        perms = list(self.default_permissions.values_list('codename', flat=True))
        cache.set(cache_key, perms, timeout=300)  # Cache for 5 minutes
        return perms


class UserPermission(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='custom_user_permissions',
    )
    permission = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        help_text="Must match user's industry.",
    )
    granted = models.BooleanField(
        default=True,
        help_text="True to grant, False to revoke (override role default).",
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_permissions',
    )
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'permission')
        verbose_name = "User Permission"
        verbose_name_plural = "User Permissions"
        ordering = ['-assigned_at']

    def clean(self):
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