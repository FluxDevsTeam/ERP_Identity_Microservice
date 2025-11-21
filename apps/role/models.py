import uuid
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.cache import cache

# Organized Permissions Configuration
PERMISSIONS_CONFIG = {
    'Finance': {
        'permissions': {
            'BASIC_INCOME_ACCESS': {'tier_req': 'tier1', 'category': 'income', 'level': 'basic'},
            'CREATE_INCOME_ACCESS': {'tier_req': 'tier1', 'category': 'income', 'level': 'create'},
            'FULL_INCOME_ACCESS': {'tier_req': 'tier1', 'category': 'income', 'level': 'full'},
            'BASIC_LOAN_MANAGEMENT': {'tier_req': 'tier2', 'category': 'loan', 'level': 'basic'},
            'APPROVE_LOAN_ACCESS': {'tier_req': 'tier2', 'category': 'loan', 'level': 'approve'},
            'FULL_LOAN_MANAGEMENT': {'tier_req': 'tier2', 'category': 'loan', 'level': 'full'},
            'BASIC_REPORT_ACCESS': {'tier_req': 'tier1', 'category': 'report', 'level': 'basic'},
            'EDIT_REPORT_ACCESS': {'tier_req': 'tier1', 'category': 'report', 'level': 'edit'},
            'FULL_REPORT_ACCESS': {'tier_req': 'tier2', 'category': 'report', 'level': 'full'},
            'MANAGE_BUDGET_ACCESS': {'tier_req': 'tier3', 'category': 'budget', 'level': 'manage'},
            'GENERATE_STATEMENT_ACCESS': {'tier_req': 'tier2', 'category': 'statement', 'level': 'generate'},
            'AUDIT_COMPLIANCE_ACCESS': {'tier_req': 'tier3', 'category': 'audit', 'level': 'audit'},
        },
        'roles': {
            'accountant': ['FULL_INCOME_ACCESS', 'EDIT_REPORT_ACCESS'],
            'loan_officer': ['BASIC_LOAN_MANAGEMENT', 'APPROVE_LOAN_ACCESS'],
            'auditor': ['FULL_INCOME_ACCESS', 'FULL_LOAN_MANAGEMENT', 'AUDIT_COMPLIANCE_ACCESS'],
            'branch_manager': ['FULL_INCOME_ACCESS', 'FULL_LOAN_MANAGEMENT', 'EDIT_REPORT_ACCESS'],
            'general_manager': ['FULL_INCOME_ACCESS', 'FULL_LOAN_MANAGEMENT', 'MANAGE_BUDGET_ACCESS', 'GENERATE_STATEMENT_ACCESS'],
            'ceo': ['FULL_INCOME_ACCESS', 'FULL_LOAN_MANAGEMENT', 'MANAGE_BUDGET_ACCESS', 'GENERATE_STATEMENT_ACCESS', 'AUDIT_COMPLIANCE_ACCESS'],
        }
    },
    'Healthcare': {
        'permissions': {
            'BASIC_PATIENT_ACCESS': {'tier_req': 'tier1', 'category': 'patient', 'level': 'basic'},
            'FULL_PATIENT_ACCESS': {'tier_req': 'tier1', 'category': 'patient', 'level': 'full'},
            'EDIT_DIAGNOSIS_ACCESS': {'tier_req': 'tier1', 'category': 'patient', 'level': 'edit_diagnosis'},
            'MANAGE_SCHEDULE_ACCESS': {'tier_req': 'tier2', 'category': 'schedule', 'level': 'manage'},
            'PHARMACY_ACCESS': {'tier_req': 'tier2', 'category': 'pharmacy', 'level': 'pharmacy'},
        },
        'roles': {
            'doctor': ['FULL_PATIENT_ACCESS', 'EDIT_DIAGNOSIS_ACCESS'],
            'nurse': ['BASIC_PATIENT_ACCESS'],
            'admin': ['MANAGE_SCHEDULE_ACCESS', 'PHARMACY_ACCESS'],
            'branch_manager': ['FULL_PATIENT_ACCESS', 'MANAGE_SCHEDULE_ACCESS', 'PHARMACY_ACCESS'],
            'general_manager': ['FULL_PATIENT_ACCESS', 'MANAGE_SCHEDULE_ACCESS', 'PHARMACY_ACCESS'],
            'ceo': ['BASIC_PATIENT_ACCESS', 'FULL_PATIENT_ACCESS', 'EDIT_DIAGNOSIS_ACCESS', 'MANAGE_SCHEDULE_ACCESS', 'PHARMACY_ACCESS'],
        }
    },
    'Education': {
        'permissions': {
            'BASIC_STUDENT_ACCESS': {'tier_req': 'tier1', 'category': 'student', 'level': 'basic'},
            'EDIT_GRADES_ACCESS': {'tier_req': 'tier1', 'category': 'student', 'level': 'edit_grades'},
            'FULL_STUDENT_ACCESS': {'tier_req': 'tier1', 'category': 'student', 'level': 'full'},
            'MANAGE_ATTENDANCE_ACCESS': {'tier_req': 'tier2', 'category': 'attendance', 'level': 'manage'},
            'PLAN_CURRICULUM_ACCESS': {'tier_req': 'tier2', 'category': 'curriculum', 'level': 'plan'},
        },
        'roles': {
            'teacher': ['FULL_STUDENT_ACCESS', 'EDIT_GRADES_ACCESS'],
            'student_admin': ['MANAGE_ATTENDANCE_ACCESS', 'PLAN_CURRICULUM_ACCESS'],
            'branch_manager': ['FULL_STUDENT_ACCESS', 'MANAGE_ATTENDANCE_ACCESS', 'PLAN_CURRICULUM_ACCESS'],
            'general_manager': ['FULL_STUDENT_ACCESS', 'MANAGE_ATTENDANCE_ACCESS', 'PLAN_CURRICULUM_ACCESS'],
            'ceo': ['BASIC_STUDENT_ACCESS', 'EDIT_GRADES_ACCESS', 'FULL_STUDENT_ACCESS', 'MANAGE_ATTENDANCE_ACCESS', 'PLAN_CURRICULUM_ACCESS'],
        }
    },
    'Production': {
        'permissions': {
            'BASIC_PRODUCT_ACCESS': {'tier_req': 'tier1', 'category': 'product', 'level': 'basic'},
            'EDIT_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'product', 'level': 'edit_inventory'},
            'FULL_PRODUCT_ACCESS': {'tier_req': 'tier1', 'category': 'product', 'level': 'full'},
            'MANAGE_PRODUCTION_ACCESS': {'tier_req': 'tier2', 'category': 'production', 'level': 'manage'},
            'QUALITY_CONTROL_ACCESS': {'tier_req': 'tier2', 'category': 'quality', 'level': 'control'},
        },
        'roles': {
            'production_manager': ['FULL_PRODUCT_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_PRODUCTION_ACCESS'],
            'quality_control': ['BASIC_PRODUCT_ACCESS', 'QUALITY_CONTROL_ACCESS'],
            'operator': ['BASIC_PRODUCT_ACCESS', 'EDIT_INVENTORY_ACCESS'],
            'branch_manager': ['FULL_PRODUCT_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_PRODUCTION_ACCESS', 'QUALITY_CONTROL_ACCESS'],
            'general_manager': ['FULL_PRODUCT_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_PRODUCTION_ACCESS', 'QUALITY_CONTROL_ACCESS'],
            'ceo': ['BASIC_PRODUCT_ACCESS', 'EDIT_INVENTORY_ACCESS', 'FULL_PRODUCT_ACCESS', 'MANAGE_PRODUCTION_ACCESS', 'QUALITY_CONTROL_ACCESS'],
        }
    },
    'Technology': {
        'permissions': {
            'BASIC_CODE_ACCESS': {'tier_req': 'tier1', 'category': 'code', 'level': 'basic'},
            'EDIT_CODE_ACCESS': {'tier_req': 'tier1', 'category': 'code', 'level': 'edit'},
            'FULL_CODE_ACCESS': {'tier_req': 'tier1', 'category': 'code', 'level': 'full'},
            'MANAGE_PROJECTS_ACCESS': {'tier_req': 'tier2', 'category': 'project', 'level': 'manage'},
            'REVIEW_CODE_ACCESS': {'tier_req': 'tier2', 'category': 'review', 'level': 'review'},
        },
        'roles': {
            'developer': ['FULL_CODE_ACCESS'],
            'qa_tester': ['BASIC_CODE_ACCESS', 'REVIEW_CODE_ACCESS'],
            'project_manager': ['BASIC_CODE_ACCESS', 'EDIT_CODE_ACCESS', 'MANAGE_PROJECTS_ACCESS'],
            'branch_manager': ['FULL_CODE_ACCESS', 'MANAGE_PROJECTS_ACCESS', 'REVIEW_CODE_ACCESS'],
            'general_manager': ['FULL_CODE_ACCESS', 'MANAGE_PROJECTS_ACCESS', 'REVIEW_CODE_ACCESS'],
            'ceo': ['BASIC_CODE_ACCESS', 'EDIT_CODE_ACCESS', 'FULL_CODE_ACCESS', 'MANAGE_PROJECTS_ACCESS', 'REVIEW_CODE_ACCESS'],
        }
    },
    'Retail': {
        'permissions': {
            'BASIC_SALES_ACCESS': {'tier_req': 'tier1', 'category': 'sales', 'level': 'basic'},
            'EDIT_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'sales', 'level': 'edit_inventory'},
            'FULL_SALES_ACCESS': {'tier_req': 'tier1', 'category': 'sales', 'level': 'full'},
            'MANAGE_REPORTS_ACCESS': {'tier_req': 'tier2', 'category': 'report', 'level': 'manage'},
            'SUPPLIER_RELATIONS_ACCESS': {'tier_req': 'tier2', 'category': 'supplier', 'level': 'relations'},
        },
        'roles': {
            'sales_rep': ['BASIC_SALES_ACCESS'],
            'sales_manager': ['FULL_SALES_ACCESS', 'EDIT_INVENTORY_ACCESS'],
            'store_manager': ['FULL_SALES_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_REPORTS_ACCESS'],
            'branch_manager': ['FULL_SALES_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_REPORTS_ACCESS', 'SUPPLIER_RELATIONS_ACCESS'],
            'general_manager': ['FULL_SALES_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_REPORTS_ACCESS', 'SUPPLIER_RELATIONS_ACCESS'],
            'ceo': ['BASIC_SALES_ACCESS', 'EDIT_INVENTORY_ACCESS', 'FULL_SALES_ACCESS', 'MANAGE_REPORTS_ACCESS', 'SUPPLIER_RELATIONS_ACCESS'],
        }
    },
    'Agriculture': {
        'permissions': {
            'BASIC_CROP_ACCESS': {'tier_req': 'tier1', 'category': 'crop', 'level': 'basic'},
            'EDIT_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'crop', 'level': 'edit_inventory'},
            'FULL_CROP_ACCESS': {'tier_req': 'tier1', 'category': 'crop', 'level': 'full'},
            'MANAGE_FARM_ACCESS': {'tier_req': 'tier2', 'category': 'farm', 'level': 'manage'},
            'ANALYZE_MARKET_ACCESS': {'tier_req': 'tier2', 'category': 'market', 'level': 'analyze'},
        },
        'roles': {
            'farm_worker': ['BASIC_CROP_ACCESS', 'EDIT_INVENTORY_ACCESS'],
            'farm_manager': ['FULL_CROP_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_FARM_ACCESS'],
            'analyst': ['BASIC_CROP_ACCESS', 'ANALYZE_MARKET_ACCESS'],
            'branch_manager': ['FULL_CROP_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_FARM_ACCESS', 'ANALYZE_MARKET_ACCESS'],
            'general_manager': ['FULL_CROP_ACCESS', 'EDIT_INVENTORY_ACCESS', 'MANAGE_FARM_ACCESS', 'ANALYZE_MARKET_ACCESS'],
            'ceo': ['BASIC_CROP_ACCESS', 'EDIT_INVENTORY_ACCESS', 'FULL_CROP_ACCESS', 'MANAGE_FARM_ACCESS', 'ANALYZE_MARKET_ACCESS'],
        }
    },
    'Real Estate': {
        'permissions': {
            'BASIC_PROPERTY_ACCESS': {'tier_req': 'tier1', 'category': 'property', 'level': 'basic'},
            'EDIT_LISTINGS_ACCESS': {'tier_req': 'tier1', 'category': 'property', 'level': 'edit_listings'},
            'FULL_PROPERTY_ACCESS': {'tier_req': 'tier1', 'category': 'property', 'level': 'full'},
            'MANAGE_CLIENTS_ACCESS': {'tier_req': 'tier2', 'category': 'client', 'level': 'manage'},
            'INVESTMENT_ANALYSIS_ACCESS': {'tier_req': 'tier2', 'category': 'investment', 'level': 'analysis'},
        },
        'roles': {
            'agent': ['BASIC_PROPERTY_ACCESS', 'EDIT_LISTINGS_ACCESS'],
            'property_manager': ['FULL_PROPERTY_ACCESS', 'EDIT_LISTINGS_ACCESS', 'MANAGE_CLIENTS_ACCESS'],
            'analyst': ['BASIC_PROPERTY_ACCESS', 'INVESTMENT_ANALYSIS_ACCESS'],
            'branch_manager': ['FULL_PROPERTY_ACCESS', 'EDIT_LISTINGS_ACCESS', 'MANAGE_CLIENTS_ACCESS', 'INVESTMENT_ANALYSIS_ACCESS'],
            'general_manager': ['FULL_PROPERTY_ACCESS', 'EDIT_LISTINGS_ACCESS', 'MANAGE_CLIENTS_ACCESS', 'INVESTMENT_ANALYSIS_ACCESS'],
            'ceo': ['BASIC_PROPERTY_ACCESS', 'EDIT_LISTINGS_ACCESS', 'FULL_PROPERTY_ACCESS', 'MANAGE_CLIENTS_ACCESS', 'INVESTMENT_ANALYSIS_ACCESS'],
        }
    },
    'Supermarket': {
        'permissions': {
            'BASIC_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'inventory', 'level': 'basic'},
            'PROCESS_CHECKOUT_ACCESS': {'tier_req': 'tier1', 'category': 'inventory', 'level': 'process_checkout'},
            'FULL_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'inventory', 'level': 'full'},
            'MANAGE_SCHEDULE_ACCESS': {'tier_req': 'tier2', 'category': 'schedule', 'level': 'manage'},
            'OPTIMIZE_SUPPLY_ACCESS': {'tier_req': 'tier3', 'category': 'supply', 'level': 'optimize'},
        },
        'roles': {
            'cashier': ['BASIC_INVENTORY_ACCESS', 'PROCESS_CHECKOUT_ACCESS'],
            'stocker': ['FULL_INVENTORY_ACCESS'],
            'shift_manager': ['FULL_INVENTORY_ACCESS', 'PROCESS_CHECKOUT_ACCESS', 'MANAGE_SCHEDULE_ACCESS'],
            'branch_manager': ['FULL_INVENTORY_ACCESS', 'PROCESS_CHECKOUT_ACCESS', 'MANAGE_SCHEDULE_ACCESS', 'OPTIMIZE_SUPPLY_ACCESS'],
            'general_manager': ['FULL_INVENTORY_ACCESS', 'PROCESS_CHECKOUT_ACCESS', 'MANAGE_SCHEDULE_ACCESS', 'OPTIMIZE_SUPPLY_ACCESS'],
            'ceo': ['BASIC_INVENTORY_ACCESS', 'PROCESS_CHECKOUT_ACCESS', 'FULL_INVENTORY_ACCESS', 'MANAGE_SCHEDULE_ACCESS', 'OPTIMIZE_SUPPLY_ACCESS'],
        }
    },
    'Warehouse': {
        'permissions': {
            'BASIC_GOODS_ACCESS': {'tier_req': 'tier1', 'category': 'goods', 'level': 'basic'},
            'MOVE_GOODS_ACCESS': {'tier_req': 'tier1', 'category': 'goods', 'level': 'move'},
            'FULL_GOODS_ACCESS': {'tier_req': 'tier1', 'category': 'goods', 'level': 'full'},
            'MANAGE_INVENTORY_ACCESS': {'tier_req': 'tier2', 'category': 'inventory', 'level': 'manage'},
            'SUPERVISE_OPERATIONS_ACCESS': {'tier_req': 'tier3', 'category': 'operations', 'level': 'supervise'},
        },
        'roles': {
            'warehouse_worker': ['BASIC_GOODS_ACCESS', 'MOVE_GOODS_ACCESS'],
            'inventory_clerk': ['FULL_GOODS_ACCESS', 'MANAGE_INVENTORY_ACCESS'],
            'forklift_operator': ['BASIC_GOODS_ACCESS', 'MOVE_GOODS_ACCESS'],
            'branch_manager': ['FULL_GOODS_ACCESS', 'MOVE_GOODS_ACCESS', 'MANAGE_INVENTORY_ACCESS', 'SUPERVISE_OPERATIONS_ACCESS'],
            'general_manager': ['FULL_GOODS_ACCESS', 'MOVE_GOODS_ACCESS', 'MANAGE_INVENTORY_ACCESS', 'SUPERVISE_OPERATIONS_ACCESS'],
            'ceo': ['BASIC_GOODS_ACCESS', 'MOVE_GOODS_ACCESS', 'FULL_GOODS_ACCESS', 'MANAGE_INVENTORY_ACCESS', 'SUPERVISE_OPERATIONS_ACCESS'],
        }
    },
}

class IndustryPermissions:
    def __init__(self, config, industry_name):
        self.PERMISSIONS = config['permissions']
        self.ROLES = config['roles']
        # Set permission codename attributes in caps
        for perm_name in config['permissions']:
            codename = f"{industry_name.lower()}_{perm_name}"
            setattr(self, perm_name.upper(), codename)

class Permissions:
    finance = IndustryPermissions(PERMISSIONS_CONFIG['Finance'], 'Finance')
    healthcare = IndustryPermissions(PERMISSIONS_CONFIG['Healthcare'], 'Healthcare')
    education = IndustryPermissions(PERMISSIONS_CONFIG['Education'], 'Education')
    production = IndustryPermissions(PERMISSIONS_CONFIG['Production'], 'Production')
    technology = IndustryPermissions(PERMISSIONS_CONFIG['Technology'], 'Technology')
    retail = IndustryPermissions(PERMISSIONS_CONFIG['Retail'], 'Retail')
    agriculture = IndustryPermissions(PERMISSIONS_CONFIG['Agriculture'], 'Agriculture')
    real_estate = IndustryPermissions(PERMISSIONS_CONFIG['Real Estate'], 'Real Estate')
    supermarket = IndustryPermissions(PERMISSIONS_CONFIG['Supermarket'], 'Supermarket')
    warehouse = IndustryPermissions(PERMISSIONS_CONFIG['Warehouse'], 'Warehouse')

    @staticmethod
    def get_codename(industry, perm_name):
        return f"{industry.lower()}_{perm_name}"

    @staticmethod
    def get_all_permissions(industry):
        config = PERMISSIONS_CONFIG.get(industry.capitalize())
        if not config:
            return []
        return [f"{industry.lower()}_{p}" for p in config['permissions']]

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

# Generate ROLES_BY_INDUSTRY from config
ROLES_BY_INDUSTRY = {}
for industry, config in PERMISSIONS_CONFIG.items():
    ROLES_BY_INDUSTRY[industry] = {}
    for role_name, permissions in config['roles'].items():
        # Find the highest tier requirement among the role's permissions
        tier_req = 'tier1'  # default
        for perm in permissions:
            if perm in config['permissions']:
                perm_tier = config['permissions'][perm]['tier_req']
                if perm_tier > tier_req:
                    tier_req = perm_tier
        ROLES_BY_INDUSTRY[industry][role_name] = {'tier_req': tier_req, 'default_perms': permissions}



