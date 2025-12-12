import uuid
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.cache import cache

# Organized Permissions Configuration
PERMISSIONS_CONFIG = {
    'Finance': {
        'permissions': {
            'BASIC_INCOME_ACCESS': {'tier_req': 'tier1', 'category': 'income'},
            'CREATE_INCOME_ACCESS': {'tier_req': 'tier1', 'category': 'income'},
            'FULL_INCOME_ACCESS': {'tier_req': 'tier1', 'category': 'income'},
            'BASIC_EXPENSE_ACCESS': {'tier_req': 'tier1', 'category': 'expense'},
            'CREATE_EXPENSE_ACCESS': {'tier_req': 'tier1', 'category': 'expense'},
            'FULL_EXPENSE_ACCESS': {'tier_req': 'tier1', 'category': 'expense'},
            'BASIC_REPORT_ACCESS': {'tier_req': 'tier1', 'category': 'report'},
        },
        'roles': {
            'accountant': ['FULL_INCOME_ACCESS', 'FULL_EXPENSE_ACCESS', 'BASIC_REPORT_ACCESS'],
            'auditor': ['FULL_INCOME_ACCESS', 'FULL_EXPENSE_ACCESS', 'BASIC_REPORT_ACCESS'],
            'branch_manager': ['FULL_INCOME_ACCESS', 'FULL_EXPENSE_ACCESS', 'BASIC_REPORT_ACCESS'],
            'general_manager': ['FULL_INCOME_ACCESS', 'FULL_EXPENSE_ACCESS', 'BASIC_REPORT_ACCESS'],
            'ceo': ['FULL_INCOME_ACCESS', 'FULL_EXPENSE_ACCESS', 'BASIC_REPORT_ACCESS'],
        }
    },
    'Healthcare': {
        'permissions': {
            'BASIC_PATIENT_ACCESS': {'tier_req': 'tier1', 'category': 'patient'},
            'FULL_PATIENT_ACCESS': {'tier_req': 'tier1', 'category': 'patient'},
            'EDIT_DIAGNOSIS_ACCESS': {'tier_req': 'tier1', 'category': 'patient'},
            'MANAGE_SCHEDULE_ACCESS': {'tier_req': 'tier2', 'category': 'schedule'},
            'PHARMACY_ACCESS': {'tier_req': 'tier2', 'category': 'pharmacy'},
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
            'BASIC_STUDENT_ACCESS': {'tier_req': 'tier1', 'category': 'student'},
            'EDIT_GRADES_ACCESS': {'tier_req': 'tier1', 'category': 'student'},
            'FULL_STUDENT_ACCESS': {'tier_req': 'tier1', 'category': 'student'},
            'MANAGE_ATTENDANCE_ACCESS': {'tier_req': 'tier2', 'category': 'attendance'},
            'PLAN_CURRICULUM_ACCESS': {'tier_req': 'tier2', 'category': 'curriculum'},
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
            'BASIC_PRODUCT_ACCESS': {'tier_req': 'tier1', 'category': 'product'},
            'EDIT_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'product'},
            'FULL_PRODUCT_ACCESS': {'tier_req': 'tier1', 'category': 'product'},
            'MANAGE_PRODUCTION_ACCESS': {'tier_req': 'tier2', 'category': 'production'},
            'QUALITY_CONTROL_ACCESS': {'tier_req': 'tier2', 'category': 'quality'},
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
            'BASIC_CODE_ACCESS': {'tier_req': 'tier1', 'category': 'code'},
            'EDIT_CODE_ACCESS': {'tier_req': 'tier1', 'category': 'code'},
            'FULL_CODE_ACCESS': {'tier_req': 'tier1', 'category': 'code'},
            'MANAGE_PROJECTS_ACCESS': {'tier_req': 'tier2', 'category': 'project'},
            'REVIEW_CODE_ACCESS': {'tier_req': 'tier2', 'category': 'review'},
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
            'BASIC_SALES_ACCESS': {'tier_req': 'tier1', 'category': 'sales'},
            'EDIT_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'sales'},
            'FULL_SALES_ACCESS': {'tier_req': 'tier1', 'category': 'sales'},
            'MANAGE_REPORTS_ACCESS': {'tier_req': 'tier2', 'category': 'report'},
            'SUPPLIER_RELATIONS_ACCESS': {'tier_req': 'tier2', 'category': 'supplier'},
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
            'BASIC_CROP_ACCESS': {'tier_req': 'tier1', 'category': 'crop'},
            'EDIT_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'crop'},
            'FULL_CROP_ACCESS': {'tier_req': 'tier1', 'category': 'crop'},
            'MANAGE_FARM_ACCESS': {'tier_req': 'tier2', 'category': 'farm'},
            'ANALYZE_MARKET_ACCESS': {'tier_req': 'tier2', 'category': 'market'},
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
            'BASIC_PROPERTY_ACCESS': {'tier_req': 'tier1', 'category': 'property'},
            'EDIT_LISTINGS_ACCESS': {'tier_req': 'tier1', 'category': 'property'},
            'FULL_PROPERTY_ACCESS': {'tier_req': 'tier1', 'category': 'property'},
            'MANAGE_CLIENTS_ACCESS': {'tier_req': 'tier2', 'category': 'client'},
            'INVESTMENT_ANALYSIS_ACCESS': {'tier_req': 'tier2', 'category': 'investment'},
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
            'BASIC_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'inventory'},
            'PROCESS_CHECKOUT_ACCESS': {'tier_req': 'tier1', 'category': 'inventory'},
            'FULL_INVENTORY_ACCESS': {'tier_req': 'tier1', 'category': 'inventory'},
            'MANAGE_SCHEDULE_ACCESS': {'tier_req': 'tier2', 'category': 'schedule'},
            'OPTIMIZE_SUPPLY_ACCESS': {'tier_req': 'tier3', 'category': 'supply'},
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
            'BASIC_GOODS_ACCESS': {'tier_req': 'tier1', 'category': 'goods'},
            'MOVE_GOODS_ACCESS': {'tier_req': 'tier1', 'category': 'goods'},
            'FULL_GOODS_ACCESS': {'tier_req': 'tier1', 'category': 'goods'},
            'MANAGE_INVENTORY_ACCESS': {'tier_req': 'tier2', 'category': 'inventory'},
            'SUPERVISE_OPERATIONS_ACCESS': {'tier_req': 'tier3', 'category': 'operations'},
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
    # Removed loan_officer as it's not needed for basic finance microservice
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



