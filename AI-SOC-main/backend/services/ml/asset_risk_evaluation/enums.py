"""
Enhanced Enums for Asset Risk Evaluation

Comprehensive asset types, industries, and data classifications.
"""

from enum import Enum


class ComprehensiveAssetType(Enum):
    """
    Comprehensive asset type classification (25 types).
    
    Expanded from original 6 types to cover all infrastructure categories.
    """
    
    # Compute Infrastructure (6)
    PHYSICAL_SERVER = "physical_server"
    VIRTUAL_SERVER = "virtual_server"
    CONTAINER = "container"
    SERVERLESS_FUNCTION = "serverless_function"
    MAINFRAME = "mainframe"
    HYPERVISOR = "hypervisor"
    
    # Endpoints (4)
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    MOBILE_DEVICE = "mobile_device"
    THIN_CLIENT = "thin_client"
    
    # Network Infrastructure (6)
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    VPN_GATEWAY = "vpn_gateway"
    WIRELESS_ACCESS_POINT = "wireless_ap"
    
    # Data Infrastructure (4)
    DATABASE_SERVER = "database_server"
    DATA_WAREHOUSE = "data_warehouse"
    FILE_SERVER = "file_server"
    BACKUP_SERVER = "backup_server"
    
    # Security Infrastructure (3)
    IDS_IPS = "ids_ips"
    SIEM = "siem"
    PKI_CA = "pki_ca"
    
    # Cloud Resources (5)
    CLOUD_VM = "cloud_vm"
    CLOUD_STORAGE = "cloud_storage"
    CLOUD_DATABASE = "cloud_database"
    CLOUD_FUNCTION = "cloud_function"
    KUBERNETES_CLUSTER = "k8s_cluster"
    
    # Application Infrastructure (4)
    WEB_SERVER = "web_server"
    APPLICATION_SERVER = "application_server"
    API_GATEWAY = "api_gateway"
    MESSAGE_QUEUE = "message_queue"
    
    # IoT & OT (3)
    IOT_DEVICE = "iot_device"
    SCADA_HMI = "scada_hmi"
    PLC = "plc"
    
    # Other (2)
    PRINTER = "printer"
    UNKNOWN = "unknown"


class Industry(Enum):
    """
    Comprehensive industry classification (30 industries).
    
    Expanded for comprehensive threat intelligence correlation.
    """
    
    # Financial Services (5)
    BANKING = "banking"
    INSURANCE = "insurance"
    INVESTMENT = "investment"
    PAYMENTS = "payments"
    FINTECH = "fintech"
    
    # Healthcare (3)
    HEALTHCARE_PROVIDER = "healthcare_provider"
    PHARMACEUTICALS = "pharmaceuticals"
    MEDICAL_DEVICES = "medical_devices"
    
    # Technology (4)
    SOFTWARE_SAAS = "software_saas"
    TELECOMMUNICATIONS = "telecommunications"
    IT_SERVICES = "it_services"
    CYBERSECURITY = "cybersecurity"
    
    # Retail & E-commerce (3)
    RETAIL = "retail"
    ECOMMERCE = "ecommerce"
    HOSPITALITY = "hospitality"
    
    # Manufacturing & Industrial (4)
    MANUFACTURING = "manufacturing"
    AUTOMOTIVE = "automotive"
    AEROSPACE = "aerospace"
    ENERGY_UTILITIES = "energy_utilities"
    
    # Government & Defense (2)
    GOVERNMENT = "government"
    DEFENSE = "defense"
    
    # Education & Research (2)
    EDUCATION = "education"
    RESEARCH = "research"
    
    # Media & Entertainment (3)
    MEDIA = "media"
    ENTERTAINMENT = "entertainment"
    GAMING = "gaming"
    
    # Other (4)
    LEGAL = "legal"
    CONSULTING = "consulting"
    TRANSPORTATION = "transportation"
    NONPROFIT = "nonprofit"


class Criticality(Enum):
    """Asset criticality levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataClassification(Enum):
    """Data classification levels."""
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
