"""
Cross-verification: Compare compliance_rules_full.json against the canonical
290-control list and reversibility_db_full.json against the 240-action list.
"""
import json
from collections import defaultdict

# ── 1. Load our JSON databases ─────────────────────────────────────────────
with open("compliance_rules_full.json") as f:
    rules = json.load(f)

with open("reversibility_db_full.json") as f:
    actions = json.load(f)

written_control_ids = set(r["control_id"] for r in rules)
written_action_types = set(a["action_type"] for a in actions)

# ── 2. Canonical 290 controls listed in the reference doc ─────────────────
# (keyed as control_id → framework)  — extracted from the reference markdown

CANONICAL_CONTROLS = {
    # PCI-DSS v4 (35)
    "10.2.1": "pci_dss", "10.2.2": "pci_dss", "10.2.4": "pci_dss", "10.2.5": "pci_dss",
    "10.2.6": "pci_dss", "10.2.7": "pci_dss", "10.5.1": "pci_dss", "10.7.2": "pci_dss",
    "10.7.3": "pci_dss", "11.4.7": "pci_dss", "12.10.1": "pci_dss", "12.10.2": "pci_dss",
    "12.10.4": "pci_dss", "12.10.5": "pci_dss", "12.10.6": "pci_dss", "12.10.7": "pci_dss",
    "6.3.3": "pci_dss", "6.4.3": "pci_dss", "7.1.1": "pci_dss", "7.2.5": "pci_dss",
    "7.2.6": "pci_dss", "8.2.6": "pci_dss", "8.2.8": "pci_dss", "8.3.10": "pci_dss",
    "3.4": "pci_dss", "3.5.1": "pci_dss", "4.2": "pci_dss", "5.2.1": "pci_dss",
    "5.3.2": "pci_dss", "9.9.1": "pci_dss", "9.9.3": "pci_dss", "1.4.1": "pci_dss",
    "1.4.5": "pci_dss", "2.2.7": "pci_dss", "2.3.2": "pci_dss",

    # GDPR (45)
    "Art. 33(1)": "gdpr", "Art. 33(2)": "gdpr", "Art. 33(3)(a)": "gdpr", "Art. 33(3)(b)": "gdpr",
    "Art. 33(3)(c)": "gdpr", "Art. 33(5)": "gdpr", "Art. 34(1)": "gdpr", "Art. 34(3)(a)": "gdpr",
    "Art. 32(1)(a)": "gdpr", "Art. 32(1)(b)": "gdpr", "Art. 32(1)(c)": "gdpr", "Art. 32(1)(d)": "gdpr",
    "Art. 32(2)": "gdpr", "Art. 25(1)": "gdpr", "Art. 25(2)": "gdpr", "Art. 5(1)(e)": "gdpr",
    "Art. 5(1)(f)": "gdpr", "Art. 6": "gdpr", "Art. 9": "gdpr", "Art. 15": "gdpr",
    "Art. 17": "gdpr", "Art. 18": "gdpr", "Art. 20": "gdpr", "Art. 21": "gdpr",
    "Art. 35": "gdpr", "Art. 37": "gdpr", "Art. 44": "gdpr", "Art. 46": "gdpr",
    "Recital 49": "gdpr", "Recital 75": "gdpr", "Recital 83": "gdpr", "Recital 87": "gdpr",
    "Art. 30": "gdpr", "Art. 24": "gdpr", "Art. 28": "gdpr", "Art. 47": "gdpr",
    "Art. 58": "gdpr", "Art. 77": "gdpr", "Art. 82": "gdpr", "Art. 83": "gdpr",
    "Art. 12": "gdpr", "Art. 13": "gdpr", "Art. 14": "gdpr", "Art. 38": "gdpr",
    "Art. 40": "gdpr",

    # HIPAA (28)
    "§164.312(a)(1)": "hipaa", "§164.312(a)(2)(i)": "hipaa", "§164.312(a)(2)(ii)": "hipaa",
    "§164.312(a)(2)(iii)": "hipaa", "§164.312(a)(2)(iv)": "hipaa", "§164.312(b)": "hipaa",
    "§164.312(c)(1)": "hipaa", "§164.312(c)(2)": "hipaa", "§164.312(d)": "hipaa",
    "§164.312(e)(1)": "hipaa", "§164.312(e)(2)(i)": "hipaa", "§164.312(e)(2)(ii)": "hipaa",
    "§164.308(a)(1)(i)": "hipaa", "§164.308(a)(1)(ii)(A)": "hipaa", "§164.308(a)(1)(ii)(B)": "hipaa",
    "§164.308(a)(1)(ii)(C)": "hipaa", "§164.308(a)(1)(ii)(D)": "hipaa", "§164.308(a)(6)(i)": "hipaa",
    "§164.308(a)(6)(ii)": "hipaa", "§164.308(a)(7)(i)": "hipaa", "§164.308(a)(7)(ii)(A)": "hipaa",
    "§164.308(a)(7)(ii)(B)": "hipaa", "§164.308(a)(7)(ii)(C)": "hipaa", "§164.308(a)(7)(ii)(D)": "hipaa",
    "§164.308(a)(7)(ii)(E)": "hipaa", "§164.310(a)(1)": "hipaa", "§164.310(d)(1)": "hipaa",
    "§164.316(b)(2)(i)": "hipaa",

    # ISO 27001 (32)
    "A.5.24": "iso_27001", "A.5.25": "iso_27001", "A.5.26": "iso_27001", "A.5.27": "iso_27001",
    "A.5.28": "iso_27001", "A.16.1.5": "iso_27001", "A.16.1.6": "iso_27001", "A.16.1.7": "iso_27001",
    "A.8.15": "iso_27001", "A.8.16": "iso_27001", "A.8.17": "iso_27001", "A.5.33": "iso_27001",
    "A.5.34": "iso_27001", "A.5.10": "iso_27001", "A.8.2": "iso_27001", "A.8.3": "iso_27001",
    "A.8.5": "iso_27001", "A.8.10": "iso_27001", "A.8.11": "iso_27001", "A.8.12": "iso_27001",
    "A.8.13": "iso_27001", "A.8.14": "iso_27001", "A.7.2": "iso_27001", "A.7.4": "iso_27001",
    "A.6.8": "iso_27001", "A.8.25": "iso_27001", "A.8.26": "iso_27001", "A.8.28": "iso_27001",
    "A.8.32": "iso_27001", "A.5.23": "iso_27001", "A.5.30": "iso_27001", "A.8.6": "iso_27001",

    # NIST 800-53 (42)
    "IR-1": "nist_800_53", "IR-2": "nist_800_53", "IR-3": "nist_800_53", "IR-4": "nist_800_53",
    "IR-5": "nist_800_53", "IR-6": "nist_800_53", "IR-7": "nist_800_53", "IR-8": "nist_800_53",
    "IR-9": "nist_800_53", "IR-10": "nist_800_53", "AU-2": "nist_800_53", "AU-3": "nist_800_53",
    "AU-4": "nist_800_53", "AU-6": "nist_800_53", "AU-9": "nist_800_53", "AU-11": "nist_800_53",
    "AU-12": "nist_800_53", "SI-3": "nist_800_53", "SI-4": "nist_800_53", "SI-5": "nist_800_53",
    "SI-7": "nist_800_53", "SI-12": "nist_800_53", "AC-2": "nist_800_53", "AC-3": "nist_800_53",
    "AC-4": "nist_800_53", "AC-6": "nist_800_53", "AC-17": "nist_800_53", "CM-3": "nist_800_53",
    "CM-5": "nist_800_53", "CP-2": "nist_800_53", "CP-4": "nist_800_53", "CP-9": "nist_800_53",
    "CP-10": "nist_800_53", "RA-3": "nist_800_53", "RA-5": "nist_800_53", "SA-11": "nist_800_53",
    "SC-7": "nist_800_53", "SC-8": "nist_800_53", "SC-12": "nist_800_53", "SC-13": "nist_800_53",
    "SC-28": "nist_800_53", "PE-3": "nist_800_53",

    # SOC 2 (18)
    "CC6.1": "soc2", "CC6.2": "soc2", "CC6.3": "soc2", "CC6.6": "soc2", "CC6.7": "soc2",
    "CC7.1": "soc2", "CC7.2": "soc2", "CC7.3": "soc2", "CC7.4": "soc2", "CC7.5": "soc2",
    "CC8.1": "soc2", "CC9.1": "soc2", "A1.1": "soc2", "A1.2": "soc2", "A1.3": "soc2",
    "C1.1": "soc2", "C1.2": "soc2", "PI1.4": "soc2",

    # CIS v8 (25)
    "17.1": "cis_v8", "17.2": "cis_v8", "17.3": "cis_v8", "17.4": "cis_v8", "17.5": "cis_v8",
    "17.6": "cis_v8", "17.7": "cis_v8", "17.8": "cis_v8", "17.9": "cis_v8",
    "8.1": "cis_v8", "8.2": "cis_v8", "8.3": "cis_v8", "8.5": "cis_v8", "8.10": "cis_v8",
    "8.11": "cis_v8", "6.1": "cis_v8", "6.2": "cis_v8", "6.5": "cis_v8", "6.8": "cis_v8",
    "5.1": "cis_v8", "5.2": "cis_v8", "5.3": "cis_v8", "10.1": "cis_v8", "11.1": "cis_v8",
    "11.5": "cis_v8",

    # SEBI-CSCRF (15)
    "4.1.1": "sebi", "4.1.2": "sebi", "4.1.3": "sebi", "4.1.4": "sebi", "4.2.1": "sebi",
    "4.2.2": "sebi", "4.2.3": "sebi", "4.3.1": "sebi", "4.3.2": "sebi", "4.3.3": "sebi",
    "4.4.1": "sebi", "4.4.2": "sebi", "4.4.3": "sebi", "4.5.1": "sebi", "4.5.2": "sebi",

    # DPDP (12)
    "Sec 8(1)": "dpdp", "Sec 8(2)": "dpdp", "Sec 8(3)": "dpdp", "Sec 8(4)": "dpdp",
    "Sec 8(5)": "dpdp", "Sec 8(6)": "dpdp", "Sec 10": "dpdp", "Sec 11": "dpdp",
    "Sec 12": "dpdp", "Sec 6": "dpdp", "Sec 7": "dpdp", "Sec 9": "dpdp",

    # ISO 42001 (20)
    "8.1.1": "iso_42001", "8.1.2": "iso_42001", "8.1.3": "iso_42001",
    "7.2.1": "iso_42001", "7.2.2": "iso_42001", "7.2.3": "iso_42001",
    "8.2.1": "iso_42001", "8.2.2": "iso_42001", "8.2.3": "iso_42001",
    "6.2.1": "iso_42001", "6.2.2": "iso_42001", "6.2.3": "iso_42001",
    "9.1.1": "iso_42001", "9.1.2": "iso_42001", "9.1.3": "iso_42001",
    "5.1.1": "iso_42001", "5.1.2": "iso_42001", "7.3.1": "iso_42001",
    "7.3.2": "iso_42001", "10.1.1": "iso_42001",

    # NIST CSF 2.0 (18)
    "DE.AE-1": "nist_csf", "DE.AE-2": "nist_csf", "DE.AE-3": "nist_csf",
    "DE.CM-1": "nist_csf", "DE.CM-7": "nist_csf", "RS.RP-1": "nist_csf",
    "RS.CO-2": "nist_csf", "RS.CO-3": "nist_csf", "RS.AN-1": "nist_csf",
    "RS.AN-2": "nist_csf", "RS.AN-3": "nist_csf", "RS.MI-1": "nist_csf",
    "RS.MI-2": "nist_csf", "RS.IM-1": "nist_csf", "RC.RP-1": "nist_csf",
    "RC.IM-1": "nist_csf", "RC.CO-3": "nist_csf", "ID.SC-4": "nist_csf",
}

# ── 3. Canonical 240 actions ────────────────────────────────────────────────
CANONICAL_ACTIONS = [
    # Network (25)
    "block_ip","block_ip_range","block_subnet","unblock_ip","block_domain","block_url","block_port",
    "block_protocol","isolate_host","isolate_network_segment","disconnect_network","move_to_quarantine_vlan",
    "enable_network_tap","enable_ips_mode","block_dns_query","poison_dns_cache","null_route_ip",
    "rate_limit_ip","rate_limit_endpoint","capture_network_traffic","enable_netflow","mirror_traffic",
    "deploy_network_sensor","enable_ssl_inspection","update_firewall_rules",
    # Cloud AWS (20)
    "revoke_iam_role","delete_iam_user","disable_iam_user","rotate_access_keys","delete_access_key",
    "revoke_sts_token","detach_iam_policy","remove_from_iam_group","enable_mfa_requirement",
    "delete_compromised_role","terminate_ec2_instance","stop_ec2_instance","isolate_ec2_instance",
    "snapshot_ec2_volume","detach_ec2_volume","delete_ami","deregister_ami","terminate_lambda_function",
    "disable_lambda_trigger","block_s3_public_access",
    # Cloud Multi (20)
    "delete_s3_bucket_policy","enable_s3_versioning","enable_s3_object_lock","revoke_s3_bucket_access",
    "delete_s3_bucket","quarantine_s3_object","modify_security_group","delete_security_group_rule",
    "isolate_vpc","delete_vpc_endpoint","disable_vpc_peering","revoke_gcp_service_account",
    "delete_gcp_instance","disable_gcp_api","revoke_gcp_iam_binding","revoke_azure_ad_token",
    "disable_azure_vm","revoke_azure_rbac","delete_azure_resource","snapshot_cloud_resource",
    # Container/K8s (30)
    "stop_container","kill_container","remove_container","pause_container","isolate_container_network",
    "limit_container_resources","delete_container_image","block_container_registry","scan_container_image",
    "quarantine_container_image","delete_pod","delete_deployment","delete_service","isolate_namespace",
    "revoke_service_account","delete_secret","delete_configmap","scale_deployment_to_zero","cordon_node",
    "drain_node","delete_ingress","revoke_rbac_binding","apply_network_policy","delete_persistent_volume_claim",
    "disable_admission_webhook","enable_container_runtime_protection","scan_running_containers",
    "enforce_pod_security_policy","enable_seccomp_profile","enable_apparmor_profile",
    # IAM (35)
    "disable_account","lock_account","delete_account","suspend_account","force_logout",
    "force_logout_all_sessions","revoke_all_sessions","reset_password","expire_password",
    "require_password_change","enable_mfa","require_mfa_reauthentication","revoke_mfa_device",
    "revoke_permissions","remove_from_group","revoke_role","downgrade_privileges","revoke_admin_rights",
    "revoke_api_token","revoke_oauth_token","revoke_jwt_token","invalidate_refresh_token",
    "rotate_service_account_key","revoke_certificate","revoke_ssh_key","disable_sso","revoke_saml_assertion",
    "disable_ldap_bind","revoke_kerberos_ticket","enable_privileged_access_management",
    "require_just_in_time_access","enable_session_recording","force_password_reset_all_users",
    "rotate_all_service_credentials","grant_access",
    # Endpoint/EDR (30)
    "trigger_edr_isolate","trigger_edr_contain","trigger_edr_scan","trigger_edr_remediate",
    "collect_edr_forensics","kill_process","kill_process_tree","suspend_process","block_executable",
    "quarantine_executable","quarantine_file","delete_file","restore_file_from_backup","revert_file_changes",
    "lock_file","delete_registry_key","restore_registry_backup","block_registry_modification",
    "reboot_system","shutdown_system","enable_safe_mode","restore_system_snapshot","rollback_system_update",
    "capture_memory_dump","capture_disk_image","collect_volatile_data","enable_kernel_logging",
    "enable_application_whitelisting","block_usb_devices","disable_autorun",
    # Data Protection (25)
    "enable_encryption_at_rest","enable_encryption_in_transit","rotate_encryption_keys","revoke_encryption_key",
    "enable_dlp_policy","block_data_exfiltration","revoke_data_access","classify_sensitive_data",
    "create_backup","restore_from_backup","enable_versioning","create_snapshot","restore_snapshot",
    "anonymize_data","pseudonymize_data","delete_data","shred_data","revoke_share_link",
    "disable_public_sharing","enable_access_logging","require_data_approval","watermark_document",
    "encrypt_data","decrypt_data","secure_data_deletion",
    # Application/API (25)
    "rate_limit_api","block_api_endpoint","revoke_api_key","rotate_api_secret","disable_api_version",
    "enable_api_authentication","enable_waf_rule","block_waf_signature","enable_bot_protection",
    "challenge_with_captcha","block_user_agent","block_http_method","restart_application",
    "rollback_application_version","enable_maintenance_mode","disable_feature_flag","disable_webhook",
    "revoke_integration_token","disable_third_party_integration","invalidate_application_cache",
    "clear_session_store","revoke_application_token","block_dependency_download",
    "quarantine_malicious_package","revert_code_deployment",
    # DB/Email/Forensics/Notification (30)
    "revoke_database_user","revoke_database_privileges","disable_database_login","rotate_database_password",
    "stop_database_service","create_database_backup","restore_database_backup","quarantine_email",
    "delete_email","recall_email","block_sender","block_email_domain","collect_logs",
    "collect_network_pcap","collect_process_dump","preserve_evidence","create_forensic_snapshot",
    "calculate_file_hash","analyze_malware_sample","perform_timeline_analysis","extract_iocs",
    "correlate_events","notify_security_team","notify_incident_commander","escalate_to_manager",
    "notify_affected_users","create_breach_notification","notify_data_protection_authority",
    "create_ticket","document_incident",
]

# ── 4. Control gap analysis ─────────────────────────────────────────────────
missing_controls = {}
for ctrl_id, fw in CANONICAL_CONTROLS.items():
    if ctrl_id not in written_control_ids:
        missing_controls.setdefault(fw, []).append(ctrl_id)

# ── 5. Action gap analysis ─────────────────────────────────────────────────
canonical_action_set = set(CANONICAL_ACTIONS)
missing_actions = sorted(canonical_action_set - written_action_types)
extra_actions = sorted(written_action_types - canonical_action_set)

# ── 6. Report ─────────────────────────────────────────────────────────────
print("=" * 70)
print("CROSS-VERIFICATION REPORT")
print("=" * 70)

print(f"\n📋 CONTROLS")
print(f"  Canonical controls required:   {len(CANONICAL_CONTROLS)}")
print(f"  Written control_ids in JSON:   {len(written_control_ids)}")
print(f"  Missing from our JSONs:        {sum(len(v) for v in missing_controls.values())}")

if missing_controls:
    print("\n  ⛔ MISSING CONTROLS BY FRAMEWORK:")
    for fw, cids in sorted(missing_controls.items()):
        print(f"    [{fw}]  {len(cids)} missing:")
        for c in cids:
            print(f"      - {c}")
else:
    print("  ✅ All canonical control IDs are covered!")

print(f"\n⚡ ACTIONS")
print(f"  Canonical actions required:    {len(canonical_action_set)}")
print(f"  Written in reversibility DB:   {len(written_action_types)}")
print(f"  Missing from reversibility DB: {len(missing_actions)}")
print(f"  Extra (not in reference list): {len(extra_actions)}")

if missing_actions:
    print("\n  ⛔ MISSING ACTIONS (need entries in reversibility_db):")
    for a in missing_actions:
        print(f"    - {a}")

if extra_actions:
    print("\n  ℹ️  EXTRA ACTIONS (in our DB but not in reference list — OK to keep):")
    for a in extra_actions:
        print(f"    - {a}")
