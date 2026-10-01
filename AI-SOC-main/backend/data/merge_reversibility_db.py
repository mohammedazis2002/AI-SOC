#!/usr/bin/env python3
"""
Merge all reversibility JSON files into reversibility_db_full.json.
Run from: soar-platform/backend/data/
Usage: python merge_reversibility_db.py
"""
import json
from pathlib import Path
from collections import Counter

DATA_DIR = Path(__file__).parent

# Existing base DB + 6 new expansion files
REVERSIBILITY_FILES = [
    "reversibility_db_full.json",               # existing 108 actions (base)
    "reversibility_cloud_aws_multi.json",        # +32 cloud actions
    "reversibility_container_k8s.json",          # +18 container/k8s actions
    "reversibility_identity_access.json",         # +17 identity actions
    "reversibility_data_protection.json",         # +21 data protection actions
    "reversibility_application_api.json",         # +21 app/api actions
    "reversibility_network_forensics_misc.json",  # +44 network/forensics/misc actions
    "reversibility_final_5.json",                 # +5 final missing canonical actions
]

# Canonical 240 actions from reference document
CANONICAL_ACTIONS = {
    # Network
    "block_ip","unblock_ip","block_domain","enable_netflow","enable_network_tap",
    "deploy_network_sensor","mirror_traffic","block_protocol","poison_dns_cache",
    "enable_ssl_inspection","block_data_exfiltration","update_firewall_rules",
    "block_email_domain","block_api_endpoint","block_http_method","block_user_agent",
    "block_waf_signature","block_registry_modification","block_container_registry",
    "block_dependency_download","rate_limit_endpoint","challenge_with_captcha",
    # Identity/Access
    "disable_account","disable_mfa","enable_mfa","reset_password","revoke_permissions",
    "suspend_account","remove_from_group","revoke_all_sessions","revoke_api_key",
    "revoke_certificate","revoke_mfa_device","require_password_change",
    "require_mfa_reauthentication","require_just_in_time_access","grant_access",
    "revoke_role","revoke_data_access","revoke_database_privileges","revoke_service_account",
    "disable_database_login","disable_ldap_bind","revoke_integration_token","revoke_jwt_token",
    "revoke_saml_assertion","revoke_application_token","revoke_share_link",
    "rotate_api_secret","rotate_all_service_credentials","rotate_access_keys",
    "delete_access_key","revoke_sts_token","detach_iam_policy","remove_from_iam_group",
    "enable_mfa_requirement","delete_compromised_role","disable_iam_user","delete_iam_user",
    "revoke_gcp_iam_binding","revoke_azure_rbac","revoke_gcp_service_account",
    "enable_privileged_access_management","enable_session_recording",
    # Endpoint
    "isolate_host","trigger_edr_scan","trigger_edr_contain","trigger_edr_remediate",
    "quarantine_file","update_threat_signatures","patch_system","rollback_system_update",
    "disable_autorun","disable_usb","restore_file_from_backup","restore_registry_backup",
    "disable_feature_flag","restart_application","revert_code_deployment",
    # Email
    "recall_email","delete_email","block_email_domain",
    # File System
    "delete_logs","preserve_evidence","calculate_file_hash","collect_logs",
    "restore_from_backup","create_backup","secure_data_deletion","delete_data","shred_data",
    "watermark_document","create_forensic_snapshot","create_snapshot","restore_snapshot",
    # Cloud AWS
    "rotate_access_keys","delete_access_key","revoke_sts_token","detach_iam_policy",
    "remove_from_iam_group","enable_mfa_requirement","delete_compromised_role",
    "disable_iam_user","delete_iam_user","isolate_ec2_instance","detach_ec2_volume",
    "delete_ami","deregister_ami","terminate_lambda_function","disable_lambda_trigger",
    "block_s3_public_access","delete_s3_bucket_policy","enable_s3_versioning",
    "revoke_s3_bucket_access","quarantine_s3_object","delete_security_group_rule",
    "isolate_vpc","delete_vpc_endpoint","disable_vpc_peering","snapshot_cloud_resource",
    # Cloud Multi
    "delete_gcp_instance","disable_gcp_api","revoke_gcp_iam_binding","revoke_gcp_service_account",
    "revoke_azure_ad_token","disable_azure_vm","revoke_azure_rbac","delete_azure_resource",
    "enable_access_logging","enable_versioning",
    # Container/K8s
    "remove_container","pause_container","isolate_container_network","limit_container_resources",
    "delete_container_image","block_container_registry","scan_container_image","delete_service",
    "delete_secret","delete_configmap","delete_ingress","revoke_rbac_binding",
    "delete_persistent_volume_claim","disable_admission_webhook",
    "enable_container_runtime_protection","scan_running_containers",
    "enable_seccomp_profile","enable_apparmor_profile",
    # Data Protection
    "encrypt_data","decrypt_data","anonymize_data","pseudonymize_data",
    "classify_sensitive_data","watermark_document","enable_dlp_policy","secure_data_deletion",
    "delete_data","shred_data","enable_encryption_at_rest","enable_encryption_in_transit",
    "rotate_encryption_keys","revoke_encryption_key","require_data_approval",
    "disable_public_sharing","create_breach_notification","enable_access_logging",
    "enable_versioning","invalidate_application_cache","invalidate_refresh_token",
    # Application/API
    "block_api_endpoint","block_http_method","block_user_agent","block_waf_signature",
    "enable_bot_protection","rate_limit_endpoint","block_protocol",
    "enable_api_authentication","challenge_with_captcha","revert_code_deployment",
    "restart_application","enable_session_recording","enable_maintenance_mode",
    "disable_feature_flag","block_dependency_download","disable_webhook",
    "disable_third_party_integration","quarantine_malicious_package",
    "enable_privileged_access_management","block_registry_modification",
    "enable_kernel_logging",
    # Forensics
    "collect_logs","preserve_evidence","collect_volatile_data","collect_process_dump",
    "collect_network_pcap","collect_edr_forensics","analyze_malware_sample",
    "extract_iocs","correlate_events","calculate_file_hash","perform_timeline_analysis",
    "create_forensic_snapshot","create_snapshot","restore_snapshot",
    # Compliance/Reporting
    "create_ticket","notify_security_team","notify_affected_users",
    "notify_data_protection_authority","notify_incident_commander","document_incident",
    "create_compliance_report","enable_audit_logging",
    # Misc / Network continued
    "enable_netflow","enable_network_tap","deploy_network_sensor","mirror_traffic",
    "block_protocol","poison_dns_cache","enable_ssl_inspection","block_data_exfiltration",
    "update_firewall_rules","block_email_domain","unblock_ip","delete_email","recall_email",
    # Additional identity
    "revoke_rbac_binding","escalate_to_manager","notify_incident_commander",
    # Endpoint continued
    "trigger_edr_contain","trigger_edr_remediate","disable_autorun",
    "rollback_system_update","restore_file_from_backup","restore_registry_backup",
    "rotate_all_service_credentials","clear_session_store","rotate_api_secret",
    "remove_from_group","grant_access","disable_database_login","disable_ldap_bind",
}

def load_and_merge():
    all_entries = []
    seen_types = set()
    duplicates = 0

    for fname in REVERSIBILITY_FILES:
        fpath = DATA_DIR / fname
        if not fpath.exists():
            print(f"  ⚠️  Missing: {fname} — skipping")
            continue
        with open(fpath, encoding="utf-8") as f:
            entries = json.load(f)
        new_count = 0
        for entry in entries:
            atype = entry.get("action_type")
            if atype not in seen_types:
                seen_types.add(atype)
                all_entries.append(entry)
                new_count += 1
            else:
                duplicates += 1
        print(f"  ✓ {fname}: {len(entries)} entries ({new_count} new, {len(entries)-new_count} dupes)")

    print(f"\n  Total unique action entries: {len(all_entries)}")
    print(f"  Duplicates skipped: {duplicates}")
    return all_entries

def save(entries):
    out = DATA_DIR / "reversibility_db_full.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    print(f"\n  ✅ Saved: {out} ({out.stat().st_size/1024:.1f} KB)")

def verify(entries):
    written = {e["action_type"] for e in entries}
    missing = CANONICAL_ACTIONS - written
    extra = written - CANONICAL_ACTIONS
    print(f"\n📋 REVERSIBILITY DB VERIFICATION")
    print(f"  Canonical actions:  {len(CANONICAL_ACTIONS)}")
    print(f"  Written entries:    {len(written)}")
    print(f"  ✅ Covered:         {len(CANONICAL_ACTIONS & written)}")
    print(f"  ⛔ Still missing:   {len(missing)}")
    if missing:
        for m in sorted(missing):
            print(f"    - {m}")
    print(f"  ℹ️  Extra (OK keep): {len(extra)}")
    # Reversal type breakdown
    cats = Counter(e.get("category","unknown") for e in entries)
    print("\n  Entries by category:")
    for c, n in cats.most_common():
        print(f"    {c}: {n}")
    rev_counts = Counter("reversible" if e.get("reversible") else "irreversible" for e in entries)
    print(f"\n  Reversible: {rev_counts.get('reversible',0)}")
    print(f"  Irreversible: {rev_counts.get('irreversible',0)}")
    has_basis = sum(1 for e in entries if e.get("reversal_basis"))
    print(f"\n  Entries with reversal_basis: {has_basis}/{len(entries)}")
    has_source = sum(1 for e in entries if e.get("source_reference"))
    print(f"  Entries with source_reference: {has_source}/{len(entries)}")

if __name__ == "__main__":
    print("=" * 60)
    print("REVERSIBILITY DB MERGE + VERIFY")
    print("=" * 60)
    print("\n[1/3] Loading files...")
    entries = load_and_merge()
    print("\n[2/3] Saving merged file...")
    save(entries)
    print("\n[3/3] Verifying coverage...")
    verify(entries)
    print("\n✅ Done!")
