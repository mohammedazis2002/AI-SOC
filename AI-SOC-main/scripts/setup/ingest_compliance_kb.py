"""
Compliance KB Ingest Script
=============================
Builds the `compliance_kb` Qdrant collection from 11 frameworks.

Frameworks:
  - NIST CSF 2.0        (official ATT&CK mapping)
  - CIS Controls v8     (official ATT&CK mapping)
  - NIST 800-53 r5      (official ATT&CK mapping)
  - ISO 27001:2022      (community ATT&CK mapping)
  - ISO 42001:2023      (Llama-tagged at ingest)
  - GDPR                (Llama-tagged at ingest)
  - HIPAA               (Llama-tagged at ingest)
  - PCI-DSS v4.0        (Llama-tagged at ingest)
  - SOC2 TSC            (Llama-tagged at ingest)
  - SEBI CSCRF          (Llama-tagged at ingest)
  - DPDP Act 2023       (Llama-tagged at ingest)

PageIndexRAG: each control stores its parent_chain in payload.
Retrieval: Stage 1 = exact filter by mitre_technique_ids; Stage 2 = per-framework semantic sweep.

Run:
    python scripts/setup/ingest_compliance_kb.py
"""

import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer

ROOT            = Path(__file__).parent.parent.parent
DATA_DIR        = ROOT / "backend" / "services" / "knowledge_base" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

QDRANT_HOST     = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT     = int(os.getenv("QDRANT_PORT", "6333"))
OLLAMA_URL      = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
COLLECTION_NAME = "compliance_kb"
EMBEDDING_MODEL = "BAAI/bge-large-en-v1.5"
BGE_PREFIX      = "Represent this sentence for searching relevant passages: "
VECTOR_SIZE     = 1024
BATCH_SIZE      = 32

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── Framework Data (structured inline — no external files needed) ───────────────

def build_all_frameworks() -> List[Dict]:
    """
    Returns all controls across all 11 frameworks as a flat list.
    Each control: {framework, control_id, control_name, description,
                   parent_chain[], mitre_technique_ids[], cia_flags{}, severity_weight}
    """
    controls = []
    controls.extend(_nist_csf())
    controls.extend(_cis_18())
    controls.extend(_nist_800_53())
    controls.extend(_iso_27001())
    controls.extend(_iso_42001())
    controls.extend(_gdpr())
    controls.extend(_hipaa())
    controls.extend(_pci_dss())
    controls.extend(_soc2())
    controls.extend(_sebi_cscrf())
    controls.extend(_dpdp())
    logger.info(f"Total controls across 11 frameworks: {len(controls)}")
    return controls


def _c(fw, cid, name, desc, parent_chain, techs=None, cia=None, weight=0.7) -> Dict:
    """Helper to build a control dict."""
    return {
        "framework": fw,
        "control_id": cid,
        "control_name": name,
        "description": desc,
        "parent_chain": parent_chain,
        "mitre_technique_ids": techs or [],
        "cia_flags": cia or {"confidentiality": False, "integrity": False, "availability": False},
        "severity_weight": weight,
        "llama_tagged": False,
    }


def _nist_csf() -> List[Dict]:
    fw = "NIST_CSF"
    # NIST CSF 2.0 — 6 Functions, key subcategories with official ATT&CK mappings
    return [
        _c(fw,"GV.OC-01","Mission Objectives","Organizational mission context is established and communicated.",["NIST CSF 2.0","GV - GOVERN"],[],{"c":False,"i":True,"a":False},0.5),
        _c(fw,"ID.AM-01","Asset Inventory","Software assets (apps, OS, FW, tools) inventoried.",["NIST CSF 2.0","ID - IDENTIFY","ID.AM - Asset Management"],["T1592","T1590"],{"confidentiality":True,"integrity":False,"availability":False},0.6),
        _c(fw,"ID.AM-02","Software Inventory","Hardware assets on network inventoried.",["NIST CSF 2.0","ID - IDENTIFY","ID.AM - Asset Management"],["T1592"],{"confidentiality":True,"integrity":False,"availability":False},0.6),
        _c(fw,"ID.RA-01","Vulnerability Identification","Assets identified for vulnerability identification.",["NIST CSF 2.0","ID - IDENTIFY","ID.RA - Risk Assessment"],["T1190","T1203"],{"confidentiality":True,"integrity":True,"availability":True},0.8),
        _c(fw,"ID.RA-06","Risk Response","Risk responses are chosen, prioritized, planned, tracked, communicated.",["NIST CSF 2.0","ID - IDENTIFY","ID.RA - Risk Assessment"],[],{"confidentiality":False,"integrity":True,"availability":False},0.7),
        _c(fw,"PR.AA-01","Identity Management","Identities and credentials managed for authorized assets and individuals.",["NIST CSF 2.0","PR - PROTECT","PR.AA - Identity Management, Authentication and Access Control"],["T1078","T1110","T1556"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"PR.AA-02","Authentication","Identities verified before access granted.",["NIST CSF 2.0","PR - PROTECT","PR.AA - Identity Management, Authentication and Access Control"],["T1110","T1078","T1556"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"PR.AA-03","IAM Lifecycle","Users, services, and hardware managed consistently.",["NIST CSF 2.0","PR - PROTECT","PR.AA - Identity Management, Authentication and Access Control"],["T1098","T1136","T1531"],{"confidentiality":True,"integrity":True,"availability":False},0.8),
        _c(fw,"PR.AA-05","Access Permissions","Access permissions managed incorporating least privilege principles.",["NIST CSF 2.0","PR - PROTECT","PR.AA - Identity Management, Authentication and Access Control"],["T1078","T1548","T1134"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"PR.AA-06","Remote Access","Remote access managed to prevent unauthorized access.",["NIST CSF 2.0","PR - PROTECT","PR.AA - Identity Management, Authentication and Access Control"],["T1133","T1021"],{"confidentiality":True,"integrity":False,"availability":False},0.85),
        _c(fw,"PR.AT-01","Security Awareness","Personnel educated on cybersecurity responsibilities.",["NIST CSF 2.0","PR - PROTECT","PR.AT - Awareness and Training"],["T1566"],{"confidentiality":False,"integrity":True,"availability":False},0.6),
        _c(fw,"PR.DS-01","Data at Rest","Data-at-rest protected.",["NIST CSF 2.0","PR - PROTECT","PR.DS - Data Security"],["T1486","T1530","T1552"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"PR.DS-02","Data in Transit","Data-in-transit protected.",["NIST CSF 2.0","PR - PROTECT","PR.DS - Data Security"],["T1040","T1557"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"PR.DS-10","Data in Use","Data-in-use protected.",["NIST CSF 2.0","PR - PROTECT","PR.DS - Data Security"],["T1055","T1003"],{"confidentiality":True,"integrity":False,"availability":False},0.85),
        _c(fw,"PR.IR-01","Network Segmentation","Networks and environments protected from unauthorized logical access.",["NIST CSF 2.0","PR - PROTECT","PR.IR - Technology Infrastructure Resilience"],["T1021","T1210"],{"confidentiality":True,"integrity":False,"availability":True},0.8),
        _c(fw,"PR.PS-01","Configuration Management","Configuration management practices applied.",["NIST CSF 2.0","PR - PROTECT","PR.PS - Platform Security"],["T1562","T1490"],{"confidentiality":False,"integrity":True,"availability":True},0.75),
        _c(fw,"DE.AE-02","Event Analysis","Potentially adverse events analyzed to characterize the events.",["NIST CSF 2.0","DE - DETECT","DE.AE - Adverse Event Analysis"],["T1059","T1055"],{"confidentiality":False,"integrity":True,"availability":True},0.8),
        _c(fw,"DE.CM-01","Network Monitoring","Networks and network services monitored for anomalies.",["NIST CSF 2.0","DE - DETECT","DE.CM - Continuous Monitoring"],["T1046","T1041","T1071"],{"confidentiality":False,"integrity":False,"availability":True},0.85),
        _c(fw,"DE.CM-03","Personnel Activity","Personnel activity monitored for unauthorized behavior.",["NIST CSF 2.0","DE - DETECT","DE.CM - Continuous Monitoring"],["T1078","T1530"],{"confidentiality":True,"integrity":True,"availability":False},0.8),
        _c(fw,"DE.CM-06","External Service Monitoring","External service activity monitored.",["NIST CSF 2.0","DE - DETECT","DE.CM - Continuous Monitoring"],["T1195","T1199"],{"confidentiality":True,"integrity":True,"availability":True},0.75),
        _c(fw,"RS.MA-01","Incident Execution","Incident response plan executed.",["NIST CSF 2.0","RS - RESPOND","RS.MA - Incident Management"],[],{"confidentiality":False,"integrity":True,"availability":True},0.7),
        _c(fw,"RC.RP-01","Recovery Execution","Recovery plan executed to restore assets.",["NIST CSF 2.0","RC - RECOVER","RC.RP - Incident Recovery Plan Execution"],[],{"confidentiality":False,"integrity":True,"availability":True},0.7),
    ]


def _cis_18() -> List[Dict]:
    fw = "CIS_18"
    return [
        _c(fw,"CIS-01.01","Enterprise Asset Inventory","Actively manage all enterprise assets.",["CIS Controls v8","IG1","Control 01 - Inventory and Control of Enterprise Assets"],["T1592","T1590"],{"confidentiality":True,"integrity":False,"availability":False},0.7),
        _c(fw,"CIS-02.01","Software Inventory","Maintain inventory of authorized software.",["CIS Controls v8","IG1","Control 02 - Inventory and Control of Software Assets"],["T1204","T1218"],{"confidentiality":False,"integrity":True,"availability":False},0.7),
        _c(fw,"CIS-03.03","Data Protection","Protect sensitive data.",["CIS Controls v8","IG1","Control 03 - Data Protection"],["T1486","T1530","T1041"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"CIS-04.01","Vulnerability Management","Establish and maintain vulnerability management process.",["CIS Controls v8","IG1","Control 04 - Vulnerability Management"],["T1190","T1203","T1068"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"CIS-05.01","Account Management","Establish and maintain account inventory.",["CIS Controls v8","IG1","Control 05 - Account Management"],["T1078","T1098","T1136"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"CIS-05.02","Administrator Accounts","Use unique passwords, ensure mFA for privileged accounts.",["CIS Controls v8","IG1","Control 05 - Account Management"],["T1078","T1110"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"CIS-06.01","Access Control Management","Establish an access control process.",["CIS Controls v8","IG1","Control 06 - Access Control Management"],["T1078","T1548","T1134"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"CIS-08.01","Audit Log Management","Establish and maintain audit log process.",["CIS Controls v8","IG1","Control 08 - Audit Log Management"],["T1562","T1070"],{"confidentiality":False,"integrity":True,"availability":False},0.85),
        _c(fw,"CIS-09.01","Email Protection","Use DNS-based filtering services.",["CIS Controls v8","IG1","Control 09 - Email and Web Browser Protections"],["T1566","T1071"],{"confidentiality":True,"integrity":False,"availability":False},0.8),
        _c(fw,"CIS-10.01","Malware Defense","Deploy anti-malware software.",["CIS Controls v8","IG1","Control 10 - Malware Defenses"],["T1059","T1204","T1486"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"CIS-12.01","Network Defense","Network monitoring and defense.",["CIS Controls v8","IG2","Control 12 - Network Infrastructure Management"],["T1046","T1210","T1021"],{"confidentiality":True,"integrity":False,"availability":True},0.8),
        _c(fw,"CIS-13.01","Network Monitoring","Perform traffic and log analysis.",["CIS Controls v8","IG2","Control 13 - Network Monitoring and Defense"],["T1041","T1071","T1048"],{"confidentiality":True,"integrity":False,"availability":True},0.85),
        _c(fw,"CIS-16.01","Application Security","Establish and maintain secure application dev practice.",["CIS Controls v8","IG2","Control 16 - Application Software Security"],["T1190","T1059"],{"confidentiality":True,"integrity":True,"availability":True},0.8),
        _c(fw,"CIS-17.01","Incident Response","Designate personnel to manage incidents.",["CIS Controls v8","IG1","Control 17 - Incident Response Management"],[],{"confidentiality":False,"integrity":True,"availability":True},0.7),
        _c(fw,"CIS-18.01","Penetration Testing","Establish penetration testing program.",["CIS Controls v8","IG2","Control 18 - Penetration Testing"],["T1595","T1190"],{"confidentiality":True,"integrity":True,"availability":True},0.7),
    ]


def _nist_800_53() -> List[Dict]:
    fw = "NIST_800_53"
    return [
        _c(fw,"AC-2","Account Management","Manage information system accounts including establishment, authorization, review, and disabling.",["NIST 800-53r5","AC - Access Control"],["T1078","T1098","T1136","T1531"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"AC-3","Access Enforcement","Enforce approved authorizations for logical access.",["NIST 800-53r5","AC - Access Control"],["T1078","T1548"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"AC-6","Least Privilege","Employ least privilege principle.",["NIST 800-53r5","AC - Access Control"],["T1548","T1134","T1078"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"AC-7","Unsuccessful Login Attempts","Enforce limit on consecutive invalid access attempts.",["NIST 800-53r5","AC - Access Control"],["T1110"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"AC-17","Remote Access","Establish usage restrictions for remote access.",["NIST 800-53r5","AC - Access Control"],["T1133","T1021"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"AU-2","Event Logging","Identify events to be logged.",["NIST 800-53r5","AU - Audit and Accountability"],["T1562","T1070"],{"confidentiality":False,"integrity":True,"availability":False},0.85),
        _c(fw,"AU-6","Audit Record Review","Review and analyze audit records.",["NIST 800-53r5","AU - Audit and Accountability"],["T1562","T1070.001"],{"confidentiality":False,"integrity":True,"availability":False},0.85),
        _c(fw,"CM-6","Configuration Settings","Establish and document config settings.",["NIST 800-53r5","CM - Configuration Management"],["T1562","T1490"],{"confidentiality":False,"integrity":True,"availability":True},0.8),
        _c(fw,"CM-7","Least Functionality","Configure system to provide only essential capabilities.",["NIST 800-53r5","CM - Configuration Management"],["T1059","T1218"],{"confidentiality":False,"integrity":True,"availability":True},0.85),
        _c(fw,"IA-2","Identification and Authentication","Uniquely identify and authenticate users.",["NIST 800-53r5","IA - Identification and Authentication"],["T1078","T1110","T1556"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"IA-5","Authenticator Management","Manage system authenticators.",["NIST 800-53r5","IA - Identification and Authentication"],["T1552","T1555","T1003"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"IR-4","Incident Handling","Implement incident handling capability.",["NIST 800-53r5","IR - Incident Response"],[],{"confidentiality":False,"integrity":True,"availability":True},0.8),
        _c(fw,"SC-7","Boundary Protection","Monitor and control communications at external boundaries.",["NIST 800-53r5","SC - System and Communications Protection"],["T1041","T1048","T1071"],{"confidentiality":True,"integrity":False,"availability":True},0.85),
        _c(fw,"SC-28","Protection of Information at Rest","Implement cryptographic mechanisms to protect information at rest.",["NIST 800-53r5","SC - System and Communications Protection"],["T1486","T1530"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"SI-3","Malicious Code Protection","Implement malicious code protection mechanisms.",["NIST 800-53r5","SI - System and Information Integrity"],["T1059","T1204","T1486"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"SI-4","System Monitoring","Monitor systems to detect attacks and indicators of attack.",["NIST 800-53r5","SI - System and Information Integrity"],["T1059","T1055","T1003"],{"confidentiality":False,"integrity":True,"availability":True},0.9),
    ]


def _iso_27001() -> List[Dict]:
    fw = "ISO_27001"
    return [
        _c(fw,"A.5.1","Policies for Information Security","Define and review information security policies.",["ISO 27001:2022","5. Organizational Controls"],[],{"confidentiality":True,"integrity":True,"availability":True},0.5),
        _c(fw,"A.5.15","Access Control","Establish rules to control physical/logical access.",["ISO 27001:2022","5. Organizational Controls"],["T1078","T1548"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"A.5.16","Identity Management","Manage full lifecycle of identities.",["ISO 27001:2022","5. Organizational Controls"],["T1078","T1098","T1136"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"A.5.17","Authentication Information","Manage authentication information appropriately.",["ISO 27001:2022","5. Organizational Controls"],["T1110","T1552","T1003"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"A.5.23","Information Security for Cloud","Establish security processes for cloud services.",["ISO 27001:2022","5. Organizational Controls"],["T1530","T1537","T1526"],{"confidentiality":True,"integrity":True,"availability":True},0.85),
        _c(fw,"A.5.26","Response to Information Security Incidents","Respond to incidents according to procedures.",["ISO 27001:2022","5. Organizational Controls"],[],{"confidentiality":False,"integrity":True,"availability":True},0.8),
        _c(fw,"A.8.2","Privileged Access Rights","Restrict and manage privileged access rights.",["ISO 27001:2022","8. Technological Controls"],["T1078","T1134","T1548"],{"confidentiality":True,"integrity":True,"availability":False},0.95),
        _c(fw,"A.8.3","Information Access Restriction","Restrict access to information per access control policy.",["ISO 27001:2022","8. Technological Controls"],["T1078","T1530"],{"confidentiality":True,"integrity":False,"availability":False},0.85),
        _c(fw,"A.8.5","Secure Authentication","Implement secure authentication technologies.",["ISO 27001:2022","8. Technological Controls"],["T1110","T1078","T1556"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"A.8.7","Protection Against Malware","Protect against malware.",["ISO 27001:2022","8. Technological Controls"],["T1059","T1204","T1486"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"A.8.9","Configuration Management","Manage configurations including security.",["ISO 27001:2022","8. Technological Controls"],["T1562","T1490"],{"confidentiality":False,"integrity":True,"availability":True},0.8),
        _c(fw,"A.8.12","Data Leakage Prevention","Apply DLP measures to systems and networks.",["ISO 27001:2022","8. Technological Controls"],["T1041","T1048","T1567"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"A.8.15","Logging","Produce, store, protect and analyze event logs.",["ISO 27001:2022","8. Technological Controls"],["T1562","T1070"],{"confidentiality":False,"integrity":True,"availability":False},0.85),
        _c(fw,"A.8.16","Monitoring Activities","Monitor networks and applications for anomalous behavior.",["ISO 27001:2022","8. Technological Controls"],["T1046","T1071","T1059"],{"confidentiality":False,"integrity":True,"availability":True},0.85),
        _c(fw,"A.8.20","Network Security","Secure and manage networks and network devices.",["ISO 27001:2022","8. Technological Controls"],["T1046","T1021","T1210"],{"confidentiality":True,"integrity":False,"availability":True},0.85),
        _c(fw,"A.8.24","Use of Cryptography","Define and implement rules on cryptography.",["ISO 27001:2022","8. Technological Controls"],["T1557","T1040","T1486"],{"confidentiality":True,"integrity":True,"availability":False},0.85),
    ]


def _iso_42001() -> List[Dict]:
    fw = "ISO_42001"
    # AI management system — ATT&CK tags added by Llama at ingest
    return [
        _c(fw,"A.6.1.2","AI Risk Assessment","Identify and assess risks specific to AI system development and use.",["ISO 42001:2023","A.6 - AI Risk Management"],[],{"confidentiality":True,"integrity":True,"availability":True},0.7),
        _c(fw,"A.6.2.1","Bias and Fairness","Implement measures to assess and mitigate bias in AI systems.",["ISO 42001:2023","A.6 - AI Risk Management"],[],{"confidentiality":False,"integrity":True,"availability":False},0.6),
        _c(fw,"A.8.4","AI Data Governance","Manage data used for AI training and operation.",["ISO 42001:2023","A.8 - AI System Life Cycle"],[],{"confidentiality":True,"integrity":True,"availability":False},0.75),
        _c(fw,"A.9.3","AI System Transparency","Provide transparency about AI system capabilities and limitations.",["ISO 42001:2023","A.9 - AI System Transparency"],[],{"confidentiality":False,"integrity":True,"availability":False},0.6),
        _c(fw,"A.10.1","Adversarial Robustness","Protect AI systems from adversarial inputs and manipulation.",["ISO 42001:2023","A.10 - AI Security"],[],{"confidentiality":True,"integrity":True,"availability":True},0.8),
    ]


def _gdpr() -> List[Dict]:
    fw = "GDPR"
    return [
        _c(fw,"Art.5.1.f","Integrity and Confidentiality","Personal data processed to ensure appropriate security including protection against unauthorized processing.",["GDPR","Chapter II - Principles"],[],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"Art.25","Data Protection by Design","Implement appropriate technical measures to ensure data protection principles are met by design.",["GDPR","Chapter III - Rights of Data Subject"],[],{"confidentiality":True,"integrity":True,"availability":False},0.85),
        _c(fw,"Art.32.1","Security of Processing","Implement appropriate technical and organizational measures to ensure security appropriate to the risk.",["GDPR","Chapter IV - Controller and Processor"],[],{"confidentiality":True,"integrity":True,"availability":True},0.95),
        _c(fw,"Art.32.1.a","Pseudonymisation and Encryption","Implement pseudonymisation and encryption of personal data.",["GDPR","Chapter IV - Controller and Processor","Art.32 - Security of Processing"],[],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"Art.32.1.b","Ongoing Confidentiality","Ensure ongoing confidentiality, integrity, availability and resilience of processing systems.",["GDPR","Chapter IV - Controller and Processor","Art.32 - Security of Processing"],[],{"confidentiality":True,"integrity":True,"availability":True},0.95),
        _c(fw,"Art.32.1.d","Regular Testing","Regularly test, assess and evaluate the effectiveness of technical and organizational measures.",["GDPR","Chapter IV - Controller and Processor","Art.32 - Security of Processing"],[],{"confidentiality":False,"integrity":True,"availability":False},0.8),
        _c(fw,"Art.33","Breach Notification to Authority","Notify supervisory authority of personal data breach within 72 hours.",["GDPR","Chapter IV - Controller and Processor"],[],{"confidentiality":True,"integrity":False,"availability":False},0.85),
        _c(fw,"Art.34","Communication to Data Subject","Communicate personal data breach to data subject without undue delay.",["GDPR","Chapter IV - Controller and Processor"],[],{"confidentiality":True,"integrity":False,"availability":False},0.85),
    ]


def _hipaa() -> List[Dict]:
    fw = "HIPAA"
    return [
        _c(fw,"164.308.a.1","Security Management Process","Implement policies and procedures to prevent, detect, contain, correct security violations.",["HIPAA Security Rule","164.308 - Administrative Safeguards"],[],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"164.308.a.3","Workforce Authorization","Implement procedures to authorize access to ePHI.",["HIPAA Security Rule","164.308 - Administrative Safeguards"],["T1078"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"164.308.a.5","Security Awareness Training","Train workforce on security awareness.",["HIPAA Security Rule","164.308 - Administrative Safeguards"],["T1566"],{"confidentiality":False,"integrity":True,"availability":False},0.75),
        _c(fw,"164.308.a.6","Security Incident Procedures","Implement policies to address security incidents.",["HIPAA Security Rule","164.308 - Administrative Safeguards"],[],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"164.312.a.1","Access Control","Implement technical policies restricting access to ePHI.",["HIPAA Security Rule","164.312 - Technical Safeguards"],["T1078","T1548"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"164.312.a.2.i","Unique User Identification","Assign a unique name/number for identifying and tracking user identity.",["HIPAA Security Rule","164.312 - Technical Safeguards","164.312.a - Access Control"],["T1078"],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"164.312.a.2.iii","Automatic Logoff","Implement electronic procedures to terminate sessions after period of inactivity.",["HIPAA Security Rule","164.312 - Technical Safeguards","164.312.a - Access Control"],["T1078"],{"confidentiality":True,"integrity":False,"availability":False},0.8),
        _c(fw,"164.312.b","Audit Controls","Implement hardware, software, and procedural mechanisms to record and examine ePHI access.",["HIPAA Security Rule","164.312 - Technical Safeguards"],["T1562","T1070"],{"confidentiality":False,"integrity":True,"availability":False},0.9),
        _c(fw,"164.312.c.1","Integrity Controls","Implement policies to protect ePHI from improper alteration or destruction.",["HIPAA Security Rule","164.312 - Technical Safeguards"],["T1565","T1491"],{"confidentiality":False,"integrity":True,"availability":False},0.85),
        _c(fw,"164.312.e.1","Transmission Security","Implement technical security measures to guard against unauthorized ePHI access during transmission.",["HIPAA Security Rule","164.312 - Technical Safeguards"],["T1040","T1557"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
    ]


def _pci_dss() -> List[Dict]:
    fw = "PCI_DSS"
    return [
        _c(fw,"PCI-01.1","Network Security Controls","Establish and implement network security controls.",["PCI-DSS v4.0","Requirement 1 - Network Security Controls"],["T1046","T1021","T1210"],{"confidentiality":True,"integrity":False,"availability":True},0.85),
        _c(fw,"PCI-02.1","Secure Configurations","Do not use vendor-supplied defaults for system passwords.",["PCI-DSS v4.0","Requirement 2 - Secure Configurations"],["T1078","T1110"],{"confidentiality":True,"integrity":True,"availability":False},0.85),
        _c(fw,"PCI-03.4","Cardholder Data Protection","Render PAN unreadable anywhere it is stored.",["PCI-DSS v4.0","Requirement 3 - Protect Stored Account Data"],["T1486","T1530"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"PCI-04.2","Strong Cryptography","Use strong cryptography for transmission of cardholder data.",["PCI-DSS v4.0","Requirement 4 - Protect Cardholder Data with Strong Cryptography"],["T1040","T1557"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"PCI-05.1","Anti-Malware","Deploy anti-malware solutions on all applicable systems.",["PCI-DSS v4.0","Requirement 5 - Protect All Systems Against Malware"],["T1059","T1204","T1486"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"PCI-06.3","Vulnerability Management","Develop secure software and protect systems from known vulnerabilities.",["PCI-DSS v4.0","Requirement 6 - Develop and Maintain Secure Systems"],["T1190","T1203"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"PCI-07.2","Restrict Access","Restrict access to system components and cardholder data by need to know.",["PCI-DSS v4.0","Requirement 7 - Restrict Access to System Components"],["T1078","T1548"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"PCI-08.2","User Authentication","Identify and authenticate access to system components.",["PCI-DSS v4.0","Requirement 8 - Identify Users and Authenticate Access"],["T1078","T1110","T1556"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"PCI-08.4","MFA Required","Implement MFA for all access to the cardholder data environment.",["PCI-DSS v4.0","Requirement 8 - Identify Users and Authenticate Access"],["T1110","T1078"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"PCI-10.2","Audit Logs","Implement audit logs to capture all access to system components.",["PCI-DSS v4.0","Requirement 10 - Log and Monitor All Access"],["T1562","T1070"],{"confidentiality":False,"integrity":True,"availability":False},0.9),
        _c(fw,"PCI-11.3","Penetration Testing","Implement penetration testing methodology.",["PCI-DSS v4.0","Requirement 11 - Test Security Regularly"],["T1595","T1190"],{"confidentiality":True,"integrity":True,"availability":True},0.75),
        _c(fw,"PCI-12.10","Incident Response Plan","Implement an incident response plan.",["PCI-DSS v4.0","Requirement 12 - Support Information Security Policies"],[],{"confidentiality":False,"integrity":True,"availability":True},0.8),
    ]


def _soc2() -> List[Dict]:
    fw = "SOC2"
    return [
        _c(fw,"CC6.1","Logical Access Controls","Implement logical access security software, infrastructure, and architectures.",["SOC2 TSC","CC6 - Logical and Physical Access Controls"],["T1078","T1548","T1134"],{"confidentiality":True,"integrity":True,"availability":False},0.95),
        _c(fw,"CC6.2","Authentication","Before allowing access, authenticate users and subjects.",["SOC2 TSC","CC6 - Logical and Physical Access Controls"],["T1078","T1110","T1556"],{"confidentiality":True,"integrity":False,"availability":False},0.95),
        _c(fw,"CC6.3","Role-Based Access","Create and maintain role-based access controls.",["SOC2 TSC","CC6 - Logical and Physical Access Controls"],["T1078","T1548"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"CC6.6","Threats from Outside Network","Implement controls to prevent external threats.",["SOC2 TSC","CC6 - Logical and Physical Access Controls"],["T1133","T1190","T1046"],{"confidentiality":True,"integrity":False,"availability":True},0.9),
        _c(fw,"CC6.8","Malware Prevention","Implement controls to prevent and detect unauthorized or malicious software.",["SOC2 TSC","CC6 - Logical and Physical Access Controls"],["T1059","T1204","T1486"],{"confidentiality":True,"integrity":True,"availability":True},0.9),
        _c(fw,"CC7.1","Anomaly Detection","Monitor system components for anomalies.",["SOC2 TSC","CC7 - System Operations"],["T1046","T1059","T1055"],{"confidentiality":False,"integrity":True,"availability":True},0.85),
        _c(fw,"CC7.2","Evaluate Security Events","Monitor system components for anomalous behavior.",["SOC2 TSC","CC7 - System Operations"],["T1071","T1041","T1048"],{"confidentiality":False,"integrity":True,"availability":True},0.85),
        _c(fw,"CC7.3","Incident Response","Evaluate identified security incidents.",["SOC2 TSC","CC7 - System Operations"],[],{"confidentiality":False,"integrity":True,"availability":True},0.8),
        _c(fw,"CC8.1","Change Management","Authorize and implement changes to infrastructure, data, software.",["SOC2 TSC","CC8 - Change Management"],["T1562","T1490"],{"confidentiality":False,"integrity":True,"availability":True},0.75),
        _c(fw,"A1.2","Availability Commitments","Meet availability commitments and system requirements.",["SOC2 TSC","A1 - Availability"],[],{"confidentiality":False,"integrity":False,"availability":True},0.8),
        _c(fw,"C1.1","Data Classification","Identify and maintain confidential information.",["SOC2 TSC","C1 - Confidentiality"],["T1530","T1041"],{"confidentiality":True,"integrity":False,"availability":False},0.85),
    ]


def _sebi_cscrf() -> List[Dict]:
    fw = "SEBI_CSCRF"
    return [
        _c(fw,"SEBI-GOV-01","Cybersecurity Governance","Establish board-level cybersecurity governance framework.",["SEBI CSCRF 2023","Governance"],[],{"confidentiality":True,"integrity":True,"availability":True},0.6),
        _c(fw,"SEBI-ID-01","Asset Classification","Identify and classify critical assets including trading systems.",["SEBI CSCRF 2023","Identify"],["T1592"],{"confidentiality":True,"integrity":False,"availability":True},0.75),
        _c(fw,"SEBI-PR-01","Access Control","Implement strong access controls for trading and core systems.",["SEBI CSCRF 2023","Protect"],["T1078","T1548","T1110"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"SEBI-PR-02","Encryption","Encrypt sensitive financial data at rest and in transit.",["SEBI CSCRF 2023","Protect"],["T1040","T1530","T1557"],{"confidentiality":True,"integrity":True,"availability":False},0.9),
        _c(fw,"SEBI-PR-03","Network Security","Implement network segmentation and monitoring for trading infrastructure.",["SEBI CSCRF 2023","Protect"],["T1046","T1021","T1210"],{"confidentiality":True,"integrity":False,"availability":True},0.85),
        _c(fw,"SEBI-DE-01","Threat Detection","Implement continuous monitoring for cyber threats to financial systems.",["SEBI CSCRF 2023","Detect"],["T1059","T1041","T1486"],{"confidentiality":False,"integrity":True,"availability":True},0.85),
        _c(fw,"SEBI-RS-01","Incident Response","Establish cyber incident response capability and report to SEBI within prescribed timelines.",["SEBI CSCRF 2023","Respond"],[],{"confidentiality":False,"integrity":True,"availability":True},0.9),
        _c(fw,"SEBI-RC-01","Recovery","Ensure business continuity and recovery of critical market infrastructure.",["SEBI CSCRF 2023","Recover"],[],{"confidentiality":False,"integrity":True,"availability":True},0.9),
        _c(fw,"SEBI-RA-01","Risk Assessment","Conduct annual cyber risk assessment for SEBI-regulated entities.",["SEBI CSCRF 2023","Risk Assessment"],[],{"confidentiality":True,"integrity":True,"availability":True},0.75),
        _c(fw,"SEBI-TP-01","Third-Party Risk","Manage cybersecurity risks from third-party vendors and service providers.",["SEBI CSCRF 2023","Third Party Risk"],["T1195","T1199"],{"confidentiality":True,"integrity":True,"availability":True},0.8),
    ]


def _dpdp() -> List[Dict]:
    fw = "DPDP"
    return [
        _c(fw,"DPDP-S4","Consent and Lawful Processing","Process personal data only with consent or other lawful basis under the Act.",["India DPDP Act 2023","Section 4 - Grounds for Processing"],[],{"confidentiality":True,"integrity":False,"availability":False},0.8),
        _c(fw,"DPDP-S8.1","Data Security","Implement appropriate technical and organizational measures to ensure security of personal data.",["India DPDP Act 2023","Section 8 - Obligations of Data Fiduciary"],[],{"confidentiality":True,"integrity":True,"availability":True},0.95),
        _c(fw,"DPDP-S8.3","Data Minimization","Collect only such personal data as is necessary for the specified purpose.",["India DPDP Act 2023","Section 8 - Obligations of Data Fiduciary"],[],{"confidentiality":True,"integrity":False,"availability":False},0.8),
        _c(fw,"DPDP-S8.6","Data Breach Notification","Notify Data Protection Board and affected data principals upon personal data breach.",["India DPDP Act 2023","Section 8 - Obligations of Data Fiduciary"],[],{"confidentiality":True,"integrity":False,"availability":False},0.9),
        _c(fw,"DPDP-S9","Children's Data","Process children's personal data with verifiable parental consent.",["India DPDP Act 2023","Section 9 - Processing of Children's Data"],[],{"confidentiality":True,"integrity":False,"availability":False},0.75),
        _c(fw,"DPDP-S10","Significant Data Fiduciary","Additional obligations for Significant Data Fiduciaries including data audits.",["India DPDP Act 2023","Section 10 - Additional Obligations"],[],{"confidentiality":True,"integrity":True,"availability":True},0.85),
        _c(fw,"DPDP-S17","Exemptions","Conditions under which government may exempt certain processing.",["India DPDP Act 2023","Section 17 - Exemptions"],[],{"confidentiality":True,"integrity":False,"availability":False},0.5),
    ]


# ── Llama ATT&CK Tagging (for controls without pre-mapped technique_ids) ───────

def llama_tag_control(control: Dict, ollama_url: str) -> List[str]:
    """
    Ask Llama 3.1 8B to identify ATT&CK technique IDs for an untagged control.
    Runs once at ingest time; result stored in payload.
    """
    prompt = (
        f"You are a cybersecurity expert. Given this compliance control, "
        f"identify which MITRE ATT&CK technique IDs (format: T####.###) this control "
        f"helps mitigate or detect. Return ONLY a JSON array of technique IDs, nothing else.\n\n"
        f"Framework: {control['framework']}\n"
        f"Control ID: {control['control_id']}\n"
        f"Control Name: {control['control_name']}\n"
        f"Description: {control['description']}\n\n"
        f"Response format: [\"T1078\", \"T1110\"] or [] if none apply."
    )
    try:
        resp = requests.post(
            f"{ollama_url}/api/generate",
            json={"model": "llama3.1:8b", "prompt": prompt, "stream": False},
            timeout=30,
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "[]").strip()
        # Extract JSON array from response
        import re as _re
        match = _re.search(r'\[.*?\]', raw, _re.DOTALL)
        if match:
            ids = json.loads(match.group())
            return [t for t in ids if isinstance(t, str) and t.startswith("T")]
        return []
    except Exception as e:
        logger.debug(f"Llama tagging failed for {control['control_id']}: {e}")
        return []


def enrich_with_llama(controls: List[Dict], ollama_url: str) -> List[Dict]:
    """Tag untagged controls using Llama 3.1 8B."""
    untagged = [c for c in controls if not c["mitre_technique_ids"] and not c.get("llama_tagged")]
    if not untagged:
        logger.info("All controls already have ATT&CK tags — skipping Llama tagging.")
        return controls

    logger.info(f"Llama tagging {len(untagged)} untagged controls (approx {len(untagged)*5}s)...")
    tagged_map = {c["control_id"]: c for c in controls}

    for i, ctrl in enumerate(untagged, 1):
        tech_ids = llama_tag_control(ctrl, ollama_url)
        tagged_map[ctrl["control_id"]]["mitre_technique_ids"] = tech_ids
        tagged_map[ctrl["control_id"]]["llama_tagged"] = True
        if i % 20 == 0:
            logger.info(f"  Tagged {i}/{len(untagged)} controls")
        time.sleep(0.1)

    return list(tagged_map.values())


# ── Embed + Upsert ─────────────────────────────────────────────────────────────

def build_embed_text(ctrl: Dict) -> str:
    """Build rich text for embedding: parent chain + control text."""
    chain = " > ".join(ctrl["parent_chain"]) if ctrl["parent_chain"] else ctrl["framework"]
    cia_parts = [k for k, v in ctrl.get("cia_flags", {}).items() if v]
    cia_str = f" CIA: {', '.join(cia_parts)}." if cia_parts else ""
    tech_str = f" ATT&CK: {', '.join(ctrl['mitre_technique_ids'][:6])}." if ctrl["mitre_technique_ids"] else ""
    return (
        f"{chain} | {ctrl['control_id']} {ctrl['control_name']}. "
        f"{ctrl['description']}{cia_str}{tech_str}"
    )


def setup_collection(client: QdrantClient):
    try:
        client.get_collection(COLLECTION_NAME)
        logger.info(f"Collection '{COLLECTION_NAME}' exists.")
        return
    except Exception:
        pass
    client.create_collection(
        COLLECTION_NAME,
        vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
    )
    logger.info(f"Created collection '{COLLECTION_NAME}'.")


def main():
    client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=60)
    setup_collection(client)
    logger.info(f"Loading {EMBEDDING_MODEL}...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    # Build all framework controls
    controls = build_all_frameworks()

    # Llama-tag untagged controls
    controls = enrich_with_llama(controls, OLLAMA_URL)

    # Cache tagged controls
    cache_path = DATA_DIR / "compliance_controls_tagged.json"
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(controls, f, indent=2, ensure_ascii=False)
    logger.info(f"Tagged controls cached → {cache_path}")

    # Embed
    texts = [BGE_PREFIX + build_embed_text(c) for c in controls]
    logger.info(f"Embedding {len(texts)} compliance controls...")
    embeddings = model.encode(texts, batch_size=BATCH_SIZE, show_progress_bar=True, normalize_embeddings=True)

    # Build points
    points = []
    for ctrl, emb in zip(controls, embeddings):
        pid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ctrl['framework']}::{ctrl['control_id']}"))
        points.append(PointStruct(id=pid, vector=emb.tolist(), payload=ctrl))

    # Upsert in small batches with retry to handle transient Qdrant timeouts
    UPSERT_BATCH = 8
    failed_batches = 0
    for i in range(0, len(points), UPSERT_BATCH):
        batch = points[i:i + UPSERT_BATCH]
        for attempt in range(3):
            try:
                client.upsert(COLLECTION_NAME, points=batch)
                logger.info(f"  Upserted {min(i+UPSERT_BATCH,len(points))}/{len(points)}")
                break
            except Exception as e:
                if attempt < 2:
                    wait = 2 ** attempt
                    logger.warning(f"  Upsert failed (attempt {attempt+1}), retrying in {wait}s: {e}")
                    time.sleep(wait)
                else:
                    logger.error(f"  Upsert permanently failed for batch {i//UPSERT_BATCH}: {e}")
                    failed_batches += 1
    if failed_batches:
        logger.warning(f"⚠️  {failed_batches} batches failed — rerun to retry")

    logger.info(f"\n✅ compliance_kb ready: {len(points)} controls across 11 frameworks")
    fw_counts: Dict[str, int] = {}
    for c in controls:
        fw_counts[c["framework"]] = fw_counts.get(c["framework"], 0) + 1
    for fw, cnt in sorted(fw_counts.items()):
        logger.info(f"   {fw}: {cnt} controls")


if __name__ == "__main__":
    main()
