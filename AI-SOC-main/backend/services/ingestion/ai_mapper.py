"""
AI-powered log mapper using LLM for intelligent alert classification
"""
import httpx
import json
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime
import os

from services.classification.event_classifier import event_classifier
from services.ingestion.extraction_helpers import extract_all, get_extraction_result

logger = logging.getLogger(__name__)

class AIMapper:
    """AI-powered log event mapper using LLM"""
    
    def __init__(
        self,
        llm_url: str = None,
        model_name: str = None,
        timeout: int = 120,
        confidence_threshold: float = 0.7
    ):
        # Use environment variables with fallbacks
        base_url = llm_url or os.getenv(
            "LLM_SERVICE_URL", 
            "http://ollama:11434"
        )
        
        # If running outside Docker, replace 'ollama' with 'localhost'
        # This allows the script to work both inside and outside containers
        if "ollama:" in base_url:
            try:
                import socket
                socket.gethostbyname("ollama")
            except socket.gaierror:
                # Can't resolve 'ollama', we're outside Docker
                base_url = base_url.replace("ollama:", "localhost:")
                logger.info(f"Running outside Docker, using localhost instead of ollama")
        
        self.llm_url = base_url + "/v1/chat/completions"
        
        self.model_name = model_name or os.getenv(
            "LLM_MODEL_NAME", 
            "mistral:latest"
        )
        
        self.timeout = float(os.getenv("LLM_TIMEOUT", timeout))
        self.confidence_threshold = float(os.getenv(
            "AI_CONFIDENCE_THRESHOLD", 
            confidence_threshold
        ))
        
        logger.info(f"AIMapper initialized: {self.llm_url} | Model: {self.model_name}")
    
    async def map_log_event(
        self, 
        raw_log: str,
        log_metadata: Dict = None
    ) -> Tuple[Dict, bool]:
        """
        Map a raw log to structured alert fields using LLM
        
        Returns:
            Tuple of (mapped_data, needs_human_review)
        """
        try:
            # Create the prompt
            prompt = self._create_mapping_prompt(raw_log, log_metadata)
            
            # Call LLM
            response_text = await self._call_llm(prompt)
            
            # Parse response
            mapped_data = self._parse_llm_response(response_text)
            
            # Determine if human review is needed
            needs_review = self._requires_human_review(mapped_data)
            
            # Add metadata
            mapped_data["ai_processed_at"] = datetime.utcnow().isoformat()
            mapped_data["ai_model_used"] = self.model_name
            mapped_data["raw_log"] = raw_log
            
            logger.info(
                f"AI Mapping: confidence={mapped_data.get('confidence', 0):.2f}, "
                f"needs_review={needs_review}"
            )
            
            return mapped_data, needs_review
            
        except Exception as e:
            logger.error(f"AI mapping failed: {e}", exc_info=True)
            # Return fallback mapping
            return self._create_fallback_mapping(raw_log, str(e)), True
    
    def _create_mapping_prompt(self, raw_log: str, metadata: Dict = None) -> str:
        """Create prompt for LLM with security fields - emphasizes extraction only"""
        
        prompt = f"""You are a cybersecurity log analyzer. Analyze this log and extract ONLY information that is EXPLICITLY present in the log. DO NOT guess, infer, or fabricate any data.

Log: {raw_log}

Return ONLY valid JSON in this exact format:
{{
  "finding": "Brief event title",
  "severity": "Critical/High/Medium/Low",
  "confidence": 0.0-1.0,
  "source_ip": "IP or null",
  "source_port": "port or null",
  "dest_ip": "IP or null", 
  "dest_port": "port or null",
  "username": "user or null",
  "process_name": "process or null",
  "file_path": "path or null",
  "timestamp": "Time from log (e.g. 'Jan 15 14:23:45' or ISO) or null",
  "action": "What happened",
  "recommended_action": "What to do",
  "mitre_techniques": ["T1110", "T1078"] or []
}}

MITRE ATT&CK Techniques: Analyze the log and identify relevant technique IDs:
- T1110: Brute Force (failed password attempts)
- T1078: Valid Accounts
- T1059: Command/Script Execution  
- T1190: Exploit Public App
- T1071: Application Layer C2
- T1595: Active Scanning
- T1204: User Execution
- T1105: File Transfer
- T1003: Credential Dumping
- T1021: Remote Services
Return as array or []. Do not fabricate MITRE IDs.

Rules: Use null for missing fields. Be brief."""
        
        return prompt
    
    async def _call_llm(self, prompt: str) -> str:
        """Call the LLM API"""
        
        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert specializing in OCSF log analysis. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,  # Low temperature for consistent output
            "stream": False
        }
        
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:  # 5 minute timeout
                response = await client.post(
                    self.llm_url,
                    json=payload
                )
                response.raise_for_status()
                
                result = response.json()
                
                if "choices" in result and len(result["choices"]) > 0:
                    content = result["choices"][0]["message"]["content"]
                    return content
                else:
                    raise ValueError(f"Unexpected LLM response format: {result}")
                    
        except httpx.TimeoutException as e:
            logger.error(f"LLM request timed out after 300s: {e}")
            raise TimeoutError(f"LLM took too long to respond. Consider using a faster model.")
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            raise
    
    def _parse_llm_response(self, response_text: str) -> Dict:
        """Parse the LLM's JSON response"""
        
        # Clean up response - remove markdown code blocks if present
        cleaned = response_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
        
        try:
            data = json.loads(cleaned)
            
            # Helper to recursively clean "null" strings
            def clean_values(obj):
                if isinstance(obj, dict):
                    return {k: clean_values(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [clean_values(v) for v in obj]
                elif isinstance(obj, str):
                    if obj.lower() in ["null", "none", "n/a", ""]:
                        return None
                    return obj
                return obj
            
            # Clean the entire data structure first
            data = clean_values(data)
            
            # Convert simplified flat format to nested format if needed
            if "network" not in data and ("source_ip" in data or "dest_ip" in data):
                # Helper to safely get port (already cleaned, but ensure int)
                def get_port(val):
                    if val is None: return None
                    try:
                        return int(val)
                    except (ValueError, TypeError):
                        return None

                data["network"] = {
                    "source_ip": data.pop("source_ip", None),
                    "source_port": get_port(data.pop("source_port", None)),
                    "source_hostname": None,
                    "destination_ip": data.pop("dest_ip", None),
                    "destination_port": get_port(data.pop("dest_port", None)),
                    "destination_hostname": None,
                    "protocol": None
                }
            
            if "actor" not in data and "username" in data:
                data["actor"] = {
                    "username": data.pop("username", None),
                    "user_id": None,
                    "domain": None
                }
            
            if "process" not in data and "process_name" in data:
                data["process"] = {
                    "name": data.pop("process_name", None),
                    "pid": None,
                    "command_line": None,
                    "parent_process": None
                }
            
            if "file" not in data and "file_path" in data:
                data["file"] = {
                    "name": None,
                    "path": data.pop("file_path", None),
                    "hash_md5": None,
                    "hash_sha256": None
                }
            
            # Convert flat attack fields to nested structure
            if "attack_classification" not in data:
                data["attack_classification"] = {
                    "attack_type": data.pop("attack_type", None),
                    "event_category": data.pop("event_category", "other"),
                    "mitre_techniques": data.pop("mitre_techniques", []),
                    "mitre_tactics": data.pop("mitre_tactics", [])
                }
            
            # Convert iocs to indicators_of_compromise
            if "iocs" in data and "indicators_of_compromise" not in data:
                data["indicators_of_compromise"] = data.pop("iocs", [])
            
            # Use action as finding_description if available
            if "action" in data and "finding_description" not in data:
                data["finding_description"] = data.pop("action", "")
            
            # Ensure required fields exist with defaults
            defaults = {
                "finding": "Unmapped Log Event",
                "finding_description": "",
                "severity": "Medium",
                "confidence": 0.5,
                "network": {
                    "source_ip": None, "source_port": None, "source_hostname": None,
                    "destination_ip": None, "destination_port": None, "destination_hostname": None,
                    "protocol": None
                },
                "actor": {"username": None, "user_id": None, "domain": None},
                "process": {"name": None, "pid": None, "command_line": None, "parent_process": None},
                "file": {"name": None, "path": None, "hash_md5": None, "hash_sha256": None},
                "attack_classification": {"attack_type": None, "event_category": "other", "mitre_techniques": [], "mitre_tactics": []},
                "indicators_of_compromise": [],
                "recommended_action": "Review manually",
                "reasoning": "AI analysis completed"
            }
            
            # Merge defaults with parsed data (nested merge)
            for key, default_value in defaults.items():
                if key not in data:
                    data[key] = default_value
                elif isinstance(default_value, dict) and isinstance(data[key], dict):
                    for nested_key, nested_default in default_value.items():
                        if nested_key not in data[key]:
                            data[key][nested_key] = nested_default
            
            # Ensure confidence is float between 0 and 1 - robust handling
            conf_value = data.get("confidence")
            try:
                if conf_value is None:
                    data["confidence"] = 0.5
                else:
                    data["confidence"] = max(0.0, min(1.0, float(conf_value)))
            except (TypeError, ValueError):
                logger.warning(f"Invalid confidence value: {conf_value}, using default 0.5")
                data["confidence"] = 0.5
            
            return data
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {e}")
            logger.error(f"Response was: {cleaned}")
            raise ValueError(f"LLM returned invalid JSON: {e}")
    
    def _requires_human_review(self, mapped_data: Dict) -> bool:
        """Determine if this mapping requires human review"""
        
        confidence = mapped_data.get("confidence", 0)
        severity = mapped_data.get("severity", "Medium").lower()
        
        # Review criteria
        if confidence < self.confidence_threshold:
            mapped_data["review_reason"] = "Low confidence"
            return True
        
        if severity in ["critical", "high"]:
            mapped_data["review_reason"] = "High/Critical severity"
            return True
        
        return False
    
    def _create_fallback_mapping(self, raw_log: str, error: str) -> Dict:
        """Create a fallback mapping when AI fails - uses regex extraction and EventClassifier"""
        
        # Use regex extraction for basic fields
        extracted = get_extraction_result(raw_log)
        
        # Use EventClassifier for accurate class/category
        classification = event_classifier.classify({"message": raw_log})
        
        return {
            "finding": "Unmapped Log Event - AI Parsing Failed",
            "severity": "Medium",  # Default to medium, not unknown
            "confidence": 0.0,
            "source_ip": extracted.get("source_ip"),
            "destination_ip": extracted.get("destination_ip"),
            "source_port": extracted.get("source_port"),
            "destination_port": extracted.get("destination_port"),
            "username": extracted.get("username"),
            "attack_type": None,
            "action_taken": None,
            "protocol": extracted.get("protocol"),
            "event_category": classification.category,
            "indicators_of_compromise": [],
            "recommended_action": "Manual review required - AI processing failed",
            "reasoning": f"AI mapper encountered an error: {error}",
            "raw_log": raw_log,
            "ai_processed_at": datetime.utcnow().isoformat(),
            "ai_model_used": self.model_name,
            "processing_status": "mapping_failed_requires_manual_review",
            "review_reason": "AI processing failure",
            # Include classification info for ULF building
            "_classification": {
                "class_uid": classification.class_uid,
                "class_name": classification.class_name,
                "category_uid": classification.category_uid,
                "category_name": classification.category,
            }
        }
    
    async def health_check(self) -> Dict:
        """Check if the LLM service is available"""
        
        try:
            # Try to get models list
            models_url = self.llm_url.replace("/v1/chat/completions", "/v1/models")
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(models_url)
                response.raise_for_status()
                
                models = response.json()
                
                return {
                    "status": "healthy",
                    "llm_url": self.llm_url,
                    "model_name": self.model_name,
                    "available_models": models.get("data", [])
                }
                
        except Exception as e:
            logger.error(f"LLM health check failed: {e}")
            return {
                "status": "unhealthy",
                "llm_url": self.llm_url,
                "model_name": self.model_name,
                "error": str(e)
            }
    
    def _parse_timestamp(self, time_str: str) -> datetime:
        """Parse timestamp string to datetime object using standard library"""
        from datetime import datetime
        if not time_str:
            return datetime.utcnow()
            
        try:
            # Try ISO format matching (e.g., 2024-01-15T14:23:45Z)
            # Remove Z for fromisoformat if present (handle generic UTC)
            clean_str = time_str.replace('Z', '+00:00')
            return datetime.fromisoformat(clean_str)
        except ValueError:
            pass
            
        try:
            # Try Syslog format (Jan 15 14:23:45) - assumes current year
            current_year = datetime.utcnow().year
            dt = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
            return dt
        except ValueError:
            pass
            
        try:
            # Try common format (2024-01-15 14:23:45)
            return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

        return datetime.utcnow()

    async def map_to_ulf(
        self,
        raw_log: str,
        source: str = "unknown"
    ) -> Tuple['UnifiedLogFormat', float]:
        """
        Map raw log to ULF format using AI with enhanced OCSF field extraction
        
        Returns:
            Tuple of (UnifiedLogFormat object, confidence score)
        """
        from schemas.ulf_schema import (
            UnifiedLogFormat,
            SeverityEnum,
            StatusEnum,
            Metadata,
            Product,
            Finding,
            Endpoint,
            Observable,
            User,
            Process,
            File,
            Resource
        )
        from datetime import datetime
        import uuid
        
        # Get AI mapping
        mapped_data, needs_review = await self.map_log_event(raw_log)
        
        # Extract confidence
        confidence = mapped_data.get("confidence", 0.5)
        
        # Map severity string to enum
        severity_str = mapped_data.get("severity", "Medium")
        severity_map = {
            "Critical": (SeverityEnum.CRITICAL, "Critical"),
            "High": (SeverityEnum.HIGH, "High"),
            "Medium": (SeverityEnum.MEDIUM, "Medium"),
            "Low": (SeverityEnum.LOW, "Low"),
            "Informational": (SeverityEnum.INFORMATIONAL, "Informational"),
        }
        severity_id, severity = severity_map.get(
            severity_str,
            (SeverityEnum.MEDIUM, "Medium")
        )
        
        # Generate alert ID
        alert_id = f"SOAR-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        
        # Parse original timestamp
        extracted_time_str = mapped_data.get("timestamp")
        original_time_dt = self._parse_timestamp(extracted_time_str)
        
        # Build metadata
        metadata = Metadata(
            version="1.1.0",
            product=Product(
                name=f"AI Mapper ({source})",
                vendor_name="SOAR Platform",
                version="1.0.0"
            ),
            original_time=original_time_dt,
            logged_time=datetime.utcnow()
        )
        
        # Extract MITRE ATT&CK techniques
        attack_class = mapped_data.get("attack_classification", {})
        mitre_techniques = attack_class.get("mitre_techniques", [])
        
        # Build finding with MITRE techniques
        finding = Finding(
            title=mapped_data.get("finding", "AI-Mapped Security Event"),
            desc=mapped_data.get("finding_description") or mapped_data.get("reasoning", ""),
            uid=alert_id,
            types=mitre_techniques,  # MITRE ATT&CK technique IDs
            src_url=None
        )
        
        # Build source endpoint from network data
        network = mapped_data.get("network", {})
        src_endpoint = None
        if network.get("source_ip"):
            try:
                src_endpoint = Endpoint(
                    ip=network.get("source_ip"),
                    port=int(network.get("source_port")) if network.get("source_port") else None,
                    hostname=network.get("source_hostname")
                )
            except Exception as e:
                logger.warning(f"Failed to create source endpoint: {e}")
        
        # Build destination endpoint from network data
        dst_endpoint = None
        if network.get("destination_ip"):
            try:
                dst_endpoint = Endpoint(
                    ip=network.get("destination_ip"),
                    port=int(network.get("destination_port")) if network.get("destination_port") else None,
                    hostname=network.get("destination_hostname")
                )
            except Exception as e:
                logger.warning(f"Failed to create destination endpoint: {e}")
        
        # Build actor (user) from actor data
        actor_data = mapped_data.get("actor", {})
        actor = None
        if actor_data.get("username"):
            try:
                actor = User(
                    name=actor_data.get("username"),
                    uid=actor_data.get("user_id"),
                    domain=actor_data.get("domain")
                )
            except Exception as e:
                logger.warning(f"Failed to create actor: {e}")
        
        # Build process from process data
        process_data = mapped_data.get("process", {})
        process = None
        if process_data.get("name"):
            try:
                process = Process(
                    name=process_data.get("name"),
                    pid=int(process_data.get("pid")) if process_data.get("pid") else None,
                    cmd_line=process_data.get("command_line"),
                    parent_process=process_data.get("parent_process")
                )
            except Exception as e:
                logger.warning(f"Failed to create process: {e}")
        
        # Build file from file data
        file_data = mapped_data.get("file", {})
        file = None
        if file_data.get("name") or file_data.get("path"):
            try:
                file_hash = {}
                if file_data.get("hash_md5"):
                    file_hash["md5"] = file_data.get("hash_md5")
                if file_data.get("hash_sha256"):
                    file_hash["sha256"] = file_data.get("hash_sha256")
                
                file = File(
                    name=file_data.get("name"),
                    path=file_data.get("path"),
                    hash=file_hash if file_hash else None
                )
            except Exception as e:
                logger.warning(f"Failed to create file: {e}")
        
        # Build resources
        resources = []
        if dst_endpoint and dst_endpoint.hostname:
            resources.append(Resource(
                name=dst_endpoint.hostname,
                type="Server",
                uid=None
            ))
        
        # Build observables from IOCs
        observables = []
        iocs = mapped_data.get("indicators_of_compromise", [])
        for ioc in iocs:
            if isinstance(ioc, dict):
                observables.append(Observable(
                    name=ioc.get("type", "ioc"),
                    type=ioc.get("type", "Indicator").title(),
                    value=str(ioc.get("value", ""))
                ))
            else:
                # Legacy format support
                observables.append(Observable(
                    name="ioc",
                    type="Indicator",
                    value=str(ioc)
                ))
        
        # Add network endpoints as observables
        if src_endpoint and src_endpoint.ip:
            observables.append(Observable(
                name="source_ip",
                type="IP Address",
                value=src_endpoint.ip
            ))
        if dst_endpoint and dst_endpoint.ip:
            observables.append(Observable(
                name="destination_ip",
                type="IP Address",
                value=dst_endpoint.ip
            ))
        
        # Determine OCSF class - prefer EventClassifier for accuracy
        # Check if fallback mapping provided classification info
        if "_classification" in mapped_data:
            cls_info = mapped_data["_classification"]
            class_uid = cls_info["class_uid"]
            class_name = cls_info["class_name"]
            category_uid = cls_info["category_uid"]
            category_name = cls_info["category_name"]
            type_uid = class_uid * 100 + 1  # Default type
        else:
            # Use EventClassifier for accurate classification
            classification = event_classifier.classify({"message": raw_log})
            class_uid = classification.class_uid
            class_name = classification.class_name
            category_uid = classification.category_uid
            category_name = classification.category
            type_uid = class_uid * 100 + 1
        
        # Create ULF object with all extracted fields
        ulf = UnifiedLogFormat(
            class_uid=class_uid,
            class_name=class_name,
            category_uid=category_uid,
            category_name=category_name,
            severity_id=severity_id,
            severity=severity,
            activity_id=1,
            activity_name="Create",
            type_uid=type_uid,
            time=int(datetime.utcnow().timestamp() * 1000),
            status=StatusEnum.NEW,
            metadata=metadata,
            finding=finding,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            actor=actor,
            process=process,
            file=file,
            resources=resources,
            observables=observables,
            raw_data=raw_log,
            unmapped={
                "ai_mapped": True,
                "ai_confidence": confidence,
                "ai_needs_review": needs_review,
                "ai_attack_type": attack_class.get("attack_type"),
                "ai_event_category": attack_class.get("event_category"),
                "ai_recommended_action": mapped_data.get("recommended_action"),
                "ai_reasoning": mapped_data.get("reasoning"),
                "ai_network_protocol": network.get("protocol")
            },
            alert_id=alert_id,
            siem_source=source,
            ingestion_timestamp=datetime.utcnow(),
            processing_status="ai_mapped"
        )
        
        return ulf, confidence
    
    def _determine_ocsf_class(self, event_category: str, attack_type: str = None) -> tuple:
        """
        Determine OCSF class_uid and class_name based on event category
        
        Returns:
            Tuple of (class_uid, class_name, category_uid, category_name, type_uid)
        """
        
        # Map event categories to OCSF classes
        category_map = {
            # Authentication events
            "authentication": (
                3002,  # class_uid
                "Authentication",  # class_name
                3,  # category_uid (Identity & Access Management)
                "Identity & Access Management",  # category_name
                300201  # type_uid (Logon)
            ),
            
            # Network events
            "network": (
                4001,  # Network Activity
                "Network Activity",
                4,  # Network Activity category
                "Network Activity",
                400101  # Traffic
            ),
            
            # Malware/Security findings
            "malware": (
                2001,  # Security Finding
                "Security Finding",
                2,  # Findings
                "Findings",
                200101  # Vulnerability Finding
            ),
            
            # File access
            "data_access": (
                1001,  # File System Activity
                "File System Activity",
                1,  # System Activity
                "System Activity",
                100101  # File Access
            ),
            
            # Data exfiltration
            "data_exfiltration": (
                4011,  # Network File Activity
                "Network File Activity",
                4,  # Network Activity
                "Network Activity",
                401101  # File Upload
            ),
            
            # Privilege escalation
            "privilege_escalation": (
                3001,  # Account Change
                "Account Change",
                3,  # Identity & Access Management
                "Identity & Access Management",
                300101  # User Access Management
            ),
            
            # System events
            "system": (
                1002,  # Kernel Activity
                "Kernel Activity",
                1,  # System Activity
                "System Activity",
                100201  # Kernel Extension
            ),
            
            # Application events
            "application": (
                6001,  # Web Resources Activity
                "Web Resources Activity",
                6,  # Application Activity
                "Application Activity",
                600101  # HTTP Activity
            ),
        }
        
        # Get mapping or default to Detection Finding
        mapping = category_map.get(
            event_category.lower() if event_category else "other",
            (2004, "Detection Finding", 2, "Findings", 200401)  # Default
        )
        
        return mapping

