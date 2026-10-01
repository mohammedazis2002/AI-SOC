"""
Extraction Helpers

Shared regex-based extraction utilities for all log mappers.
Extracts IPs, ports, usernames, and file paths from raw log text.
"""
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class NetworkInfo:
    """Extracted network information"""
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None


@dataclass
class ExtractionResult:
    """All extracted information from a log"""
    network: NetworkInfo
    username: Optional[str] = None
    file_path: Optional[str] = None
    process_name: Optional[str] = None
    hostname: Optional[str] = None


# Regex patterns
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# IP with port: 192.168.1.1:8080 or 192.168.1.1 port 8080
IP_PORT_PATTERN = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s]+(\d{1,5})'
)

# Arrow pattern: 10.0.0.1:80 -> 10.0.0.2:443
ARROW_PATTERN = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\s*[-=]>\s*'
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
)

# "from IP" pattern (common in auth logs)
FROM_IP_PATTERN = re.compile(
    r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s+port\s+(\d{1,5}))?',
    re.IGNORECASE
)

# Port patterns
PORT_PATTERN = re.compile(r'\bport\s+(\d{1,5})\b', re.IGNORECASE)

# Username patterns
USERNAME_PATTERNS = [
    re.compile(r"(?:user|username|user_name|login|account)[=:\s]+['\"]?(\w+)['\"]?", re.IGNORECASE),
    re.compile(r"for\s+(?:user\s+)?['\"]?(\w+)['\"]?\s+from", re.IGNORECASE),
    re.compile(r"User\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"user=(\w+)", re.IGNORECASE),
]

# File path patterns (Windows and Unix)
FILE_PATH_PATTERNS = [
    re.compile(r'([A-Za-z]:\\[^\s"\'<>|]+)', re.IGNORECASE),  # Windows
    re.compile(r'(/(?:[\w.-]+/)*[\w.-]+)', re.IGNORECASE),  # Unix
]

# Process name patterns
PROCESS_PATTERNS = [
    re.compile(r'(\w+)\[(\d+)\]:', re.IGNORECASE),  # sshd[12345]:
    re.compile(r'process[=:\s]+["\']?(\w+)["\']?', re.IGNORECASE),
    re.compile(r'cmd=["\']?([^"\']+)["\']?', re.IGNORECASE),
]

# Protocol patterns
PROTOCOL_PATTERN = re.compile(
    r'\b(TCP|UDP|ICMP|HTTP|HTTPS|SSH|FTP|DNS|SMTP|RDP|SMB)\b',
    re.IGNORECASE
)


def extract_ip_addresses(text: str) -> List[str]:
    """Extract all IP addresses from text"""
    if not text:
        return []
    return IP_PATTERN.findall(text)


def extract_network_info(text: str) -> NetworkInfo:
    """
    Extract network information (source/dest IPs and ports) from text.
    Uses multiple patterns to identify source vs destination.
    """
    if not text:
        return NetworkInfo()
    
    result = NetworkInfo()
    
    # Try arrow pattern first (most explicit: src:port -> dst:port)
    arrow_match = ARROW_PATTERN.search(text)
    if arrow_match:
        result.source_ip = arrow_match.group(1)
        result.source_port = int(arrow_match.group(2)) if arrow_match.group(2) else None
        result.destination_ip = arrow_match.group(3)
        result.destination_port = int(arrow_match.group(4)) if arrow_match.group(4) else None
    else:
        # Try "from IP port X" pattern (common in auth logs)
        from_match = FROM_IP_PATTERN.search(text)
        if from_match:
            result.source_ip = from_match.group(1)
            if from_match.group(2):
                result.source_port = int(from_match.group(2))
        
        # Get all IPs
        all_ips = extract_ip_addresses(text)
        
        # If we have a source from "from" pattern, remaining IPs might be destination
        if result.source_ip and len(all_ips) > 1:
            for ip in all_ips:
                if ip != result.source_ip:
                    result.destination_ip = ip
                    break
        elif not result.source_ip and all_ips:
            # Just take first IP as source if no explicit pattern matched
            result.source_ip = all_ips[0]
            if len(all_ips) > 1:
                result.destination_ip = all_ips[1]
    
    # Extract protocol
    proto_match = PROTOCOL_PATTERN.search(text)
    if proto_match:
        result.protocol = proto_match.group(1).upper()
    
    return result


def extract_username(text: str) -> Optional[str]:
    """Extract username from text"""
    if not text:
        return None
    
    for pattern in USERNAME_PATTERNS:
        match = pattern.search(text)
        if match:
            username = match.group(1)
            # Filter out common false positives
            if username.lower() not in ['invalid', 'unknown', 'none', 'null', 'system']:
                return username
    
    return None


def extract_file_path(text: str) -> Optional[str]:
    """Extract file path from text (Windows or Unix)"""
    if not text:
        return None
    
    for pattern in FILE_PATH_PATTERNS:
        match = pattern.search(text)
        if match:
            path = match.group(1)
            # Basic validation
            if len(path) > 3 and not path.startswith('http'):
                return path
    
    return None


def extract_process_info(text: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Extract process name and PID from text.
    Returns (process_name, pid)
    """
    if not text:
        return None, None
    
    for pattern in PROCESS_PATTERNS:
        match = pattern.search(text)
        if match:
            groups = match.groups()
            if len(groups) >= 2:
                try:
                    return groups[0], int(groups[1])
                except (ValueError, TypeError):
                    return groups[0], None
            return groups[0], None
    
    return None, None


def extract_hostname(text: str) -> Optional[str]:
    """Extract hostname from text"""
    if not text:
        return None
    
    # Common patterns for hostnames in logs
    patterns = [
        re.compile(r'^(\w+)\s+\w+\s+\d+', re.MULTILINE),  # syslog format: hostname month day
        re.compile(r'host[=:\s]+["\']?([a-zA-Z0-9.-]+)["\']?', re.IGNORECASE),
        re.compile(r'hostname[=:\s]+["\']?([a-zA-Z0-9.-]+)["\']?', re.IGNORECASE),
    ]
    
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            hostname = match.group(1)
            # Filter out common non-hostnames
            if hostname.lower() not in ['jan', 'feb', 'mar', 'apr', 'may', 'jun',
                                        'jul', 'aug', 'sep', 'oct', 'nov', 'dec']:
                return hostname
    
    return None


def extract_all(text: str) -> ExtractionResult:
    """
    Extract all available information from log text.
    Returns ExtractionResult with all extracted fields.
    """
    network = extract_network_info(text)
    process_name, _ = extract_process_info(text)
    
    return ExtractionResult(
        network=network,
        username=extract_username(text),
        file_path=extract_file_path(text),
        process_name=process_name,
        hostname=extract_hostname(text)
    )


# Convenience instance for direct import
def get_extraction_result(text: str) -> Dict:
    """
    Get extraction result as a dictionary for easy integration.
    Only includes non-None values.
    """
    result = extract_all(text)
    
    output = {}
    
    # Network info
    if result.network.source_ip:
        output['source_ip'] = result.network.source_ip
    if result.network.source_port:
        output['source_port'] = result.network.source_port
    if result.network.destination_ip:
        output['destination_ip'] = result.network.destination_ip
    if result.network.destination_port:
        output['destination_port'] = result.network.destination_port
    if result.network.protocol:
        output['protocol'] = result.network.protocol
    
    # Other fields
    if result.username:
        output['username'] = result.username
    if result.file_path:
        output['file_path'] = result.file_path
    if result.process_name:
        output['process_name'] = result.process_name
    if result.hostname:
        output['hostname'] = result.hostname
    
    return output
