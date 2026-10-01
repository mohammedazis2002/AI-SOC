"""
MITRE ATT&CK Pattern Library Generator

Downloads official MITRE ATT&CK Enterprise data and generates
a pattern matching library for alert enrichment.

Output: data/mitre/attack_patterns.json

Usage:
    python scripts/build_pattern_library.py
"""

import json
import re
import logging
from typing import Dict, List, Any, Set
from pathlib import Path
import urllib.request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MITRE ATT&CK data source
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Tactic mapping (14 MITRE tactics)
TACTIC_MAPPING = {
    'TA0043': 'reconnaissance',
    'TA0042': 'resource-development',
    'TA0001': 'initial-access',
    'TA0002': 'execution',
    'TA0003': 'persistence',
    'TA0004': 'privilege-escalation',
    'TA0005': 'defense-evasion',
    'TA0006': 'credential-access',
    'TA0007': 'discovery',
    'TA0008': 'lateral-movement',
    'TA0009': 'collection',
    'TA0011': 'command-and-control',
    'TA0010': 'exfiltration',
    'TA0040': 'impact'
}


class MITREPatternLibraryGenerator:
    """Generate pattern matching library from MITRE ATT&CK data"""
    
    def __init__(self):
        self.attack_data = None
        self.pattern_library = {tactic: [] for tactic in TACTIC_MAPPING.values()}
        
    def download_mitre_data(self, save_path: str = 'data/mitre/enterprise-attack.json') -> bool:
        """
        Download official MITRE ATT&CK Enterprise data
        
        Args:
            save_path: Local path to save the data
            
        Returns:
            True if successful
        """
        logger.info(f"Downloading MITRE ATT&CK data from {MITRE_ATTACK_URL}")
        
        try:
            # Create directory if needed
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Download
            with urllib.request.urlopen(MITRE_ATTACK_URL) as response:
                data = response.read()
            
            # Save to file
            with open(save_path, 'wb') as f:
                f.write(data)
            
            logger.info(f"Downloaded {len(data)} bytes to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download MITRE data: {e}")
            return False
    
    def load_mitre_data(self, data_path: str = 'data/mitre/enterprise-attack.json') -> bool:
        """
        Load MITRE ATT&CK data from file
        
        Args:
            data_path: Path to MITRE data JSON
            
        Returns:
            True if successful
        """
        try:
            with open(data_path, 'r', encoding='utf-8') as f:
                self.attack_data = json.load(f)
            
            logger.info(f"Loaded MITRE data with {len(self.attack_data.get('objects', []))} objects")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            return False
    
    def extract_keywords(self, text: str, max_keywords: int = 10) -> List[str]:
        """
        Extract relevant keywords from technique description
        
        Args:
            text: Description text
            max_keywords: Maximum keywords to extract
            
        Returns:
            List of keywords
        """
        if not text:
            return []
        
        # Clean text
        text = text.lower()
        
        # Remove common words
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be',
            'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
            'would', 'could', 'should', 'may', 'might', 'can', 'this', 'that',
            'these', 'those', 'adversaries', 'adversary', 'attackers', 'attacker',
            'techniques', 'technique', 'may', 'use', 'used', 'using'
        }
        
        # Extract potential keywords (words 3+ chars, alphanumeric with hyphens/underscores)
        words = re.findall(r'\b[a-z0-9_-]{3,}\b', text)
        
        # Filter stop words
        keywords = [w for w in words if w not in stop_words]
        
        # Count frequency
        word_freq = {}
        for word in keywords:
            word_freq[word] = word_freq.get(word, 0) + 1
        
        # Sort by frequency and return top N
        sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
        
        return [word for word, _ in sorted_words[:max_keywords]]
    
    def extract_technical_terms(self, name: str, description: str) -> Set[str]:
        """
        Extract technical terms, tool names, commands from technique
        
        Args:
            name: Technique name
            description: Technique description
            
        Returns:
            Set of technical terms
        """
        terms = set()
        
        # Add words from technique name
        name_words = re.findall(r'\b[a-z0-9_.-]+\b', name.lower())
        terms.update(name_words)
        
        # Extract commands (text in backticks or quotes)
        commands = re.findall(r'`([^`]+)`|"([^"]+)"', description)
        for cmd_group in commands:
            for cmd in cmd_group:
                if cmd:
                    # Extract command/tool names
                    cmd_parts = re.findall(r'\b[a-z0-9_.-]+\b', cmd.lower())
                    terms.update(cmd_parts)
        
        # Extract file extensions
        extensions = re.findall(r'\.[a-z]{2,4}\b', description.lower())
        terms.update(extensions)
        
        # Extract registry paths (common patterns)
        if 'registry' in description.lower():
            terms.add('registry')
            terms.add('reg')
        
        # Extract process names
        exe_names = re.findall(r'\b\w+\.exe\b', description.lower())
        terms.update(exe_names)
        
        # Extract protocols
        protocols = re.findall(r'\b(http|https|ftp|ssh|rdp|smb|dns|tcp|udp)\b', description.lower())
        terms.update(protocols)
        
        return terms
    
    
    def build_pattern_library(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build complete pattern matching library
        
        Returns:
            Pattern library dictionary
        """
        if not self.attack_data:
            logger.error("No MITRE data loaded")
            return {}
        
        logger.info("Building pattern library...")
        
        techniques_processed = 0
        
        for obj in self.attack_data.get('objects', []):
            # Process only techniques
            if obj.get('type') != 'attack-pattern':
                continue
            
            # Skip deprecated/revoked
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue
            
            # Get technique details
            technique_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break
            
            if not technique_id:
                continue
            
            name = obj.get('name', '')
            description = obj.get('description', '')
            
            # Get tactics (kill chain phases)
            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                phase_name = phase.get('phase_name', '')
                if phase_name in TACTIC_MAPPING.values():
                    tactics.append(phase_name)
            
            if not tactics:
                continue
            
            # Extract keywords and technical terms
            keywords = self.extract_keywords(description)
            technical_terms = self.extract_technical_terms(name, description)
            
            # Combine all patterns
            all_patterns = list(set(keywords) | technical_terms)
            
            # Remove generic terms
            all_patterns = [p for p in all_patterns if len(p) > 2]
            
            if not all_patterns:
                continue
            
            # Add to each tactic
            for tactic in tactics:
                pattern_entry = {
                    'technique_id': technique_id,
                    'technique_name': name,
                    'keywords': all_patterns[:15]  # Limit to top 15
                }
                
                self.pattern_library[tactic].append(pattern_entry)
            
            techniques_processed += 1
            
            if techniques_processed % 50 == 0:
                logger.info(f"Processed {techniques_processed} techniques...")
        
        logger.info(f"Pattern library built with {techniques_processed} techniques")
        
        # Log statistics
        for tactic, patterns in self.pattern_library.items():
            logger.info(f"  {tactic}: {len(patterns)} patterns")
        
        return self.pattern_library
    
    def save_pattern_library(self, output_path: str = 'data/mitre/attack_patterns.json'):
        """
        Save pattern library to JSON file
        
        Args:
            output_path: Output file path
        """
        try:
            # Create directory if needed
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.pattern_library, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Pattern library saved to {output_path}")
            
            # Log file size
            file_size = Path(output_path).stat().st_size
            logger.info(f"File size: {file_size:,} bytes ({file_size/1024:.1f} KB)")
            
        except Exception as e:
            logger.error(f"Failed to save pattern library: {e}")


def main():
    """Main execution"""
    logger.info("=" * 80)
    logger.info("MITRE ATT&CK Pattern Library Generator")
    logger.info("=" * 80)
    
    generator = MITREPatternLibraryGenerator()
    
    # Step 1: Download MITRE data
    logger.info("\nStep 1: Downloading MITRE ATT&CK data...")
    if not generator.download_mitre_data():
        logger.error("Failed to download MITRE data. Exiting.")
        return False
    
    # Step 2: Load MITRE data
    logger.info("\nStep 2: Loading MITRE data...")
    if not generator.load_mitre_data():
        logger.error("Failed to load MITRE data. Exiting.")
        return False
    
    # Step 3: Build pattern library
    logger.info("\nStep 3: Building pattern library...")
    generator.build_pattern_library()
    
    # Step 4: Save pattern library
    logger.info("\nStep 4: Saving pattern library...")
    generator.save_pattern_library()
    
    logger.info("\n" + "=" * 80)
    logger.info("Pattern library generation complete!")
    logger.info("=" * 80)
    logger.info("\nPattern library saved to: data/mitre/attack_patterns.json")
    logger.info("Use this file with MITREEnricher by providing the path:")
    logger.info("  enricher = MITREEnricher('data/mitre/attack_patterns.json')")
    
    return True


if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)
