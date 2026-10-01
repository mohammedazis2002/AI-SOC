"""
OCSF Schema Loader

Loads and manages the official OCSF schema from local repository.
Provides class/category lookup and keyword-based classification support.
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class OCSFSchemaLoader:
    """Loads OCSF schema from local cloned repository"""
    
    # Path relative to project root
    SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "ocsf" / "ocsf-schema"
    
    def __init__(self):
        self.categories: Dict[str, Dict] = {}
        self.event_classes: Dict[int, Dict] = {}
        self.objects: Dict[str, Dict] = {}
        self.dictionary: Dict[str, Dict] = {}
        self._loaded = False
    
    def load_schema(self) -> None:
        """Load complete OCSF schema from local files"""
        if self._loaded:
            return
        
        if not self.SCHEMA_PATH.exists():
            logger.error(f"OCSF schema not found at {self.SCHEMA_PATH}")
            logger.error("Please clone: git clone https://github.com/ocsf/ocsf-schema.git backend/schemas/ocsf/ocsf-schema")
            raise FileNotFoundError(f"OCSF schema not found at {self.SCHEMA_PATH}")
        
        logger.info(f"Loading OCSF schema from {self.SCHEMA_PATH}")
        
        # Load categories
        self._load_categories()
        
        # Load all event classes
        self._load_event_classes()
        
        # Load dictionary
        self._load_dictionary()
        
        # Load objects (optional, for validation)
        self._load_objects()
        
        self._loaded = True
        logger.info(f"Loaded {len(self.categories)} categories, "
                   f"{len(self.event_classes)} event classes")
    
    def _load_categories(self) -> None:
        """Load categories.json"""
        path = self.SCHEMA_PATH / "categories.json"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.categories = data.get('attributes', {})
            logger.info(f"Loaded {len(self.categories)} categories")
        except Exception as e:
            logger.error(f"Failed to load categories: {e}")
            raise
    
    def _load_event_classes(self) -> None:
        """Load all event class definitions from events/ directory"""
        events_path = self.SCHEMA_PATH / "events"
        
        if not events_path.exists():
            logger.error(f"Events directory not found: {events_path}")
            return
        
        for category_dir in events_path.iterdir():
            if not category_dir.is_dir():
                continue
            
            category_name = category_dir.name
            category_info = self.categories.get(category_name, {})
            category_uid = category_info.get('uid', 0)
            
            for event_file in category_dir.glob("*.json"):
                try:
                    self._load_event_class(event_file, category_name, category_uid)
                except Exception as e:
                    logger.warning(f"Failed to load {event_file}: {e}")
    
    def _load_event_class(self, path: Path, category_name: str, category_uid: int) -> None:
        """Load individual event class JSON"""
        with open(path, 'r', encoding='utf-8') as f:
            event_data = json.load(f)
        
        # Get event UID
        event_uid = event_data.get('uid')
        if event_uid is None:
            # Some files are base/parent classes without UID
            return
        
        # Calculate class_uid: category_uid * 1000 + event_uid
        class_uid = category_uid * 1000 + event_uid
        
        self.event_classes[class_uid] = {
            'name': path.stem,
            'category': category_name,
            'category_uid': category_uid,
            'event_uid': event_uid,
            'class_uid': class_uid,
            'caption': event_data.get('caption', ''),
            'description': event_data.get('description', ''),
            'attributes': event_data.get('attributes', {}),
            'extends': event_data.get('extends'),
            'raw': event_data
        }
    
    def _load_dictionary(self) -> None:
        """Load dictionary.json for field definitions"""
        path = self.SCHEMA_PATH / "dictionary.json"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.dictionary = data.get('attributes', {})
            logger.info(f"Loaded {len(self.dictionary)} dictionary entries")
        except Exception as e:
            logger.warning(f"Failed to load dictionary: {e}")
    
    def _load_objects(self) -> None:
        """Load object definitions for validation"""
        objects_path = self.SCHEMA_PATH / "objects"
        
        if not objects_path.exists():
            return
        
        for obj_file in objects_path.glob("*.json"):
            try:
                with open(obj_file, 'r', encoding='utf-8') as f:
                    self.objects[obj_file.stem] = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load {obj_file}: {e}")
    
    def get_class(self, class_uid: int) -> Optional[Dict]:
        """Get event class by class_uid"""
        self.load_schema()
        return self.event_classes.get(class_uid)
    
    def get_class_by_name(self, name: str) -> Optional[Dict]:
        """Get event class by name (e.g., 'authentication')"""
        self.load_schema()
        for class_info in self.event_classes.values():
            if class_info['name'] == name:
                return class_info
        return None
    
    def get_category(self, name: str) -> Optional[Dict]:
        """Get category by name"""
        self.load_schema()
        cat = self.categories.get(name)
        if cat:
            return {'name': name, **cat}
        return None
    
    def get_category_by_uid(self, uid: int) -> Optional[Dict]:
        """Get category by UID"""
        self.load_schema()
        for name, info in self.categories.items():
            if info['uid'] == uid:
                return {'name': name, **info}
        return None
    
    def list_classes(self) -> List[Dict]:
        """List all event classes"""
        self.load_schema()
        return [
            {
                'class_uid': uid,
                'name': info['name'],
                'caption': info['caption'],
                'category': info['category'],
                'category_uid': info['category_uid']
            }
            for uid, info in sorted(self.event_classes.items())
        ]
    
    def list_categories(self) -> List[Dict]:
        """List all categories"""
        self.load_schema()
        return [
            {'name': name, **info}
            for name, info in sorted(self.categories.items(), key=lambda x: x[1]['uid'])
        ]
    
    def search_by_keywords(self, keywords: List[str]) -> List[Dict]:
        """Find event classes matching keywords in name/caption/description"""
        self.load_schema()
        matches = []
        
        for class_uid, class_info in self.event_classes.items():
            score = 0
            description = class_info['description'].lower()
            caption = class_info['caption'].lower()
            name = class_info['name'].lower()
            
            for keyword in keywords:
                kw = keyword.lower()
                
                # Exact match in name = highest score
                if kw == name:
                    score += 20
                elif kw in name:
                    score += 10
                
                # Match in caption
                if kw in caption:
                    score += 5
                
                # Match in description
                words_in_desc = description.split()
                if kw in words_in_desc:
                    score += 3
                elif kw in description:
                    score += 1
            
            if score > 0:
                matches.append({
                    'class_uid': class_uid,
                    'class_name': class_info['name'],
                    'caption': class_info['caption'],
                    'category': class_info['category'],
                    'category_uid': class_info['category_uid'],
                    'score': score
                })
        
        # Sort by score descending
        matches.sort(key=lambda x: x['score'], reverse=True)
        return matches
    
    def get_class_attributes(self, class_uid: int) -> Dict[str, Dict]:
        """Get all attributes for a class (including inherited)"""
        self.load_schema()
        
        class_info = self.event_classes.get(class_uid)
        if not class_info:
            return {}
        
        attributes = dict(class_info.get('attributes', {}))
        
        # TODO: Resolve inherited attributes from 'extends'
        
        return attributes
    
    def update_schema(self) -> bool:
        """Update schema via git pull"""
        try:
            result = subprocess.run(
                ['git', 'pull'],
                cwd=self.SCHEMA_PATH,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                logger.info(f"Schema updated: {result.stdout.strip()}")
                self._loaded = False  # Force reload on next access
                return True
            else:
                logger.error(f"Git pull failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("Schema update timed out")
            return False
        except FileNotFoundError:
            logger.error("Git not found - cannot update schema")
            return False
        except Exception as e:
            logger.error(f"Schema update failed: {e}")
            return False
    
    def get_schema_version(self) -> str:
        """Get OCSF schema version"""
        version_file = self.SCHEMA_PATH / "version.json"
        try:
            with open(version_file, 'r') as f:
                data = json.load(f)
            return data.get('version', 'unknown')
        except:
            return 'unknown'


# Global singleton instance
schema_loader = OCSFSchemaLoader()
