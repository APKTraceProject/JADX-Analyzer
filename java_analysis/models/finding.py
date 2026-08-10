from dataclasses import dataclass, field
from typing import List, Dict, Any
from java_analysis.models.location import Location


@dataclass
class Finding:
    """Represents a security behavior finding or pattern match."""
    behavior_id: str
    name: str
    category: str
    priority: str
    related_permissions: List[str] = field(default_factory=list)
    source_counts: Dict[str, int] = field(default_factory=dict)
    classes: List[str] = field(default_factory=list)
    source_files: List[str] = field(default_factory=list)
    evidence: List[Location] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding object to dictionary representation."""
        return {
            "behavior_id": self.behavior_id,
            "name": self.name,
            "category": self.category,
            "priority": self.priority,
            "related_permissions": self.related_permissions,
            "source_counts": self.source_counts,
            "classes": self.classes,
            "source_files": self.source_files,
            "evidence": [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.evidence
            ],
        }
