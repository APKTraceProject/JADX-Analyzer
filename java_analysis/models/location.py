from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class Location:
    """Represents a source code location and matched evidence context."""
    source_file: str
    source_origin: str
    class_name: Optional[str] = None
    line: int = 0
    evidence: str = ""
    matched_line: int = 0
    matched_code: str = ""
    context: Optional[Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert location object to dictionary representation."""
        return {
            "source_file": self.source_file,
            "source_origin": self.source_origin,
            "class_name": self.class_name,
            "line": self.line,
            "evidence": self.evidence,
            "matched_line": self.matched_line,
            "matched_code": self.matched_code,
            "context": self.context,
        }
