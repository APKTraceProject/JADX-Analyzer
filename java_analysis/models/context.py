from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class CodeContext:
    """Represents a code snippet context surrounding a match."""
    start_line: int
    end_line: int
    code: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert code context to dictionary representation."""
        return {
            "start_line": self.start_line,
            "end_line": self.end_line,
            "code": self.code,
        }
