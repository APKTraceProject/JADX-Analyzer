from abc import ABC, abstractmethod
from typing import Any


class BaseAnalyzer(ABC):
    """Abstract base class for all code analyzers."""

    @abstractmethod
    def analyze(self, *args: Any, **kwargs: Any) -> Any:
        """Analyze source code and return findings payload."""
        pass
