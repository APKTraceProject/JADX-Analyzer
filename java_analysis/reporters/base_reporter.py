from abc import ABC, abstractmethod
from typing import Any


class BaseReporter(ABC):
    """Abstract base class for analysis result reporters."""

    @abstractmethod
    def report(self, *args: Any, **kwargs: Any) -> Any:
        """Write or output analysis results."""
        pass
