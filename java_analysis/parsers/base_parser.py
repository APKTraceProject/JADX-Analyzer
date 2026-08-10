from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    """Abstract base class for all parsers."""

    @abstractmethod
    def parse(self, *args: Any, **kwargs: Any) -> Any:
        """Parse source input and return extracted metadata payload."""
        pass
