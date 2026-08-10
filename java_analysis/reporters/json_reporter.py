import json
from pathlib import Path
from typing import Dict, Any
from java_analysis.reporters.base_reporter import BaseReporter


class JsonReporter(BaseReporter):
    """Writes analysis output payload to a JSON file."""

    def report(self, result_path: Path, data: Dict[str, Any]) -> Path:
        """Write report dictionary to JSON file."""
        return save_json_report(result_path=result_path, data=data)


def save_json_report(result_path: Path, data: Dict[str, Any]) -> Path:
    """Save structured result dictionary to target JSON path with explicit arguments."""
    result_path.parent.mkdir(parents=True, exist_ok=True)

    with result_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

    return result_path
