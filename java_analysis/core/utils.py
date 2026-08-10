import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, List, Optional, Dict

try:
    import yaml
except ImportError:
    yaml = None

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
TRAILING_CHARACTERS = ".,;:!?)]}>\"'"

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "io", "ai", "app", "dev",
    "info", "biz", "me", "tv", "co", "us", "uk", "de", "fr", "it", "es",
    "nl", "be", "ch", "at", "se", "no", "dk", "fi", "pl", "cz", "ru",
    "ua", "tr", "ir", "ae", "sa", "qa", "in", "pk", "cn", "jp", "kr",
    "tw", "hk", "sg", "id", "au", "nz", "ca", "br", "mx", "ar", "za",
    "online", "site", "tech", "store", "cloud", "network", "website",
    "services", "systems", "solutions", "digital", "media", "software",
    "company", "global", "world", "mobile", "pro", "xyz", "top", "live",
    "news", "blog", "space", "today"
}


def find_manifest(output_dir: Path) -> Path:
    """Find AndroidManifest.xml in JADX output directory."""
    possible_paths = [
        output_dir / "resources" / "AndroidManifest.xml",
        output_dir / "AndroidManifest.xml"
    ]

    for manifest_path in possible_paths:
        if manifest_path.is_file():
            return manifest_path

    manifests = list(output_dir.rglob("AndroidManifest.xml"))
    if manifests:
        return manifests[0]

    raise FileNotFoundError("AndroidManifest.xml was not found in JADX output.")


def get_android_attribute(element: Any, attribute_name: str) -> Optional[str]:
    """Get an Android XML attribute from an ElementTree element."""
    possible_names = [
        f"{{{ANDROID_NAMESPACE}}}{attribute_name}",
        f"android:{attribute_name}",
        attribute_name
    ]

    for name in possible_names:
        value = element.get(name)
        if value is not None:
            return value

    return None


def convert_number(value: Optional[str]) -> Any:
    """Convert numeric string values (including hex)."""
    if value is None:
        return None

    value = value.strip()
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return value


def convert_boolean(value: Optional[str]) -> Optional[bool]:
    """Convert string boolean values ('true'/'false')."""
    if value is None:
        return None

    val = value.strip().lower()
    if val == "true":
        return True
    if val == "false":
        return False

    return None


def find_source_directory(output_dir: Path) -> Path:
    """Find the decompiled Java source directory."""
    possible_directories = [
        output_dir / "sources",
        output_dir / "src"
    ]

    for directory in possible_directories:
        if directory.is_dir():
            return directory

    for directory in output_dir.rglob("*"):
        if directory.is_dir() and directory.name.lower() in {"sources", "src"}:
            return directory

    raise FileNotFoundError("Decompiled Java source directory was not found in JADX output.")


def find_java_files(source_dir: Path) -> List[Path]:
    """Find and sort all decompiled Java files in the source directory."""
    java_files = [f for f in source_dir.rglob("*.java") if f.is_file()]
    java_files.sort(key=lambda item: str(item))
    return java_files


def read_source_file(file_path: Path) -> str:
    """Read Java source file content safely."""
    try:
        return file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise RuntimeError(f"Unable to read Java file:\n{file_path}") from error


def clean_indicator(value: str) -> str:
    """Remove trailing punctuation characters from network indicators."""
    return value.rstrip(TRAILING_CHARACTERS)


def is_valid_ipv4(value: str) -> bool:
    """Validate whether string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Validate a domain name against structure and TLD lists."""
    value = value.lower().strip(".")
    if not value or len(value) > 253:
        return False

    if is_valid_ipv4(value):
        return False

    labels = value.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False

    tld = labels[-1]
    if tld not in COMMON_TLDS:
        return False

    return True


DEFAULT_STATIC_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "rules.yaml"


def load_yaml_or_json(file_path: Path) -> Any:
    """Load configuration or rules file supporting both YAML and JSON formats."""
    if not file_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    content = file_path.read_text(encoding="utf-8")

    if yaml is not None:
        try:
            return yaml.safe_load(content)
        except Exception:
            pass

    # Try JSON
    try:
        return json.loads(content)
    except json.JSONDecodeError as err:
        if yaml is None:
            raise RuntimeError(
                f"Failed to parse file '{file_path}'. If this is a YAML file, "
                "please ensure 'pyyaml' is installed or the file is valid JSON."
            ) from err
        raise


def load_rules(rules_path: Optional[Path] = None) -> List[dict]:
    """Load behavior detection rules from internal static rules file or given path."""
    if rules_path is None:
        rules_path = DEFAULT_STATIC_RULES_PATH

    data = load_yaml_or_json(rules_path)
    if not isinstance(data, list):
        raise ValueError("Rules configuration must be a list of rule objects.")

    return data
