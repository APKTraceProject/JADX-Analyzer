import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, List, Optional
from java_analysis.analyzers.base_analyzer import BaseAnalyzer
from java_analysis.models.finding import Finding
from java_analysis.models.location import Location
from java_analysis.models.context import CodeContext
from java_analysis.core.utils import (
    find_source_directory,
    find_java_files,
    find_manifest,
    read_source_file,
    load_rules
)

# Output Limits
MAX_EVIDENCE_PER_BEHAVIOR = 8
MAX_EVIDENCE_PER_FILE_BEHAVIOR = 3
MAX_CONTEXT_LINES = 2
MAX_CLASSES_PER_BEHAVIOR = 20
MAX_SOURCES_PER_BEHAVIOR = 20
MAX_IMPORTS_PER_SOURCE = 20

# Source Origins & Prefixes
ANDROIDX_PREFIXES = ("androidx.", "android.support.", "android.arch.")
GOOGLE_PREFIXES = ("com.google.", "firebase.", "google.")
KNOWN_THIRD_PARTY_PREFIXES = (
    "com.squareup.", "okhttp3.", "retrofit2.", "org.apache.", "org.json.",
    "org.jetbrains.", "kotlin.", "kotlinx.", "io.reactivex.", "rx.",
    "com.facebook.", "com.bumptech.", "com.airbnb.", "com.github.", "com.jakewharton.",
    "java.", "javax.", "org.slf4j.", "org.hamcrest.", "org.junit.", "junit.",
    "io.flutter.", "io.netty.", "io.grpc.", "org.commons.", "com.google.gson."
)
SYSTEM_OR_LIBRARY_PREFIXES = (
    "android.",
    "androidx.",
    "com.google.",
    "google.",
    "firebase.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "com.squareup.",
    "okhttp3.",
    "retrofit2.",
    "org.apache.",
    "org.json.",
    "org.jetbrains.",
    "org.slf4j.",
    "org.hamcrest.",
    "org.junit.",
    "junit.",
    "io.reactivex.",
    "rx.",
    "com.facebook.",
    "com.bumptech.",
    "com.airbnb.",
    "com.github.",
    "com.jakewharton.",
    "io.flutter.",
    "io.netty.",
    "io.grpc.",
    "org.commons.",
    "com.google.gson.",
)

PACKAGE_PATTERN = re.compile(
    r"^\s*package\s+([A-Za-z0-9_.$]+)\s*;", re.MULTILINE
)
CLASS_PATTERN = re.compile(
    r"\b(?:class|interface|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)", re.VERBOSE
)
IMPORT_PATTERN = re.compile(
    r"^\s*import\s+([A-Za-z0-9_.*$]+)\s*;", re.MULTILINE
)


class JavaCodeAnalyzer(BaseAnalyzer):
    """Analyzes decompiled Java source code for security-relevant behaviors."""

    def analyze(
        self,
        output_dir: Path,
        rules: Optional[List[Dict[str, Any]]] = None,
        application_package: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze Java sources for security behaviors."""
        return analyze_java_code(
            output_dir=output_dir,
            rules=rules,
            application_package=application_package
        )


def _get_package_name(content: str) -> Optional[str]:
    match = PACKAGE_PATTERN.search(content)
    return match.group(1) if match else None


def _get_class_name(content: str, package_name: Optional[str]) -> Optional[str]:
    match = CLASS_PATTERN.search(content)
    if not match:
        return None
    class_name = match.group(1)
    if package_name:
        return f"{package_name}.{class_name}"
    return class_name


def _get_imports(content: str) -> List[str]:
    imports = IMPORT_PATTERN.findall(content)
    return sorted(set(imports))[:MAX_IMPORTS_PER_SOURCE]


def _get_relative_path(file_path: Path, source_directory: Path) -> str:
    return str(file_path.relative_to(source_directory.parent)).replace("\\", "/")


def _extract_package_from_manifest(output_dir: Path) -> Optional[str]:
    try:
        manifest_path = find_manifest(output_dir)
        if manifest_path and manifest_path.is_file():
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            pkg = root.get("package")
            if pkg:
                return pkg.strip()
    except Exception:
        pass
    return None


def _infer_application_package(
    package_names: List[str],
    output_dir: Optional[Path] = None
) -> Optional[str]:
    if output_dir:
        manifest_pkg = _extract_package_from_manifest(output_dir)
        if manifest_pkg:
            return manifest_pkg

    non_lib_packages = [
        pkg for pkg in package_names
        if pkg
        and not any(pkg.startswith(prefix) for prefix in SYSTEM_OR_LIBRARY_PREFIXES)
        and not pkg.startswith("android")
        and not pkg.startswith("java")
        and not pkg.startswith("javax")
        and not pkg.startswith("kotlin")
        and not pkg.startswith("org.")
        and not pkg.startswith("io.")
    ]
    if not non_lib_packages:
        return None

    prefix_counts: Dict[str, int] = defaultdict(int)
    for pkg in non_lib_packages:
        parts = pkg.split(".")
        if len(parts) >= 2:
            prefix = ".".join(parts[:2])
            prefix_counts[prefix] += 1
            if len(parts) >= 3:
                prefix3 = ".".join(parts[:3])
                prefix_counts[prefix3] += 1
        else:
            prefix_counts[pkg] += 1

    if prefix_counts:
        best_prefix = max(prefix_counts.keys(), key=lambda p: (prefix_counts[p], len(p)))
        return best_prefix
    return None


def _classify_source(package_name: Optional[str], application_package: Optional[str]) -> str:
    if not package_name:
        return "unknown"

    if application_package and application_package != "unknown":
        if package_name == application_package or package_name.startswith(f"{application_package}."):
            return "application"

    if package_name.startswith(ANDROIDX_PREFIXES) or package_name.startswith("android."):
        return "androidx"

    if package_name.startswith(GOOGLE_PREFIXES):
        return "google"

    if (
        package_name.startswith(KNOWN_THIRD_PARTY_PREFIXES)
        or package_name.startswith("java.")
        or package_name.startswith("javax.")
        or package_name.startswith("kotlin.")
        or package_name.startswith("kotlinx.")
        or package_name.startswith("org.")
        or package_name.startswith("io.")
    ):
        return "third_party"

    if not application_package or application_package == "unknown":
        return "application"

    return "third_party"


def _compile_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled_rules = []
    for rule in rules:
        compiled_patterns = []
        for pattern_data in rule.get("patterns", []):
            compiled_patterns.append({
                **pattern_data,
                "compiled": re.compile(pattern_data["pattern"])
            })
        compiled_rules.append({
            **rule,
            "compiled_patterns": compiled_patterns
        })
    return compiled_rules


def _get_rule_lookup(rules: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {rule["id"]: rule for rule in rules}


def _get_line_number(content: str, character_index: int) -> int:
    return content.count("\n", 0, character_index) + 1


def _get_context(lines: List[str], line_number: int) -> Dict[str, Any]:
    start_index = max(0, line_number - 1 - MAX_CONTEXT_LINES)
    end_index = min(len(lines), line_number + MAX_CONTEXT_LINES)
    selected_lines = lines[start_index:end_index]

    if not selected_lines:
        code_context = CodeContext(start_line=line_number, end_line=line_number, code="")
        return code_context.to_dict()

    code_context = CodeContext(
        start_line=start_index + 1,
        end_line=end_index,
        code="\n".join(line.rstrip() for line in selected_lines)
    )
    return code_context.to_dict()


def _detect_file_behaviors(
    content: str,
    source_file: str,
    source_origin: str,
    class_name: Optional[str],
    compiled_rules: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    lines = content.splitlines()
    detections = []

    for rule in compiled_rules:
        behavior_evidence = []
        for pattern_data in rule["compiled_patterns"]:
            matches = list(pattern_data["compiled"].finditer(content))
            for match in matches:
                if len(behavior_evidence) >= MAX_EVIDENCE_PER_FILE_BEHAVIOR:
                    break
                line_number = _get_line_number(content, match.start())
                matched_line_content = lines[line_number - 1].strip() if line_number <= len(lines) else ""
                location = Location(
                    source_file=source_file,
                    source_origin=source_origin,
                    class_name=class_name,
                    line=line_number,
                    evidence=pattern_data["evidence"],
                    matched_line=line_number,
                    matched_code=matched_line_content,
                    context=_get_context(lines, line_number)
                )
                behavior_evidence.append(location.to_dict())

            if len(behavior_evidence) >= MAX_EVIDENCE_PER_FILE_BEHAVIOR:
                break

        if behavior_evidence:
            detections.append({
                "behavior_id": rule["id"],
                "evidence": behavior_evidence
            })

    return detections


def _build_behavior_summary(
    source_records: List[Dict[str, Any]],
    rule_lookup: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    behavior_data: Dict[str, Any] = {}

    for record in source_records:
        for detection in record["detections"]:
            behavior_id = detection["behavior_id"]
            if behavior_id not in behavior_data:
                behavior_data[behavior_id] = {
                    "source_counts": defaultdict(int),
                    "classes": set(),
                    "sources": set(),
                    "evidence": []
                }

            data = behavior_data[behavior_id]
            data["source_counts"][record["source_origin"]] += 1
            if record["class_name"]:
                data["classes"].add(record["class_name"])
            data["sources"].add(record["source_file"])

            for evidence in detection["evidence"]:
                if len(data["evidence"]) < MAX_EVIDENCE_PER_BEHAVIOR:
                    data["evidence"].append(evidence)

    summary = []
    for behavior_id in sorted(behavior_data):
        rule = rule_lookup.get(behavior_id, {"name": behavior_id, "category": "unknown", "priority": "low", "permissions": []})
        data = behavior_data[behavior_id]
        finding = Finding(
            behavior_id=behavior_id,
            name=rule.get("name", behavior_id),
            category=rule.get("category", "unknown"),
            priority=rule.get("priority", "low"),
            related_permissions=rule.get("permissions", []),
            source_counts={
                "application": data["source_counts"]["application"],
                "androidx": data["source_counts"]["androidx"],
                "google": data["source_counts"]["google"],
                "third_party": data["source_counts"]["third_party"],
                "unknown": data["source_counts"]["unknown"]
            },
            classes=sorted(data["classes"])[:MAX_CLASSES_PER_BEHAVIOR],
            source_files=sorted(data["sources"])[:MAX_SOURCES_PER_BEHAVIOR],
            evidence=data["evidence"]
        )
        summary.append(finding.to_dict())

    return summary


def _get_highest_priority(
    detections: List[Dict[str, Any]],
    rule_lookup: Dict[str, Dict[str, Any]]
) -> str:
    priority_values = {"high": 3, "medium": 2, "low": 1, "none": 0}
    highest_priority = "none"

    for detection in detections:
        rule = rule_lookup.get(detection["behavior_id"], {})
        priority = rule.get("priority", "none")
        if priority_values.get(priority, 0) > priority_values.get(highest_priority, 0):
            highest_priority = priority

    return highest_priority


def _build_important_sources(
    source_records: List[Dict[str, Any]],
    rule_lookup: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    important_sources = []

    for record in source_records:
        detections = record.get("detections", [])
        if not detections:
            continue

        highest_priority = _get_highest_priority(detections, rule_lookup)
        source_origin = record.get("source_origin", "unknown")

        is_application = (source_origin == "application")
        is_high_priority = (highest_priority == "high")

        if not (is_application or is_high_priority):
            continue

        behaviors = list(dict.fromkeys(detection["behavior_id"] for detection in detections))
        evidence = []
        for detection in detections:
            for item in detection.get("evidence", []):
                evidence.append({
                    "behavior_id": detection["behavior_id"],
                    **item
                })

        important_sources.append({
            "source_file": record["source_file"],
            "class_name": record.get("class_name"),
            "source_origin": source_origin,
            "priority": highest_priority,
            "behaviors": behaviors,
            "evidence": evidence[:MAX_EVIDENCE_PER_BEHAVIOR]
        })

    priority_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    important_sources.sort(
        key=lambda item: (priority_order.get(item["priority"], 3), item["source_file"])
    )
    return important_sources


def _build_source_statistics(source_records: List[Dict[str, Any]]) -> Dict[str, int]:
    source_counts: Dict[str, int] = defaultdict(int)
    for record in source_records:
        source_counts[record["source_origin"]] += 1

    return {
        "total": len(source_records),
        "application": source_counts["application"],
        "androidx": source_counts["androidx"],
        "google": source_counts["google"],
        "third_party": source_counts["third_party"],
        "unknown": source_counts["unknown"]
    }


def analyze_java_code(
    output_dir: Path,
    rules: Optional[List[Dict[str, Any]]] = None,
    application_package: Optional[str] = None
) -> Dict[str, Any]:
    """Perform security behavior analysis on decompiled Java code."""
    if rules is None:
        rules = load_rules()

    source_directory = find_source_directory(output_dir)
    java_files = find_java_files(source_directory)
    compiled_rules = _compile_rules(rules)
    rule_lookup = _get_rule_lookup(rules)

    raw_files_data = []
    package_names = []
    class_count = 0

    for file_path in java_files:
        content = read_source_file(file_path)
        package_name = _get_package_name(content)
        if package_name:
            package_names.append(package_name)
        class_name = _get_class_name(content, package_name)
        if class_name:
            class_count += 1
        raw_files_data.append((file_path, content, package_name, class_name))

    if not application_package:
        application_package = (
            _extract_package_from_manifest(output_dir)
            or _infer_application_package(package_names, output_dir)
            or "unknown"
        )

    source_records = []
    for file_path, content, package_name, class_name in raw_files_data:
        source_origin = _classify_source(package_name, application_package)
        source_file = _get_relative_path(file_path, source_directory)
        detections = _detect_file_behaviors(
            content, source_file, source_origin, class_name, compiled_rules
        )

        source_records.append({
            "source_file": source_file,
            "source_origin": source_origin,
            "package_name": package_name,
            "class_name": class_name,
            "imports": _get_imports(content),
            "detections": detections
        })

    behavior_summary = _build_behavior_summary(source_records, rule_lookup)
    important_sources = _build_important_sources(source_records, rule_lookup)
    behavior_occurrences = sum(len(r["detections"]) for r in source_records)
    source_statistics = _build_source_statistics(source_records)

    return {
        "analysis_type": "evidence_based_java_behavior_mapping",
        "application_package": application_package,
        "statistics": {
            "java_files_scanned": len(java_files),
            "classes_detected": class_count,
            "behavior_types_detected": len(behavior_summary),
            "behavior_occurrences": behavior_occurrences,
            "important_sources": len(important_sources),
            "source_origins": source_statistics
        },
        "behavior_summary": behavior_summary,
        "important_sources": important_sources
    }
