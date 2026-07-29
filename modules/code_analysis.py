import re
from pathlib import Path


# =========================
# SECURITY RULES
# =========================

SECURITY_RULES = [
    {
        "id": "insecure_http",
        "severity": "medium",
        "title": "Insecure HTTP communication",
        "description": (
            "An unencrypted HTTP URL was detected "
            "in Decompiled Java code."
        ),
        "pattern": re.compile(
            r"http://[^\s\"'<>\\]+",
            re.IGNORECASE
        )
    },
    {
        "id": "webview_usage",
        "severity": "info",
        "title": "WebView usage detected",
        "description": (
            "WebView usage was detected. "
            "WebView security settings should be reviewed."
        ),
        "pattern": re.compile(
            r"\b(?:android\.webkit\.)?WebView\b"
        )
    },
    {
        "id": "webview_javascript_enabled",
        "severity": "medium",
        "title": "WebView JavaScript enabled",
        "description": (
            "JavaScript was enabled in a WebView. "
            "Loaded content and JavaScript interfaces "
            "should be reviewed."
        ),
        "pattern": re.compile(
            r"\.setJavaScriptEnabled\s*\(\s*true\s*\)"
        )
    },
    {
        "id": "webview_file_access_enabled",
        "severity": "medium",
        "title": "WebView file access enabled",
        "description": (
            "WebView file access was enabled. "
            "Local file exposure should be reviewed."
        ),
        "pattern": re.compile(
            r"\.setAllowFileAccess\s*\(\s*true\s*\)"
        )
    },
    {
        "id": "webview_universal_file_access",
        "severity": "high",
        "title": "WebView universal file access enabled",
        "description": (
            "Universal access from file URLs was enabled "
            "in WebView."
        ),
        "pattern": re.compile(
            r"\.setAllowUniversalAccessFromFileURLs"
            r"\s*\(\s*true\s*\)"
        )
    },
    {
        "id": "webview_file_url_access",
        "severity": "high",
        "title": "WebView file URL access enabled",
        "description": (
            "Access from file URLs was enabled in WebView."
        ),
        "pattern": re.compile(
            r"\.setAllowFileAccessFromFileURLs"
            r"\s*\(\s*true\s*\)"
        )
    },
    {
        "id": "runtime_command_execution",
        "severity": "high",
        "title": "Runtime command execution",
        "description": (
            "Runtime.exec was detected. "
            "The executed command should be reviewed."
        ),
        "pattern": re.compile(
            r"Runtime\s*\.\s*getRuntime\s*\(\s*\)"
            r"\s*\.\s*exec\s*\("
        )
    },
    {
        "id": "process_builder_usage",
        "severity": "medium",
        "title": "ProcessBuilder usage",
        "description": (
            "ProcessBuilder was detected. "
            "The created process should be reviewed."
        ),
        "pattern": re.compile(
            r"\bnew\s+ProcessBuilder\s*\("
        )
    },
    {
        "id": "dex_class_loader",
        "severity": "high",
        "title": "Dynamic code loading with DexClassLoader",
        "description": (
            "DexClassLoader usage was detected. "
            "Dynamically loaded code should be reviewed."
        ),
        "pattern": re.compile(
            r"\b(?:new\s+)?DexClassLoader\s*\("
        )
    },
    {
        "id": "path_class_loader",
        "severity": "medium",
        "title": "Dynamic code loading with PathClassLoader",
        "description": (
            "PathClassLoader usage was detected."
        ),
        "pattern": re.compile(
            r"\b(?:new\s+)?PathClassLoader\s*\("
        )
    },
    {
        "id": "reflection_class_for_name",
        "severity": "low",
        "title": "Reflection using Class.forName",
        "description": (
            "Class.forName usage was detected."
        ),
        "pattern": re.compile(
            r"\bClass\s*\.\s*forName\s*\("
        )
    },
    {
        "id": "reflection_method_invoke",
        "severity": "low",
        "title": "Reflective method invocation",
        "description": (
            "Method.invoke usage was detected."
        ),
        "pattern": re.compile(
            r"\.invoke\s*\("
        )
    },
    {
        "id": "reflection_declared_method",
        "severity": "low",
        "title": "Reflective method lookup",
        "description": (
            "getDeclaredMethod usage was detected."
        ),
        "pattern": re.compile(
            r"\.getDeclaredMethod\s*\("
        )
    },
    {
        "id": "custom_hostname_verifier",
        "severity": "medium",
        "title": "Custom TLS hostname verifier",
        "description": (
            "A custom hostname verifier was detected. "
            "TLS hostname validation should be reviewed."
        ),
        "pattern": re.compile(
            r"\.setHostnameVerifier\s*\("
        )
    },
    {
        "id": "custom_trust_manager",
        "severity": "medium",
        "title": "Custom X509 trust manager",
        "description": (
            "X509TrustManager usage was detected. "
            "Certificate validation should be reviewed."
        ),
        "pattern": re.compile(
            r"\bX509TrustManager\b"
        )
    },
    {
        "id": "camera_api_usage",
        "severity": "info",
        "title": "Camera API usage",
        "description": (
            "Camera-related Android API usage was detected."
        ),
        "pattern": re.compile(
            r"\b(?:CameraManager|CameraDevice|"
            r"android\.hardware\.Camera)\b"
        )
    },
    {
        "id": "microphone_api_usage",
        "severity": "info",
        "title": "Microphone or audio recording API usage",
        "description": (
            "Audio recording API usage was detected."
        ),
        "pattern": re.compile(
            r"\b(?:MediaRecorder|AudioRecord)\b"
        )
    },
    {
        "id": "location_api_usage",
        "severity": "info",
        "title": "Location API usage",
        "description": (
            "Android location API usage was detected."
        ),
        "pattern": re.compile(
            r"\b(?:LocationManager|"
            r"FusedLocationProviderClient)\b"
        )
    },
    {
        "id": "contacts_api_usage",
        "severity": "info",
        "title": "Contacts API usage",
        "description": (
            "Android contacts API usage was detected."
        ),
        "pattern": re.compile(
            r"\bContactsContract\b"
        )
    },
    {
        "id": "sms_api_usage",
        "severity": "info",
        "title": "SMS API usage",
        "description": (
            "Android SMS API usage was detected."
        ),
        "pattern": re.compile(
            r"\bSmsManager\b"
        )
    }
]


SEVERITIES = [
    "high",
    "medium",
    "low",
    "info"
]


# =========================
# DIRECTORY HELPERS
# =========================

def _find_source_directory(
    output_dir: Path
) -> Path:
    """Find the JADX Java source directory."""

    possible_paths = [
        output_dir / "sources",
        output_dir / "src"
    ]

    for source_dir in possible_paths:

        if source_dir.is_dir():

            return source_dir

    raise FileNotFoundError(
        "The Java source directory "
        "was not found in JADX output."
    )


def _find_java_files(
    source_dir: Path
) -> list[Path]:
    """Find all Decompiled Java files."""

    java_files = list(
        source_dir.rglob(
            "*.java"
        )
    )

    java_files.sort()

    return java_files


# =========================
# SOURCE HELPERS
# =========================

def _get_source_path(
    file_path: Path,
    source_dir: Path
) -> str:
    """Create a normalized source path."""

    return str(
        file_path.relative_to(
            source_dir.parent
        )
    ).replace(
        "\\",
        "/"
    )


def _get_line_number(
    content: str,
    position: int
) -> int:
    """Get a line number from a character position."""

    return (
        content.count(
            "\n",
            0,
            position
        )
        + 1
    )


def _get_matched_value(
    content: str,
    start: int,
    end: int
) -> str:
    """Get a short code snippet around a match."""

    line_start = (
        content.rfind(
            "\n",
            0,
            start
        )
        + 1
    )

    line_end = (
        content.find(
            "\n",
            end
        )
    )

    if line_end == -1:

        line_end = len(
            content
        )

    value = (
        content[
            line_start:line_end
        ]
        .strip()
    )

    return value[:300]


def _create_evidence(
    content: str,
    match: re.Match,
    file_path: Path,
    source_dir: Path
) -> dict:
    """Create an evidence record."""

    return {
        "source_file": (
            _get_source_path(
                file_path,
                source_dir
            )
        ),

        "line": (
            _get_line_number(
                content,
                match.start()
            )
        ),

        "matched_value": (
            _get_matched_value(
                content,
                match.start(),
                match.end()
            )
        )
    }


# =========================
# FINDING HELPERS
# =========================

def _create_findings() -> dict:
    """Create empty finding containers."""

    findings = {}

    for rule in SECURITY_RULES:

        findings[
            rule["id"]
        ] = {
            "id": rule["id"],

            "severity": (
                rule["severity"]
            ),

            "title": (
                rule["title"]
            ),

            "description": (
                rule["description"]
            ),

            "evidence": []
        }

    return findings


def _add_evidence(
    finding: dict,
    evidence: dict
):
    """Add unique evidence to a finding."""

    if evidence not in (
        finding["evidence"]
    ):

        finding[
            "evidence"
        ].append(
            evidence
        )


def _finalize_findings(
    findings: dict
) -> list:
    """Remove empty findings and sort results."""

    result = []

    severity_order = {
        "high": 0,
        "medium": 1,
        "low": 2,
        "info": 3
    }

    for finding in (
        findings.values()
    ):

        if not (
            finding["evidence"]
        ):

            continue

        finding[
            "evidence"
        ].sort(
            key=lambda item: (
                item["source_file"],
                item["line"]
            )
        )

        finding[
            "evidence_count"
        ] = len(
            finding["evidence"]
        )

        result.append(
            finding
        )

    return sorted(
        result,
        key=lambda item: (
            severity_order[
                item["severity"]
            ],
            item["id"]
        )
    )


def _count_severities(
    findings: list
) -> dict:
    """Count findings by severity."""

    counts = {
        severity: 0
        for severity
        in SEVERITIES
    }

    for finding in findings:

        severity = (
            finding["severity"]
        )

        counts[
            severity
        ] += 1

    return counts


# =========================
# PUBLIC FUNCTION
# =========================

def analyze_java_code(
    config: dict
) -> dict:
    """Analyze Decompiled Java code for security indicators."""

    output_dir = Path(
        config["output_dir"]
    )

    source_dir = (
        _find_source_directory(
            output_dir
        )
    )

    java_files = (
        _find_java_files(
            source_dir
        )
    )

    findings = (
        _create_findings()
    )

    scanned_file_count = 0

    for java_file in java_files:

        try:

            content = (
                java_file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )
            )

        except OSError:

            continue

        scanned_file_count += 1

        for rule in SECURITY_RULES:

            for match in (
                rule[
                    "pattern"
                ].finditer(
                    content
                )
            ):

                evidence = (
                    _create_evidence(
                        content,
                        match,
                        java_file,
                        source_dir
                    )
                )

                _add_evidence(
                    findings[
                        rule["id"]
                    ],
                    evidence
                )

    final_findings = (
        _finalize_findings(
            findings
        )
    )

    severity_counts = (
        _count_severities(
            final_findings
        )
    )

    return {
        "scanned_java_file_count": (
            scanned_file_count
        ),

        "finding_count": (
            len(
                final_findings
            )
        ),

        "severity_counts": (
            severity_counts
        ),

        "findings": (
            final_findings
        )
    }