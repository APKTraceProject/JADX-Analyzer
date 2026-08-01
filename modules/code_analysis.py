import re
from collections import defaultdict
from pathlib import Path


# =========================
# OUTPUT LIMITS
# =========================

MAX_EVIDENCE_PER_BEHAVIOR = 8

MAX_EVIDENCE_PER_FILE_BEHAVIOR = 3

MAX_CONTEXT_LINES = 2

MAX_CLASSES_PER_BEHAVIOR = 20

MAX_SOURCES_PER_BEHAVIOR = 20

MAX_IMPORTS_PER_SOURCE = 20


# =========================
# SOURCE ORIGINS
# =========================

ANDROIDX_PREFIXES = (
    "androidx.",
    "android.support."
)

GOOGLE_PREFIXES = (
    "com.google.",
    "firebase."
)

KNOWN_THIRD_PARTY_PREFIXES = (
    "com.squareup.",
    "okhttp3.",
    "retrofit2.",
    "org.apache.",
    "org.json.",
    "org.jetbrains.",
    "kotlin.",
    "kotlinx.",
    "io.reactivex.",
    "rx.",
    "com.facebook.",
    "com.bumptech.",
    "com.airbnb.",
    "com.github.",
    "com.jakewharton."
)


# =========================
# BEHAVIOR RULES
# =========================

BEHAVIOR_RULES = [
    {
        "id": "camera_access",
        "name": "Camera Access",
        "category": "sensitive_api",
        "priority": "medium",
        "permissions": [
            "android.permission.CAMERA"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bCameraManager\b"
                ),
                "evidence": (
                    "CameraManager reference"
                )
            },
            {
                "pattern": (
                    r"\bCameraDevice\b"
                ),
                "evidence": (
                    "CameraDevice reference"
                )
            },
            {
                "pattern": (
                    r"\bopenCamera\s*\("
                ),
                "evidence": (
                    "Camera open operation"
                )
            }
        ]
    },
    {
        "id": "microphone_access",
        "name": "Microphone Access",
        "category": "sensitive_api",
        "priority": "medium",
        "permissions": [
            "android.permission.RECORD_AUDIO"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bMediaRecorder\b"
                ),
                "evidence": (
                    "MediaRecorder reference"
                )
            },
            {
                "pattern": (
                    r"\bAudioRecord\b"
                ),
                "evidence": (
                    "AudioRecord reference"
                )
            },
            {
                "pattern": (
                    r"\bsetAudioSource\s*\("
                ),
                "evidence": (
                    "Audio source configuration"
                )
            },
            {
                "pattern": (
                    r"\bstartRecording\s*\("
                ),
                "evidence": (
                    "Audio recording operation"
                )
            }
        ]
    },
    {
        "id": "location_access",
        "name": "Location Access",
        "category": "sensitive_api",
        "priority": "medium",
        "permissions": [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bLocationManager\b"
                ),
                "evidence": (
                    "LocationManager reference"
                )
            },
            {
                "pattern": (
                    r"\bFusedLocationProviderClient\b"
                ),
                "evidence": (
                    "Fused location client reference"
                )
            },
            {
                "pattern": (
                    r"\bgetLastKnownLocation\s*\("
                ),
                "evidence": (
                    "Last known location request"
                )
            },
            {
                "pattern": (
                    r"\brequestLocationUpdates\s*\("
                ),
                "evidence": (
                    "Location update request"
                )
            }
        ]
    },
    {
        "id": "contacts_access",
        "name": "Contacts Access",
        "category": "sensitive_api",
        "priority": "medium",
        "permissions": [
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_PROFILE",
            "android.permission.WRITE_PROFILE"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bContactsContract\b"
                ),
                "evidence": (
                    "ContactsContract reference"
                )
            },
            {
                "pattern": (
                    r"\bRawContacts\b"
                ),
                "evidence": (
                    "Raw contacts reference"
                )
            },
            {
                "pattern": (
                    r"\bCommonDataKinds\b"
                ),
                "evidence": (
                    "Contact data type reference"
                )
            }
        ]
    },
    {
        "id": "sms_access",
        "name": "SMS Access",
        "category": "sensitive_api",
        "priority": "high",
        "permissions": [
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bSmsManager\b"
                ),
                "evidence": (
                    "SmsManager reference"
                )
            },
            {
                "pattern": (
                    r"\bsendTextMessage\s*\("
                ),
                "evidence": (
                    "SMS sending operation"
                )
            },
            {
                "pattern": (
                    r"\bsendMultipartTextMessage\s*\("
                ),
                "evidence": (
                    "Multipart SMS sending operation"
                )
            }
        ]
    },
    {
        "id": "phone_access",
        "name": "Phone and Telephony Access",
        "category": "sensitive_api",
        "priority": "medium",
        "permissions": [
            "android.permission.CALL_PHONE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bTelephonyManager\b"
                ),
                "evidence": (
                    "TelephonyManager reference"
                )
            },
            {
                "pattern": (
                    r"\bTelecomManager\b"
                ),
                "evidence": (
                    "TelecomManager reference"
                )
            },
            {
                "pattern": (
                    r"\bACTION_CALL\b"
                ),
                "evidence": (
                    "Phone call intent"
                )
            },
            {
                "pattern": (
                    r"\bplaceCall\s*\("
                ),
                "evidence": (
                    "Phone call operation"
                )
            }
        ]
    },
    {
        "id": "account_access",
        "name": "Account Access",
        "category": "sensitive_api",
        "priority": "medium",
        "permissions": [
            "android.permission.GET_ACCOUNTS"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bAccountManager\b"
                ),
                "evidence": (
                    "AccountManager reference"
                )
            },
            {
                "pattern": (
                    r"\bgetAccounts\s*\("
                ),
                "evidence": (
                    "Account enumeration operation"
                )
            },
            {
                "pattern": (
                    r"\bgetAccountsByType\s*\("
                ),
                "evidence": (
                    "Account type enumeration"
                )
            }
        ]
    },
    {
        "id": "webview_javascript",
        "name": "WebView JavaScript Enabled",
        "category": "webview",
        "priority": "medium",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bsetJavaScriptEnabled"
                    r"\s*\(\s*true\s*\)"
                ),
                "evidence": (
                    "WebView JavaScript enabled"
                )
            }
        ]
    },
    {
        "id": "webview_file_access",
        "name": "WebView File Access",
        "category": "webview",
        "priority": "medium",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bsetAllowFileAccess"
                    r"\s*\(\s*true\s*\)"
                ),
                "evidence": (
                    "WebView file access enabled"
                )
            },
            {
                "pattern": (
                    r"\bsetAllowContentAccess"
                    r"\s*\(\s*true\s*\)"
                ),
                "evidence": (
                    "WebView content access enabled"
                )
            }
        ]
    },
    {
        "id": "webview_file_url_access",
        "name": "WebView File URL Access",
        "category": "webview",
        "priority": "high",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bsetAllowFileAccessFromFileURLs"
                    r"\s*\(\s*true\s*\)"
                ),
                "evidence": (
                    "File URL access enabled"
                )
            },
            {
                "pattern": (
                    r"\bsetAllowUniversalAccessFromFileURLs"
                    r"\s*\(\s*true\s*\)"
                ),
                "evidence": (
                    "Universal file URL access enabled"
                )
            }
        ]
    },
    {
        "id": "webview_javascript_interface",
        "name": "WebView JavaScript Interface",
        "category": "webview",
        "priority": "high",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\baddJavascriptInterface"
                    r"\s*\("
                ),
                "evidence": (
                    "Java object exposed to WebView"
                )
            }
        ]
    },
    {
        "id": "webview_debugging",
        "name": "WebView Debugging Enabled",
        "category": "webview",
        "priority": "medium",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bsetWebContentsDebuggingEnabled"
                    r"\s*\(\s*true\s*\)"
                ),
                "evidence": (
                    "WebView debugging enabled"
                )
            }
        ]
    },
    {
        "id": "network_communication",
        "name": "Network Communication",
        "category": "network",
        "priority": "low",
        "permissions": [
            "android.permission.INTERNET"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bHttpURLConnection\b"
                ),
                "evidence": (
                    "HTTP connection API"
                )
            },
            {
                "pattern": (
                    r"\bHttpsURLConnection\b"
                ),
                "evidence": (
                    "HTTPS connection API"
                )
            },
            {
                "pattern": (
                    r"\bOkHttpClient\b"
                ),
                "evidence": (
                    "OkHttp client reference"
                )
            },
            {
                "pattern": (
                    r"\bRetrofit\b"
                ),
                "evidence": (
                    "Retrofit reference"
                )
            },
            {
                "pattern": (
                    r"\bWebSocket\b"
                ),
                "evidence": (
                    "WebSocket reference"
                )
            },
            {
                "pattern": (
                    r"\bDatagramSocket\b"
                ),
                "evidence": (
                    "Datagram socket reference"
                )
            }
        ]
    },
    {
        "id": "runtime_command_execution",
        "name": "Runtime Command Execution",
        "category": "runtime_execution",
        "priority": "high",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bRuntime\.getRuntime"
                    r"\s*\(\s*\)"
                    r"\s*\.exec\s*\("
                ),
                "evidence": (
                    "Runtime command execution"
                )
            },
            {
                "pattern": (
                    r"\bnew\s+ProcessBuilder\s*\("
                ),
                "evidence": (
                    "ProcessBuilder creation"
                )
            }
        ]
    },
    {
        "id": "dynamic_code_loading",
        "name": "Dynamic Code Loading",
        "category": "dynamic_loading",
        "priority": "high",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bnew\s+DexClassLoader\s*\("
                ),
                "evidence": (
                    "DexClassLoader instantiation"
                )
            },
            {
                "pattern": (
                    r"\bnew\s+PathClassLoader\s*\("
                ),
                "evidence": (
                    "PathClassLoader instantiation"
                )
            },
            {
                "pattern": (
                    r"\bnew\s+InMemoryDexClassLoader"
                    r"\s*\("
                ),
                "evidence": (
                    "In-memory DEX loader instantiation"
                )
            }
        ]
    },
    {
        "id": "reflection",
        "name": "Java Reflection",
        "category": "reflection",
        "priority": "low",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bClass\.forName\s*\("
                ),
                "evidence": (
                    "Dynamic class lookup"
                )
            },
            {
                "pattern": (
                    r"\bgetDeclaredMethod\s*\("
                ),
                "evidence": (
                    "Reflective method lookup"
                )
            },
            {
                "pattern": (
                    r"\bgetDeclaredField\s*\("
                ),
                "evidence": (
                    "Reflective field lookup"
                )
            },
            {
                "pattern": (
                    r"\bgetDeclaredConstructor"
                    r"\s*\("
                ),
                "evidence": (
                    "Reflective constructor lookup"
                )
            },
            {
                "pattern": (
                    r"\.invoke\s*\("
                ),
                "evidence": (
                    "Reflective invocation candidate"
                )
            }
        ]
    },
    {
        "id": "custom_tls",
        "name": "Custom TLS Handling",
        "category": "tls",
        "priority": "medium",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bnew\s+X509TrustManager"
                    r"\s*\("
                ),
                "evidence": (
                    "Custom X509TrustManager"
                )
            },
            {
                "pattern": (
                    r"\bsetHostnameVerifier"
                    r"\s*\("
                ),
                "evidence": (
                    "Custom hostname verifier"
                )
            },
            {
                "pattern": (
                    r"\bcheckServerTrusted"
                    r"\s*\("
                ),
                "evidence": (
                    "Custom certificate validation"
                )
            },
            {
                "pattern": (
                    r"\bHostnameVerifier\b"
                ),
                "evidence": (
                    "HostnameVerifier reference"
                )
            }
        ]
    },
    {
        "id": "cryptographic_operations",
        "name": "Cryptographic Operations",
        "category": "cryptography",
        "priority": "low",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bCipher\.getInstance\s*\("
                ),
                "evidence": (
                    "Cipher creation"
                )
            },
            {
                "pattern": (
                    r"\bMessageDigest\.getInstance"
                    r"\s*\("
                ),
                "evidence": (
                    "Message digest creation"
                )
            },
            {
                "pattern": (
                    r"\bMac\.getInstance\s*\("
                ),
                "evidence": (
                    "MAC creation"
                )
            },
            {
                "pattern": (
                    r"\bSecretKeySpec\b"
                ),
                "evidence": (
                    "Secret key specification"
                )
            }
        ]
    },
    {
        "id": "accessibility_service",
        "name": "Accessibility Service Usage",
        "category": "privileged_behavior",
        "priority": "high",
        "permissions": [],
        "patterns": [
            {
                "pattern": (
                    r"\bclass\s+\w+"
                    r"\s+extends\s+AccessibilityService\b"
                ),
                "evidence": (
                    "Class extends AccessibilityService"
                )
            },
            {
                "pattern": (
                    r"\bperformGlobalAction"
                    r"\s*\("
                ),
                "evidence": (
                    "Accessibility global action"
                )
            }
        ]
    },
    {
        "id": "overlay_window",
        "name": "Overlay Window Usage",
        "category": "privileged_behavior",
        "priority": "high",
        "permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bTYPE_APPLICATION_OVERLAY\b"
                ),
                "evidence": (
                    "Application overlay window type"
                )
            },
            {
                "pattern": (
                    r"\bTYPE_SYSTEM_ALERT\b"
                ),
                "evidence": (
                    "System alert window type"
                )
            },
            {
                "pattern": (
                    r"\bSYSTEM_ALERT_WINDOW\b"
                ),
                "evidence": (
                    "Overlay permission reference"
                )
            }
        ]
    },
    {
        "id": "package_installation",
        "name": "Package Installation",
        "category": "privileged_behavior",
        "priority": "high",
        "permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES"
        ],
        "patterns": [
            {
                "pattern": (
                    r"\bPackageInstaller\b"
                ),
                "evidence": (
                    "PackageInstaller reference"
                )
            },
            {
                "pattern": (
                    r"\bACTION_INSTALL_PACKAGE\b"
                ),
                "evidence": (
                    "Package installation intent"
                )
            },
            {
                "pattern": (
                    r"\bREQUEST_INSTALL_PACKAGES\b"
                ),
                "evidence": (
                    "Package installation permission"
                )
            }
        ]
    }
]


# =========================
# SOURCE PATTERNS
# =========================

PACKAGE_PATTERN = re.compile(
    r"""
    ^\s*
    package
    \s+
    (
        [A-Za-z0-9_.$]+
    )
    \s*;
    """,
    re.MULTILINE | re.VERBOSE
)

CLASS_PATTERN = re.compile(
    r"""
    \b
    (?:
        class|
        interface|
        enum
    )
    \s+
    (
        [A-Za-z_$]
        [A-Za-z0-9_$]*
    )
    """,
    re.VERBOSE
)

IMPORT_PATTERN = re.compile(
    r"""
    ^\s*
    import
    \s+
    (
        [A-Za-z0-9_.*$]+
    )
    \s*;
    """,
    re.MULTILINE | re.VERBOSE
)


# =========================
# SOURCE DISCOVERY
# =========================

def _find_source_directory(
    output_dir: Path
) -> Path:

    possible_directories = [
        output_dir / "sources",
        output_dir / "src"
    ]

    for directory in possible_directories:

        if directory.is_dir():

            return directory

    for directory in output_dir.rglob(
        "*"
    ):

        if (
            directory.is_dir()
            and directory.name.lower()
            in {
                "sources",
                "src"
            }
        ):

            return directory

    raise FileNotFoundError(
        "Decompiled Java source "
        "directory was not found."
    )


def _get_java_files(
    source_directory: Path
) -> list:

    return sorted(
        [
            file_path
            for file_path
            in source_directory.rglob(
                "*.java"
            )
            if file_path.is_file()
        ],
        key=lambda item: str(
            item
        )
    )


def _read_source(
    file_path: Path
) -> str:

    try:

        return file_path.read_text(
            encoding="utf-8",
            errors="replace"
        )

    except OSError as error:

        raise RuntimeError(
            "Unable to read Java file:\n"
            f"{file_path}"
        ) from error


# =========================
# SOURCE METADATA
# =========================

def _get_package_name(
    content: str
):

    match = PACKAGE_PATTERN.search(
        content
    )

    if match is None:

        return None

    return match.group(
        1
    )


def _get_class_name(
    content: str,
    package_name
):

    match = CLASS_PATTERN.search(
        content
    )

    if match is None:

        return None

    class_name = match.group(
        1
    )

    if package_name:

        return (
            f"{package_name}."
            f"{class_name}"
        )

    return class_name


def _get_imports(
    content: str
) -> list:

    imports = IMPORT_PATTERN.findall(
        content
    )

    return sorted(
        set(
            imports
        )
    )[
        :MAX_IMPORTS_PER_SOURCE
    ]


def _get_relative_path(
    file_path: Path,
    source_directory: Path
) -> str:

    return str(
        file_path.relative_to(
            source_directory.parent
        )
    ).replace(
        "\\",
        "/"
    )


# =========================
# SOURCE CLASSIFICATION
# =========================

def _classify_source(
    package_name,
    application_package: str
) -> str:

    if (
        package_name
        and application_package
        and (
            package_name
            == application_package
            or package_name.startswith(
                f"{application_package}."
            )
        )
    ):

        return "application"

    if (
        package_name
        and package_name.startswith(
            ANDROIDX_PREFIXES
        )
    ):

        return "androidx"

    if (
        package_name
        and package_name.startswith(
            GOOGLE_PREFIXES
        )
    ):

        return "google"

    if (
        package_name
        and package_name.startswith(
            KNOWN_THIRD_PARTY_PREFIXES
        )
    ):

        return "third_party"

    if package_name:

        return "unknown"

    return "unknown"


# =========================
# COMPONENT LOOKUP
# =========================

def _build_component_lookup(
    components: dict
) -> dict:

    lookup = {}

    component_groups = {
        "activities": "activity",
        "services": "service",
        "receivers": "receiver",
        "providers": "provider"
    }

    for (
        group_name,
        component_type
    ) in component_groups.items():

        for component in (
            components.get(
                group_name,
                []
            )
        ):

            component_name = (
                component.get(
                    "name"
                )
            )

            if not component_name:

                continue

            lookup[
                component_name
            ] = {
                "type": (
                    component_type
                ),
                "exported": (
                    component.get(
                        "exported"
                    )
                ),
                "permission": (
                    component.get(
                        "permission"
                    )
                )
            }

    application = components.get(
        "application"
    )

    if isinstance(
        application,
        dict
    ):

        application_name = (
            application.get(
                "name"
            )
        )

        if application_name:

            lookup[
                application_name
            ] = {
                "type": "application",
                "exported": None,
                "permission": None
            }

    return lookup


# =========================
# RULE COMPILATION
# =========================

def _compile_rules() -> list:

    compiled_rules = []

    for rule in (
        BEHAVIOR_RULES
    ):

        compiled_patterns = []

        for pattern_data in (
            rule[
                "patterns"
            ]
        ):

            compiled_patterns.append(
                {
                    **pattern_data,
                    "compiled": re.compile(
                        pattern_data[
                            "pattern"
                        ]
                    )
                }
            )

        compiled_rules.append(
            {
                **rule,
                "compiled_patterns": (
                    compiled_patterns
                )
            }
        )

    return compiled_rules


def _get_rule_lookup() -> dict:

    return {
        rule[
            "id"
        ]: rule
        for rule in (
            BEHAVIOR_RULES
        )
    }


# =========================
# LINE AND CONTEXT HELPERS
# =========================

def _get_line_number(
    content: str,
    character_index: int
) -> int:

    return (
        content.count(
            "\n",
            0,
            character_index
        )
        + 1
    )


def _get_context(
    lines: list,
    line_number: int
) -> dict:

    start_index = max(
        0,
        line_number - 1 - MAX_CONTEXT_LINES
    )

    end_index = min(
        len(lines),
        line_number + MAX_CONTEXT_LINES
    )

    selected_lines = lines[
        start_index:end_index
    ]

    if not selected_lines:
        return {
            "start_line": line_number,
            "end_line": line_number,
            "code": ""
        }

    return {
        "start_line": start_index + 1,
        "end_line": end_index,
        "code": "\n".join(
            line.rstrip()
            for line in selected_lines
        )
    }


# =========================
# BEHAVIOR DETECTION
# =========================

def _detect_file_behaviors(
    content: str,
    source_file: str,
    source_origin: str,
    class_name,
    compiled_rules: list
) -> list:

    lines = content.splitlines()

    detections = []

    for rule in (
        compiled_rules
    ):

        behavior_evidence = []

        for pattern_data in (
            rule[
                "compiled_patterns"
            ]
        ):

            matches = list(
                pattern_data[
                    "compiled"
                ].finditer(
                    content
                )
            )

            for match in matches:

                if (
                    len(
                        behavior_evidence
                    )
                    >=
                    MAX_EVIDENCE_PER_FILE_BEHAVIOR
                ):

                    break

                line_number = (
                    _get_line_number(
                        content,
                        match.start()
                    )
                )

                behavior_evidence.append(
                    {
                        "source_file": (
                            source_file
                        ),
                        "source_origin": (
                            source_origin
                        ),
                        "class_name": (
                            class_name
                        ),
                        "line": (
                            line_number
                        ),
                        "evidence": (
                            pattern_data[
                                "evidence"
                            ]
                        ),
                        "matched_line": line_number,
                        "matched_code": lines[line_number - 1].strip(),
                        "context": (
                            _get_context(
                                lines,
                                line_number
                            )
                        )
                    }
                )

            if (
                len(
                    behavior_evidence
                )
                >=
                MAX_EVIDENCE_PER_FILE_BEHAVIOR
            ):

                break

        if behavior_evidence:

            detections.append(
                {
                    "behavior_id": (
                        rule[
                            "id"
                        ]
                    ),
                    "evidence": (
                        behavior_evidence
                    )
                }
            )

    return detections


# =========================
# BEHAVIOR SUMMARY
# =========================

def _build_behavior_summary(
    source_records: list,
    rule_lookup: dict
) -> list:

    behavior_data = {}

    for record in (
        source_records
    ):

        for detection in (
            record[
                "detections"
            ]
        ):

            behavior_id = (
                detection[
                    "behavior_id"
                ]
            )

            if behavior_id not in (
                behavior_data
            ):

                behavior_data[
                    behavior_id
                ] = {
                    "source_counts": (
                        defaultdict(
                            int
                        )
                    ),
                    "classes": set(),
                    "sources": set(),
                    "evidence": []
                }

            data = (
                behavior_data[
                    behavior_id
                ]
            )

            data[
                "source_counts"
            ][
                record[
                    "source_origin"
                ]
            ] += 1

            if record[
                "class_name"
            ]:

                data[
                    "classes"
                ].add(
                    record[
                        "class_name"
                    ]
                )

            data[
                "sources"
            ].add(
                record[
                    "source_file"
                ]
            )

            for evidence in (
                detection[
                    "evidence"
                ]
            ):

                if (
                    len(
                        data[
                            "evidence"
                        ]
                    )
                    <
                    MAX_EVIDENCE_PER_BEHAVIOR
                ):

                    data[
                        "evidence"
                    ].append(
                        evidence
                    )

    summary = []

    for behavior_id in sorted(
        behavior_data
    ):

        rule = (
            rule_lookup[
                behavior_id
            ]
        )

        data = (
            behavior_data[
                behavior_id
            ]
        )

        summary.append(
            {
                "behavior_id": (
                    behavior_id
                ),
                "name": (
                    rule[
                        "name"
                    ]
                ),
                "category": (
                    rule[
                        "category"
                    ]
                ),
                "priority": (
                    rule[
                        "priority"
                    ]
                ),
                "related_permissions": (
                    rule[
                        "permissions"
                    ]
                ),
                "source_counts": {
                    "application": (
                        data[
                            "source_counts"
                        ][
                            "application"
                        ]
                    ),
                    "androidx": (
                        data[
                            "source_counts"
                        ][
                            "androidx"
                        ]
                    ),
                    "google": (
                        data[
                            "source_counts"
                        ][
                            "google"
                        ]
                    ),
                    "third_party": (
                        data[
                            "source_counts"
                        ][
                            "third_party"
                        ]
                    ),
                    "unknown": (
                        data[
                            "source_counts"
                        ][
                            "unknown"
                        ]
                    )
                },
                "classes": sorted(
                    data[
                        "classes"
                    ]
                )[
                    :MAX_CLASSES_PER_BEHAVIOR
                ],
                "source_files": sorted(
                    data[
                        "sources"
                    ]
                )[
                    :MAX_SOURCES_PER_BEHAVIOR
                ],
                "evidence": (
                    data[
                        "evidence"
                    ]
                )
            }
        )

    return summary


# =========================
# IMPORTANT SOURCES
# =========================

def _get_highest_priority(
    detections: list,
    rule_lookup: dict
) -> str:

    priority_values = {
        "high": 3,
        "medium": 2,
        "low": 1,
        "none": 0
    }

    highest_priority = "none"

    for detection in (
        detections
    ):

        priority = (
            rule_lookup[
                detection[
                    "behavior_id"
                ]
            ][
                "priority"
            ]
        )

        if (
            priority_values[
                priority
            ]
            >
            priority_values[
                highest_priority
            ]
        ):

            highest_priority = (
                priority
            )

    return highest_priority


def _build_important_sources(
    source_records: list,
    component_lookup: dict,
    rule_lookup: dict
) -> list:

    important_sources = []

    for record in (
        source_records
    ):

        component = (
            component_lookup.get(
                record[
                    "class_name"
                ]
            )
        )

        if (
            record[
                "source_origin"
            ]
            !=
            "application"
            and component is None
        ):

            continue

        if (
            not record[
                "detections"
            ]
            and component is None
        ):

            continue

        behaviors = [
            detection[
                "behavior_id"
            ]
            for detection in (
                record[
                    "detections"
                ]
            )
        ]

        evidence = []

        for detection in (
            record[
                "detections"
            ]
        ):

            for item in (
                detection[
                    "evidence"
                ]
            ):

                evidence.append(
                    {
                        "behavior_id": (
                            detection[
                                "behavior_id"
                            ]
                        ),
                        **item
                    }
                )

        important_sources.append(
            {
                "source_file": (
                    record[
                        "source_file"
                    ]
                ),
                "source_origin": (
                    record[
                        "source_origin"
                    ]
                ),
                "class_name": (
                    record[
                        "class_name"
                    ]
                ),
                "component": (
                    component
                ),
                "behaviors": (
                    behaviors
                ),
                "priority": (
                    _get_highest_priority(
                        record[
                            "detections"
                        ],
                        rule_lookup
                    )
                ),
                "evidence": (
                    evidence[
                        :MAX_EVIDENCE_PER_BEHAVIOR
                    ]
                )
            }
        )

    priority_order = {
        "high": 0,
        "medium": 1,
        "low": 2,
        "none": 3
    }

    important_sources.sort(
        key=lambda item: (
            priority_order[
                item[
                    "priority"
                ]
            ],
            item[
                "source_file"
            ]
        )
    )

    return important_sources


# =========================
# PERMISSION CORRELATION
# =========================

def _get_requested_permissions(
    permissions: dict
) -> set:

    return {
        item[
            "name"
        ]
        for item in (
            permissions.get(
                "requested_permissions",
                []
            )
        )
        if item.get(
            "name"
        )
    }


def _build_permission_correlations(
    permissions: dict,
    source_records: list,
    rule_lookup: dict
) -> list:

    requested_permissions = (
        _get_requested_permissions(
            permissions
        )
    )

    permission_data = (
        defaultdict(
            lambda: {
                "behaviors": set(),
                "application_sources": set(),
                "library_sources": set(),
                "evidence": []
            }
        )
    )

    for record in (
        source_records
    ):

        for detection in (
            record[
                "detections"
            ]
        ):

            rule = (
                rule_lookup[
                    detection[
                        "behavior_id"
                    ]
                ]
            )

            for permission_name in (
                rule[
                    "permissions"
                ]
            ):

                data = (
                    permission_data[
                        permission_name
                    ]
                )

                data[
                    "behaviors"
                ].add(
                    detection[
                        "behavior_id"
                    ]
                )

                if (
                    record[
                        "source_origin"
                    ]
                    ==
                    "application"
                ):

                    data[
                        "application_sources"
                    ].add(
                        record[
                            "source_file"
                        ]
                    )

                else:

                    data[
                        "library_sources"
                    ].add(
                        record[
                            "source_file"
                        ]
                    )

                for evidence in (
                    detection[
                        "evidence"
                    ]
                ):

                    if (
                        len(
                            data[
                                "evidence"
                            ]
                        )
                        <
                        MAX_EVIDENCE_PER_BEHAVIOR
                    ):

                        data[
                            "evidence"
                        ].append(
                            evidence
                        )

    correlations = []
    all_permissions = (requested_permissions |set(permission_data.keys()))
    for permission_name in sorted(all_permissions):

        data = (
            permission_data[
                permission_name
            ]
        )

        correlations.append(
            {
                "permission": (
                    permission_name
                ),
                "code_evidence_found": bool(
                    data[
                        "behaviors"
                    ]
                ),
                "related_behaviors": sorted(
                    data[
                        "behaviors"
                    ]
                ),
                "application_source_files": sorted(
                    data[
                        "application_sources"
                    ]
                )[
                    :MAX_SOURCES_PER_BEHAVIOR
                ],
                "library_source_files": sorted(
                    data[
                        "library_sources"
                    ]
                )[
                    :MAX_SOURCES_PER_BEHAVIOR
                ],
                "evidence": (
                    data[
                        "evidence"
                    ]
                )
            }
        )

    return correlations


# =========================
# COMPONENT CORRELATION
# =========================

def _build_component_correlations(
    important_sources: list
) -> list:

    correlations = []

    for source in (
        important_sources
    ):

        component = (
            source[
                "component"
            ]
        )

        if component is None:

            continue

        correlations.append(
            {
                "component_class": (
                    source[
                        "class_name"
                    ]
                ),
                "component_type": (
                    component[
                        "type"
                    ]
                ),
                "exported": (
                    component[
                        "exported"
                    ]
                ),
                "permission": (
                    component[
                        "permission"
                    ]
                ),
                "source_file": (
                    source[
                        "source_file"
                    ]
                ),
                "behaviors": (
                    source[
                        "behaviors"
                    ]
                ),
                "evidence": (
                    source[
                        "evidence"
                    ]
                )
            }
        )

    return correlations


# =========================
# STATISTICS
# =========================

def _build_source_statistics(
    source_records: list
) -> dict:

    source_counts = (
        defaultdict(
            int
        )
    )

    for record in (
        source_records
    ):

        source_counts[
            record[
                "source_origin"
            ]
        ] += 1

    return {
        "total": (
            len(
                source_records
            )
        ),
        "application": (
            source_counts[
                "application"
            ]
        ),
        "androidx": (
            source_counts[
                "androidx"
            ]
        ),
        "google": (
            source_counts[
                "google"
            ]
        ),
        "third_party": (
            source_counts[
                "third_party"
            ]
        ),
        "unknown": (
            source_counts[
                "unknown"
            ]
        )
    }


# =========================
# MAIN PUBLIC FUNCTION
# =========================

def analyze_java_code(
    config: dict,
    apk_info: dict,
    permissions: dict,
    components: dict
) -> dict:

    output_directory = Path(
        config[
            "output_dir"
        ]
    )

    application_package = (
        apk_info.get(
            "package_name"
        )
    )

    if not application_package:

        raise ValueError(
            "APK package name is required "
            "for Java source classification."
        )

    source_directory = (
        _find_source_directory(
            output_directory
        )
    )

    java_files = (
        _get_java_files(
            source_directory
        )
    )

    compiled_rules = (
        _compile_rules()
    )

    rule_lookup = (
        _get_rule_lookup()
    )

    component_lookup = (
        _build_component_lookup(
            components
        )
    )

    source_records = []

    class_count = 0

    for file_path in (
        java_files
    ):

        content = (
            _read_source(
                file_path
            )
        )

        package_name = (
            _get_package_name(
                content
            )
        )

        class_name = (
            _get_class_name(
                content,
                package_name
            )
        )

        if class_name:

            class_count += 1

        source_origin = (
            _classify_source(
                package_name,
                application_package
            )
        )

        source_file = (
            _get_relative_path(
                file_path,
                source_directory
            )
        )

        detections = (
            _detect_file_behaviors(
                content,
                source_file,
                source_origin,
                class_name,
                compiled_rules
            )
        )

        source_records.append(
            {
                "source_file": (
                    source_file
                ),
                "source_origin": (
                    source_origin
                ),
                "package_name": (
                    package_name
                ),
                "class_name": (
                    class_name
                ),
                "imports": (
                    _get_imports(
                        content
                    )
                ),
                "detections": (
                    detections
                )
            }
        )

    behavior_summary = (
        _build_behavior_summary(
            source_records,
            rule_lookup
        )
    )

    important_sources = (
        _build_important_sources(
            source_records,
            component_lookup,
            rule_lookup
        )
    )

    permission_correlations = (
        _build_permission_correlations(
            permissions,
            source_records,
            rule_lookup
        )
    )

    component_correlations = (
        _build_component_correlations(
            important_sources
        )
    )

    behavior_occurrences = sum(
        len(
            record[
                "detections"
            ]
        )
        for record in (
            source_records
        )
    )

    source_statistics = (
        _build_source_statistics(
            source_records
        )
    )

    return {
        "analysis_type": (
            "evidence_based_java_"
            "behavior_mapping"
        ),
        "application_package": (
            application_package
        ),
        "statistics": {
            "java_files_scanned": (
                len(
                    java_files
                )
            ),
            "classes_detected": (
                class_count
            ),
            "behavior_types_detected": (
                len(
                    behavior_summary
                )
            ),
            "behavior_occurrences": (
                behavior_occurrences
            ),
            "important_sources": (
                len(
                    important_sources
                )
            ),
            "component_correlations": (
                len(
                    component_correlations
                )
            ),
            "permission_correlations": (
                len(
                    permission_correlations
                )
            ),
            "source_origins": (
                source_statistics
            )
        },
        "behavior_summary": (
            behavior_summary
        ),
        "important_sources": (
            important_sources
        ),
        "component_correlations": (
            component_correlations
        ),
        "permission_correlations": (
            permission_correlations
        )
    }