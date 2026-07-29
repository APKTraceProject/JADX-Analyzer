import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


# =========================
# PATTERNS
# =========================

STRING_LITERAL_PATTERN = re.compile(
    r'"(?:\\.|[^"\\])*"'
)


URL_PATTERN = re.compile(
    r"""
    (?:
        https?://
        |
        wss?://
    )
    [^\s"'<>\\]+
    """,
    re.IGNORECASE
    | re.VERBOSE
)


IPV4_PATTERN = re.compile(
    r"""
    (?<![\w.])
    (?:
        \d{1,3}
        \.
    ){3}
    \d{1,3}
    (?![\w.])
    """,
    re.VERBOSE
)


DOMAIN_PATTERN = re.compile(
    r"""
    (?<![\w@.-])
    (?:
        [a-zA-Z0-9]
        (?:[a-zA-Z0-9-]{0,61}
        [a-zA-Z0-9])?
        \.
    )+
    [a-zA-Z]{2,24}
    (?![\w.-])
    """,
    re.VERBOSE
)


TRAILING_CHARACTERS = (
    ".,;:!?)]}>\"'"
)


# =========================
# VALID TOP-LEVEL DOMAINS
# =========================

COMMON_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "io",
    "ai",
    "app",
    "dev",
    "info",
    "biz",
    "me",
    "tv",
    "co",
    "us",
    "uk",
    "de",
    "fr",
    "it",
    "es",
    "nl",
    "be",
    "ch",
    "at",
    "se",
    "no",
    "dk",
    "fi",
    "pl",
    "cz",
    "ru",
    "ua",
    "tr",
    "ir",
    "ae",
    "sa",
    "qa",
    "in",
    "pk",
    "cn",
    "jp",
    "kr",
    "tw",
    "hk",
    "sg",
    "id",
    "au",
    "nz",
    "ca",
    "br",
    "mx",
    "ar",
    "za",
    "online",
    "site",
    "tech",
    "store",
    "cloud",
    "network",
    "website",
    "services",
    "systems",
    "solutions",
    "digital",
    "media",
    "software",
    "company",
    "global",
    "world",
    "mobile",
    "pro",
    "xyz",
    "top",
    "live",
    "news",
    "blog",
    "space",
    "today"
}


# =========================
# DIRECTORY HELPERS
# =========================

def _find_source_directory(
    output_dir: Path
) -> Path:
    """Find the Decompiled Java source directory."""

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
# STRING EXTRACTION
# =========================

def _decode_java_string(
    value: str
) -> str:
    """Decode common Java string escapes."""

    value = value[1:-1]

    try:

        return bytes(
            value,
            "utf-8"
        ).decode(
            "unicode_escape"
        )

    except UnicodeDecodeError:

        return value


def _get_string_literals(
    content: str
) -> list[dict]:
    """Extract Java string literals and line numbers."""

    string_literals = []

    for match in (
        STRING_LITERAL_PATTERN.finditer(
            content
        )
    ):

        raw_value = (
            match.group()
        )

        value = (
            _decode_java_string(
                raw_value
            )
        )

        line_number = (
            content.count(
                "\n",
                0,
                match.start()
            )
            + 1
        )

        string_literals.append(
            {
                "value": value,
                "line": line_number
            }
        )

    return string_literals


# =========================
# VALIDATION HELPERS
# =========================

def _clean_indicator(
    value: str
) -> str:
    """Remove trailing punctuation."""

    return value.rstrip(
        TRAILING_CHARACTERS
    )


def _is_valid_ipv4(
    value: str
) -> bool:
    """Check whether a value is a valid IPv4 address."""

    try:

        ipaddress.IPv4Address(
            value
        )

        return True

    except ipaddress.AddressValueError:

        return False


def _is_valid_domain(
    value: str
) -> bool:
    """Validate a possible domain."""

    value = (
        value
        .lower()
        .strip(".")
    )

    if not value:

        return False

    if (
        len(value) > 253
    ):

        return False

    if (
        _is_valid_ipv4(
            value
        )
    ):

        return False

    labels = (
        value.split(".")
    )

    if len(labels) < 2:

        return False

    for label in labels:

        if not label:

            return False

        if len(label) > 63:

            return False

        if (
            label.startswith("-")
            or label.endswith("-")
        ):

            return False

        if not re.fullmatch(
            r"[a-z0-9-]+",
            label
        ):

            return False

    tld = labels[-1]

    if tld not in COMMON_TLDS:

        return False

    return True


def _get_url_type(
    value: str
) -> str:
    """Get the type of a URL."""

    scheme = (
        urlparse(
            value
        )
        .scheme
        .lower()
    )

    types = {
        "http": "http_url",
        "https": "https_url",
        "ws": "ws_url",
        "wss": "wss_url"
    }

    return types.get(
        scheme,
        "url"
    )


# =========================
# SOURCE RECORDS
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


def _create_source(
    file_path: Path,
    source_dir: Path,
    line_number: int
) -> dict:
    """Create a source location."""

    return {
        "source_file": (
            _get_source_path(
                file_path,
                source_dir
            )
        ),

        "line": line_number
    }


def _add_indicator(
    indicators: dict,
    value: str,
    indicator_type: str,
    source: dict
):
    """Add an indicator or append a source."""

    key = (
        value.lower(),
        indicator_type
    )

    if key not in indicators:

        indicators[key] = {
            "value": value,

            "type": indicator_type,

            "sources": [
                source
            ]
        }

        return

    sources = (
        indicators[key]["sources"]
    )

    if source not in sources:

        sources.append(
            source
        )


# =========================
# NETWORK EXTRACTION
# =========================

def _extract_from_string(
    value: str,
    file_path: Path,
    source_dir: Path,
    line_number: int,
    url_indicators: dict,
    domain_indicators: dict,
    ipv4_indicators: dict
):
    """Extract network indicators from one string."""

    source = (
        _create_source(
            file_path,
            source_dir,
            line_number
        )
    )

    url_ranges = []

    for match in (
        URL_PATTERN.finditer(
            value
        )
    ):

        url = (
            _clean_indicator(
                match.group()
            )
        )

        if not url:

            continue

        parsed_url = (
            urlparse(
                url
            )
        )

        if not (
            parsed_url.scheme
            and parsed_url.netloc
        ):

            continue

        url_type = (
            _get_url_type(
                url
            )
        )

        _add_indicator(
            url_indicators,
            url,
            url_type,
            source
        )

        url_ranges.append(
            (
                match.start(),
                match.end()
            )
        )

        hostname = (
            parsed_url.hostname
        )

        if not hostname:

            continue

        hostname = (
            hostname
            .lower()
        )

        if _is_valid_ipv4(
            hostname
        ):

            _add_indicator(
                ipv4_indicators,
                hostname,
                "ipv4",
                source
            )

        elif _is_valid_domain(
            hostname
        ):

            _add_indicator(
                domain_indicators,
                hostname,
                "domain",
                source
            )

    for match in (
        IPV4_PATTERN.finditer(
            value
        )
    ):

        ip_value = (
            match.group()
        )

        if not _is_valid_ipv4(
            ip_value
        ):

            continue

        _add_indicator(
            ipv4_indicators,
            ip_value,
            "ipv4",
            source
        )

    for match in (
        DOMAIN_PATTERN.finditer(
            value
        )
    ):

        start = (
            match.start()
        )

        end = (
            match.end()
        )

        inside_url = any(
            start >= url_start
            and end <= url_end
            for (
                url_start,
                url_end
            )
            in url_ranges
        )

        if inside_url:

            continue

        domain = (
            match.group()
            .lower()
        )

        if not _is_valid_domain(
            domain
        ):

            continue

        _add_indicator(
            domain_indicators,
            domain,
            "domain",
            source
        )


# =========================
# RESULT HELPERS
# =========================

def _sort_indicators(
    indicators: dict
) -> list:
    """Sort indicators and their sources."""

    result = list(
        indicators.values()
    )

    for indicator in result:

        indicator["sources"].sort(
            key=lambda item: (
                item["source_file"],
                item["line"]
            )
        )

    return sorted(
        result,
        key=lambda item: (
            item["value"].lower(),
            item["type"]
        )
    )


def _count_url_types(
    urls: list
) -> dict:
    """Count URL types."""

    counts = {
        "http_url": 0,
        "https_url": 0,
        "ws_url": 0,
        "wss_url": 0
    }

    for indicator in urls:

        indicator_type = (
            indicator["type"]
        )

        if indicator_type in counts:

            counts[
                indicator_type
            ] += 1

    return counts


# =========================
# PUBLIC FUNCTION
# =========================

def get_network_indicators(
    config: dict
) -> dict:
    """Extract network indicators from Decompiled Java code."""

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

    url_indicators = {}

    domain_indicators = {}

    ipv4_indicators = {}

    source_files_with_indicators = set()

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

        before_count = (
            len(url_indicators)
            + len(domain_indicators)
            + len(ipv4_indicators)
        )

        string_literals = (
            _get_string_literals(
                content
            )
        )

        for string_literal in (
            string_literals
        ):

            _extract_from_string(
                value=(
                    string_literal[
                        "value"
                    ]
                ),

                file_path=(
                    java_file
                ),

                source_dir=(
                    source_dir
                ),

                line_number=(
                    string_literal[
                        "line"
                    ]
                ),

                url_indicators=(
                    url_indicators
                ),

                domain_indicators=(
                    domain_indicators
                ),

                ipv4_indicators=(
                    ipv4_indicators
                )
            )

        after_count = (
            len(url_indicators)
            + len(domain_indicators)
            + len(ipv4_indicators)
        )

        if (
            after_count
            > before_count
        ):

            source_files_with_indicators.add(
                java_file
            )

    urls = (
        _sort_indicators(
            url_indicators
        )
    )

    domains = (
        _sort_indicators(
            domain_indicators
        )
    )

    ipv4_addresses = (
        _sort_indicators(
            ipv4_indicators
        )
    )

    url_type_counts = (
        _count_url_types(
            urls
        )
    )

    return {
        "scanned_java_file_count": (
            len(java_files)
        ),

        "source_file_count": (
            len(
                source_files_with_indicators
            )
        ),

        "url_count": (
            len(urls)
        ),

        "http_url_count": (
            url_type_counts[
                "http_url"
            ]
        ),

        "https_url_count": (
            url_type_counts[
                "https_url"
            ]
        ),

        "ws_url_count": (
            url_type_counts[
                "ws_url"
            ]
        ),

        "wss_url_count": (
            url_type_counts[
                "wss_url"
            ]
        ),

        "urls": urls,

        "domain_count": (
            len(domains)
        ),

        "domains": domains,

        "ipv4_count": (
            len(
                ipv4_addresses
            )
        ),

        "ipv4_addresses": (
            ipv4_addresses
        )
    }