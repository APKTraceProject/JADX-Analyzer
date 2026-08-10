import re
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, List, Set, Tuple
from java_analysis.analyzers.base_analyzer import BaseAnalyzer
from java_analysis.core.utils import (
    find_source_directory,
    find_java_files,
    clean_indicator,
    is_valid_ipv4,
    is_valid_domain
)

STRING_LITERAL_PATTERN = re.compile(r'"(?:\\.|[^"\\])*"')
URL_PATTERN = re.compile(r"(?:https?://|wss?://)[^\s\"'<>\\]+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
DOMAIN_PATTERN = re.compile(
    r"(?<![\w@.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}(?![\w.-])"
)


class NetworkAnalyzer(BaseAnalyzer):
    """Extracts URLs, IP addresses, and domains from decompiled Java source files."""

    def analyze(self, output_dir: Path) -> Dict[str, Any]:
        """Extract network indicators with explicit output directory parameter."""
        return get_network_indicators(output_dir=output_dir)


def _decode_java_string(value: str) -> str:
    value = value[1:-1]
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return value


def _get_string_literals(content: str) -> List[Dict[str, Any]]:
    string_literals = []
    for match in STRING_LITERAL_PATTERN.finditer(content):
        raw_value = match.group()
        value = _decode_java_string(raw_value)
        line_number = content.count("\n", 0, match.start()) + 1
        string_literals.append({"value": value, "line": line_number})
    return string_literals


def _get_url_type(value: str) -> str:
    scheme = urlparse(value).scheme.lower()
    types = {
        "http": "http_url",
        "https": "https_url",
        "ws": "ws_url",
        "wss": "wss_url"
    }
    return types.get(scheme, "url")


def _get_source_path(file_path: Path, source_dir: Path) -> str:
    return str(file_path.relative_to(source_dir.parent)).replace("\\", "/")


def _create_source(file_path: Path, source_dir: Path, line_number: int) -> Dict[str, Any]:
    return {
        "source_file": _get_source_path(file_path, source_dir),
        "line": line_number
    }


def _add_indicator(indicators: dict, value: str, indicator_type: str, source: dict):
    key = (value.lower(), indicator_type)
    if key not in indicators:
        indicators[key] = {
            "value": value,
            "type": indicator_type,
            "sources": [source]
        }
        return

    sources = indicators[key]["sources"]
    if source not in sources:
        sources.append(source)


def _extract_from_string(
    value: str,
    file_path: Path,
    source_dir: Path,
    line_number: int,
    url_indicators: dict,
    domain_indicators: dict,
    ipv4_indicators: dict
):
    source = _create_source(file_path, source_dir, line_number)
    url_ranges: List[Tuple[int, int]] = []

    for match in URL_PATTERN.finditer(value):
        url = clean_indicator(match.group())
        if not url:
            continue

        parsed_url = urlparse(url)
        if not (parsed_url.scheme and parsed_url.netloc):
            continue

        url_type = _get_url_type(url)
        _add_indicator(url_indicators, url, url_type, source)
        url_ranges.append((match.start(), match.end()))

        hostname = parsed_url.hostname
        if not hostname:
            continue

        hostname = hostname.lower()
        if is_valid_ipv4(hostname):
            _add_indicator(ipv4_indicators, hostname, "ipv4", source)
        elif is_valid_domain(hostname):
            _add_indicator(domain_indicators, hostname, "domain", source)

    for match in IPV4_PATTERN.finditer(value):
        ip_value = match.group()
        if not is_valid_ipv4(ip_value):
            continue
        _add_indicator(ipv4_indicators, ip_value, "ipv4", source)

    for match in DOMAIN_PATTERN.finditer(value):
        start, end = match.start(), match.end()
        inside_url = any(start >= u_start and end <= u_end for u_start, u_end in url_ranges)
        if inside_url:
            continue

        domain = match.group().lower()
        if not is_valid_domain(domain):
            continue

        _add_indicator(domain_indicators, domain, "domain", source)


def _sort_indicators(indicators: dict) -> List[Dict[str, Any]]:
    result = list(indicators.values())
    for indicator in result:
        indicator["sources"].sort(key=lambda item: (item["source_file"], item["line"]))
    return sorted(result, key=lambda item: (item["value"].lower(), item["type"]))


def _count_url_types(urls: list) -> Dict[str, int]:
    counts = {"http_url": 0, "https_url": 0, "ws_url": 0, "wss_url": 0}
    for indicator in urls:
        ind_type = indicator["type"]
        if ind_type in counts:
            counts[ind_type] += 1
    return counts


def get_network_indicators(output_dir: Path) -> Dict[str, Any]:
    """Extract network indicators from decompiled Java code."""
    source_dir = find_source_directory(output_dir)
    java_files = find_java_files(source_dir)

    url_indicators: Dict[Tuple[str, str], Dict[str, Any]] = {}
    domain_indicators: Dict[Tuple[str, str], Dict[str, Any]] = {}
    ipv4_indicators: Dict[Tuple[str, str], Dict[str, Any]] = {}
    source_files_with_indicators: Set[Path] = set()

    for java_file in java_files:
        try:
            content = java_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        before_count = len(url_indicators) + len(domain_indicators) + len(ipv4_indicators)
        string_literals = _get_string_literals(content)

        for literal in string_literals:
            _extract_from_string(
                value=literal["value"],
                file_path=java_file,
                source_dir=source_dir,
                line_number=literal["line"],
                url_indicators=url_indicators,
                domain_indicators=domain_indicators,
                ipv4_indicators=ipv4_indicators
            )

        after_count = len(url_indicators) + len(domain_indicators) + len(ipv4_indicators)
        if after_count > before_count:
            source_files_with_indicators.add(java_file)

    urls = _sort_indicators(url_indicators)
    domains = _sort_indicators(domain_indicators)
    ipv4_addresses = _sort_indicators(ipv4_indicators)
    url_type_counts = _count_url_types(urls)

    return {
        "scanned_java_file_count": len(java_files),
        "source_file_count": len(source_files_with_indicators),
        "url_count": len(urls),
        "http_url_count": url_type_counts["http_url"],
        "https_url_count": url_type_counts["https_url"],
        "ws_url_count": url_type_counts["ws_url"],
        "wss_url_count": url_type_counts["wss_url"],
        "urls": urls,
        "domain_count": len(domains),
        "domains": domains,
        "ipv4_count": len(ipv4_addresses),
        "ipv4_addresses": ipv4_addresses
    }
