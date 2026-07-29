import json
import sys
from pathlib import Path

from modules.apk_info import get_apk_info
from modules.code_analysis import analyze_java_code
from modules.components import get_components
from modules.jadx_runner import run_jadx
from modules.network import get_network_indicators
from modules.permissions import get_permissions


# =========================
# TERMINAL COLORS
# =========================

class Colors:

    RESET = "\033[0m"

    BOLD = "\033[1m"

    BLUE = "\033[38;5;39m"

    DARK_BLUE = "\033[38;5;25m"

    GREEN = "\033[38;5;71m"

    YELLOW = "\033[38;5;179m"

    RED = "\033[38;5;167m"

    GRAY = "\033[38;5;245m"

    WHITE = "\033[38;5;255m"


# =========================
# CONFIGURATION
# =========================

BASE_DIR = Path(
    __file__
).resolve().parent

CONFIG_FILE = (
    BASE_DIR
    / "config.json"
)

RESULT_FILE = (
    BASE_DIR
    / "output"
    / "analysis_result.json"
)


# =========================
# TERMINAL OUTPUT
# =========================

def print_banner():

    print()

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        "╔══════════════════════════════════════════════╗"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        "║"
        f"{Colors.RESET}"
        f"{Colors.BLUE}"
        f"{Colors.BOLD}"
        "              APKTrace"
        f"{Colors.RESET}"
        f"{Colors.WHITE}"
        "  |  JADX Analyzer"
        f"{Colors.RESET}"
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        "       ║"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        "╚══════════════════════════════════════════════╝"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.GRAY}"
        "  Android APK Static Analysis"
        f"{Colors.RESET}"
    )

    print()


def print_section(
    number: int,
    title: str
):

    print()

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        "────────────────────────────────────────────────"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.BLUE}"
        f"{Colors.BOLD}"
        f"  [{number:02d}]"
        f"{Colors.RESET}"
        f" {Colors.WHITE}"
        f"{Colors.BOLD}"
        f"{title}"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        "────────────────────────────────────────────────"
        f"{Colors.RESET}"
    )


def print_info(
    message: str
):

    print(
        f"{Colors.GRAY}"
        "  [INFO]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_success(
    message: str
):

    print(
        f"{Colors.GREEN}"
        f"{Colors.BOLD}"
        "  [SUCCESS]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_warning(
    message: str
):

    print(
        f"{Colors.YELLOW}"
        f"{Colors.BOLD}"
        "  [WARNING]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_error(
    message: str
):

    print(
        f"{Colors.RED}"
        f"{Colors.BOLD}"
        "  [ERROR]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_summary(
    apk_info: dict,
    permissions: dict,
    components: dict,
    network: dict,
    code_analysis: dict
):

    print_section(
        8,
        "Analysis Summary"
    )

    print_info(
        f"Package: "
        f"{apk_info['package_name']}"
    )

    print_info(
        f"Requested permissions: "
        f"{permissions['requested_count']}"
    )

    print_info(
        f"Exported components: "
        f"{components['exported_component_count']}"
    )

    print_info(
        f"URLs: "
        f"{network['url_count']}"
    )

    print_info(
        f"Domains: "
        f"{network['domain_count']}"
    )

    print_info(
        f"IPv4 addresses: "
        f"{network['ipv4_count']}"
    )

    print_info(
        f"Security findings: "
        f"{code_analysis['finding_count']}"
    )

    severity_counts = (
        code_analysis[
            "severity_counts"
        ]
    )

    print_info(
        "Findings by severity: "
        f"High={severity_counts['high']}, "
        f"Medium={severity_counts['medium']}, "
        f"Low={severity_counts['low']}, "
        f"Info={severity_counts['info']}"
    )


# =========================
# CONFIG
# =========================

def load_config() -> dict:

    if not CONFIG_FILE.is_file():

        raise FileNotFoundError(
            f"Config file not found:\n"
            f"{CONFIG_FILE}"
        )

    with CONFIG_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        config = json.load(
            file
        )

    required_keys = [
        "apk_path",
        "jadx_path",
        "output_dir"
    ]

    for key in required_keys:

        if key not in config:

            raise KeyError(
                f"Missing config key: {key}"
            )

    return config


# =========================
# OUTPUT
# =========================

def save_result(
    result: dict
):

    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with RESULT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            ensure_ascii=False,
            indent=4
        )


# =========================
# MAIN
# =========================

def main():

    print_banner()

    print_info(
        "Loading project configuration..."
    )

    config = load_config()

    print_success(
        "Configuration loaded."
    )

    print_section(
        1,
        "JADX Decompilation"
    )

    jadx_result = run_jadx(
        config
    )

    if (
        jadx_result["status"]
        == "success"
    ):

        print_success(
            "JADX completed successfully."
        )

    else:

        print_warning(
            "JADX completed with warnings."
        )

    print_section(
        2,
        "APK Metadata Extraction"
    )

    apk_info = get_apk_info(
        config
    )

    print_success(
        "APK metadata extracted."
    )

    print_info(
        f"Package: "
        f"{apk_info['package_name']}"
    )

    print_section(
        3,
        "Permission Extraction"
    )

    permissions = get_permissions(
        config
    )

    print_success(
        "Permissions extracted."
    )

    print_info(
        f"Requested: "
        f"{permissions['requested_count']}"
    )

    print_section(
        4,
        "Android Component Extraction"
    )

    components = get_components(
        config
    )

    print_success(
        "Android components extracted."
    )

    print_info(
        f"Exported components: "
        f"{components['exported_component_count']}"
    )

    print_section(
        5,
        "Network Indicator Extraction"
    )

    network = (
        get_network_indicators(
            config
        )
    )

    print_success(
        "Network indicators extracted."
    )

    print_info(
        f"URLs: "
        f"{network['url_count']}"
    )

    print_info(
        f"Domains: "
        f"{network['domain_count']}"
    )

    print_info(
        f"IPv4 addresses: "
        f"{network['ipv4_count']}"
    )

    print_section(
        6,
        "Java Security Analysis"
    )

    print_info(
        "Scanning Decompiled Java code..."
    )

    code_analysis = (
        analyze_java_code(
            config
        )
    )

    print_success(
        "Java security analysis completed."
    )

    print_info(
        f"Java files scanned: "
        f"{code_analysis['scanned_java_file_count']}"
    )

    print_info(
        f"Security findings: "
        f"{code_analysis['finding_count']}"
    )

    severity_counts = (
        code_analysis[
            "severity_counts"
        ]
    )

    print_info(
        f"High: "
        f"{severity_counts['high']}"
    )

    print_info(
        f"Medium: "
        f"{severity_counts['medium']}"
    )

    print_info(
        f"Low: "
        f"{severity_counts['low']}"
    )

    print_info(
        f"Info: "
        f"{severity_counts['info']}"
    )

    print_section(
        7,
        "Saving Results"
    )

    result = {
        "jadx": jadx_result,

        "apk_info": apk_info,

        "permissions": permissions,

        "components": components,

        "network": network,

        "code_analysis": (
            code_analysis
        )
    }

    save_result(
        result
    )

    print_success(
        "Analysis result saved."
    )

    print_summary(
        apk_info,
        permissions,
        components,
        network,
        code_analysis
    )

    print()

    print(
        f"{Colors.GREEN}"
        f"{Colors.BOLD}"
        "  Analysis completed successfully."
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.GRAY}"
        "  Result:"
        f"{Colors.RESET}"
        f" {RESULT_FILE}"
    )

    print()


if __name__ == "__main__":

    try:

        main()

    except Exception as error:

        print()

        print_error(
            str(error)
        )

        print()

        sys.exit(1)