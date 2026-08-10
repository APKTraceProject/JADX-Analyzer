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

DEFAULT_RESULT_FILE = (
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


# =========================
# ANALYSIS SUMMARY
# =========================

def print_summary(
    apk_info: dict,
    permissions: dict,
    components: dict,
    network: dict,
    java_analysis: dict
):

    print_section(
        8,
        "Analysis Summary"
    )

    # -------------------------
    # APK INFORMATION
    # -------------------------

    print_info(
        f"Package: "
        f"{apk_info['package_name']}"
    )

    print_info(
        f"APK size: "
        f"{apk_info['file_size_bytes']:,} bytes"
    )

    # -------------------------
    # PERMISSIONS
    # -------------------------

    print_info(
        f"Requested permissions: "
        f"{permissions['requested_count']}"
    )

    # -------------------------
    # COMPONENTS
    # -------------------------

    print_info(
        f"Activities: "
        f"{components['activity_count']}"
    )

    print_info(
        f"Services: "
        f"{components['service_count']}"
    )

    print_info(
        f"Broadcast receivers: "
        f"{components['receiver_count']}"
    )

    print_info(
        f"Content providers: "
        f"{components['provider_count']}"
    )

    print_info(
        f"Exported components: "
        f"{components['exported_component_count']}"
    )

    # -------------------------
    # NETWORK INDICATORS
    # -------------------------

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

    # -------------------------
    # JAVA ANALYSIS
    # -------------------------

    java_statistics = (
        java_analysis[
            "statistics"
        ]
    )

    print_info(
        f"Java files scanned: "
        f"{java_statistics['java_files_scanned']}"
    )

    print_info(
        f"Classes detected: "
        f"{java_statistics['classes_detected']}"
    )

    print_info(
        f"Behavior types detected: "
        f"{java_statistics['behavior_types_detected']}"
    )

    print_info(
        f"Behavior occurrences: "
        f"{java_statistics['behavior_occurrences']}"
    )

    print_info(
        f"Important source files: "
        f"{java_statistics['important_sources']}"
    )

    print_info(
        f"Component correlations: "
        f"{java_statistics['component_correlations']}"
    )

    print_info(
        f"Permission correlations: "
        f"{java_statistics['permission_correlations']}"
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

    result_file = get_result_file(
        config
    )

    config[
        "analysis_result_path"
    ] = str(
        result_file
    )

    return config


# =========================
# OUTPUT
# =========================

def get_result_file(
    config: dict
) -> Path:

    raw_path = (
        config.get("analysis_result_path")
        or config.get("analysis_result")
        or config.get("analysis_result_file")
        or config.get("result_path")
        or config.get("result_file")
    )

    if raw_path:

        return Path(
            raw_path
        )

    return DEFAULT_RESULT_FILE


def save_result(
    result: dict,
    result_file: Path
):

    result_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with result_file.open(
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

    # ---------------------
    # Configuration
    # ---------------------

    print_info(
        "Loading project configuration..."
    )

    config = load_config()

    print_success(
        "Configuration loaded."
    )

    # ---------------------
    # JADX Decompilation
    # ---------------------

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

    # ---------------------
    # APK Metadata
    # ---------------------

    print_section(
        2,
        "APK Metadata Extraction"
    )

    print_info(
        "Reading APK metadata..."
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

    if "version_name" in apk_info:

        print_info(
            f"Version: "
            f"{apk_info['version_name']}"
        )

    # ---------------------
    # Permissions
    # ---------------------

    print_section(
        3,
        "Permission Extraction"
    )

    print_info(
        "Reading Android permissions..."
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

    print_info(
        f"App-defined: "
        f"{permissions['defined_count']}"
    )

    # ---------------------
    # Android Components
    # ---------------------

    print_section(
        4,
        "Android Component Extraction"
    )

    print_info(
        "Reading application components..."
    )

    components = get_components(
        config
    )

    print_success(
        "Android components extracted."
    )

    print_info(
        f"Activities: "
        f"{components['activity_count']}"
    )

    print_info(
        f"Services: "
        f"{components['service_count']}"
    )

    print_info(
        f"Receivers: "
        f"{components['receiver_count']}"
    )

    print_info(
        f"Providers: "
        f"{components['provider_count']}"
    )

    print_info(
        f"Exported components: "
        f"{components['exported_component_count']}"
    )

    # ---------------------
    # Network Indicators
    # ---------------------

    print_section(
        5,
        "Network Indicator Extraction"
    )

    print_info(
        "Scanning Decompiled Java code..."
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

    # ---------------------
    # Java Analysis
    # ---------------------

    print_section(
        6,
        "Java Security Analysis"
    )

    print_info(
        "Building a lightweight Java behavior map..."
    )

    java_analysis = analyze_java_code(
        config,
        apk_info,
        permissions,
        components
    )


    print_success(
        "Java analysis completed."
    )

    java_statistics = (
        java_analysis[
            "statistics"
        ]
    )

    print_info(
        f"Java files scanned: "
        f"{java_statistics['java_files_scanned']}"
    )

    print_info(
        f"Classes detected: "
        f"{java_statistics['classes_detected']}"
    )

    print_info(
        f"Behavior types: "
        f"{java_statistics['behavior_types_detected']}"
    )

    print_info(
        f"Behavior occurrences: "
        f"{java_statistics['behavior_occurrences']}"
    )

    print_info(
        f"Important source files: "
        f"{java_statistics['important_sources']}"
    )

    print_info(
        f"Component correlations: "
        f"{java_statistics['component_correlations']}"
    )

    print_info(
        f"Permission correlations: "
        f"{java_statistics['permission_correlations']}"
    )



    # ---------------------
    # Save Results
    # ---------------------

    print_section(
        7,
        "Saving Results"
    )

    print_info(
        "Writing analysis result..."
    )

    result = {
        "jadx": jadx_result,

        "apk_info": apk_info,

        "network": network,

        "java_analysis": (
            java_analysis
        )
    }

    result_file = Path(
        config[
            "analysis_result_path"
        ]
    )

    save_result(
        result,
        result_file
    )

    print_success(
        "Analysis result saved."
    )

    # ---------------------
    # Final Summary
    # ---------------------

    print_summary(
        apk_info,
        permissions,
        components,
        network,
        java_analysis
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
        f" {result_file}"
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