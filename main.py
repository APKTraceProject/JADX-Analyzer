import json
import sys
from pathlib import Path

from modules.apk_info import get_apk_info
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
    """Print the APKTrace banner."""

    print()

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        f"╔══════════════════════════════════════════════╗"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        f"║"
        f"{Colors.RESET}"
        f"{Colors.BLUE}"
        f"{Colors.BOLD}"
        f"              APKTrace"
        f"{Colors.RESET}"
        f"{Colors.WHITE}"
        f"  |  JADX Analyzer"
        f"{Colors.RESET}"
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        f"       ║"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        f"╚══════════════════════════════════════════════╝"
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.GRAY}"
        f"  Android APK Static Analysis"
        f"{Colors.RESET}"
    )

    print()


def print_section(
    number: int,
    title: str
):
    """Print an analysis section."""

    print()

    print(
        f"{Colors.DARK_BLUE}"
        f"{Colors.BOLD}"
        f"────────────────────────────────────────────────"
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
        f"────────────────────────────────────────────────"
        f"{Colors.RESET}"
    )


def print_info(
    message: str
):
    """Print an information message."""

    print(
        f"{Colors.GRAY}"
        f"  [INFO]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_success(
    message: str
):
    """Print a success message."""

    print(
        f"{Colors.GREEN}"
        f"{Colors.BOLD}"
        f"  [SUCCESS]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_warning(
    message: str
):
    """Print a warning message."""

    print(
        f"{Colors.YELLOW}"
        f"{Colors.BOLD}"
        f"  [WARNING]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_error(
    message: str
):
    """Print an error message."""

    print(
        f"{Colors.RED}"
        f"{Colors.BOLD}"
        f"  [ERROR]"
        f"{Colors.RESET}"
        f" {message}"
    )


def print_summary(
    apk_info: dict,
    permissions: dict,
    components: dict,
    network: dict
):
    """Print the analysis summary."""

    print_section(
        7,
        "Analysis Summary"
    )

    print(
        f"{Colors.WHITE}"
        f"  Package:"
        f"{Colors.RESET}"
        f" {apk_info['package_name']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  APK size:"
        f"{Colors.RESET}"
        f" {apk_info['file_size_bytes']:,} bytes"
    )

    print(
        f"{Colors.WHITE}"
        f"  Requested permissions:"
        f"{Colors.RESET}"
        f" {permissions['requested_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  Activities:"
        f"{Colors.RESET}"
        f" {components['activity_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  Services:"
        f"{Colors.RESET}"
        f" {components['service_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  Broadcast receivers:"
        f"{Colors.RESET}"
        f" {components['receiver_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  Content providers:"
        f"{Colors.RESET}"
        f" {components['provider_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  Exported components:"
        f"{Colors.RESET}"
        f" {components['exported_component_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  URLs:"
        f"{Colors.RESET}"
        f" {network['url_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  Domains:"
        f"{Colors.RESET}"
        f" {network['domain_count']}"
    )

    print(
        f"{Colors.WHITE}"
        f"  IPv4 addresses:"
        f"{Colors.RESET}"
        f" {network['ipv4_count']}"
    )


# =========================
# CONFIG
# =========================

def load_config() -> dict:
    """Load the project configuration."""

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
                f"Missing config key: "
                f"{key}"
            )

    return config


# =========================
# OUTPUT
# =========================

def save_result(
    result: dict
):
    """Save the analysis result."""

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

    print_info(
        f"Version: "
        f"{apk_info['version_name']}"
    )

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

    print_section(
        6,
        "Saving Results"
    )

    result = {
        "jadx": jadx_result,

        "apk_info": apk_info,

        "permissions": permissions,

        "components": components,

        "network": network
    }

    print_info(
        "Writing analysis result..."
    )

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
        network
    )

    print()

    print(
        f"{Colors.GREEN}"
        f"{Colors.BOLD}"
        f"  Analysis completed successfully."
        f"{Colors.RESET}"
    )

    print(
        f"{Colors.GRAY}"
        f"  Result:"
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