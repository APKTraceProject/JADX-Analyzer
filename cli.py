import argparse
import sys
from pathlib import Path
from typing import Dict, Any

from java_analysis.core.engine import run_analysis
from java_analysis.core.utils import load_yaml_or_json

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config" / "cli_config.yaml"
DEFAULT_RESULT_PATH = BASE_DIR / "output" / "analysis_result.json"

# Try importing Rich for advanced terminal formatting
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None


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


def print_banner():
    if HAS_RICH and console:
        banner_text = Text()
        banner_text.append("APKTrace ", style="bold cyan")
        banner_text.append("| ", style="dim white")
        banner_text.append("Java Analysis Module\n", style="bold white")
        banner_text.append("Android APK Static Security Analysis Architecture", style="italic gray50")
        console.print(Panel(banner_text, border_style="blue", title="[bold white]JADX-ANALYZER[/bold white]"))
    else:
        print()
        print(f"{Colors.DARK_BLUE}{Colors.BOLD}╔══════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.DARK_BLUE}{Colors.BOLD}║{Colors.RESET}{Colors.BLUE}{Colors.BOLD}              APKTrace{Colors.RESET}{Colors.WHITE}  |  Java Analysis{Colors.RESET}{Colors.DARK_BLUE}{Colors.BOLD}       ║{Colors.RESET}")
        print(f"{Colors.DARK_BLUE}{Colors.BOLD}╚══════════════════════════════════════════════╝{Colors.RESET}")
        print(f"{Colors.GRAY}  Android APK Static Security Analysis Architecture{Colors.RESET}\n")


def print_info(message: str):
    if HAS_RICH and console:
        console.print(f"[bold cyan][INFO][/bold cyan] {message}")
    else:
        print(f"{Colors.GRAY}  [INFO]{Colors.RESET} {message}")


def print_success(message: str):
    if HAS_RICH and console:
        console.print(f"[bold green][SUCCESS][/bold green] {message}")
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}  [SUCCESS]{Colors.RESET} {message}")


def print_warning(message: str):
    if HAS_RICH and console:
        console.print(f"[bold yellow][WARNING][/bold yellow] {message}")
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}  [WARNING]{Colors.RESET} {message}")


def print_error(message: str):
    if HAS_RICH and console:
        console.print(f"[bold red][ERROR][/bold red] {message}")
    else:
        print(f"{Colors.RED}{Colors.BOLD}  [ERROR]{Colors.RESET} {message}")


def display_summary(payload: Dict[str, Any]):
    network = payload.get("network", {})
    java_analysis = payload.get("java_analysis", {})
    java_stats = java_analysis.get("statistics", {})

    if HAS_RICH and console:
        table = Table(title="Java Security Analysis Summary", border_style="blue")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Metric", style="white")
        table.add_column("Value", style="bold green")

        table.add_row("Execution", "JADX Status", str(payload.get("jadx_status", "N/A")))
        table.add_row("Execution", "Target APK", str(payload.get("apk_path", "N/A")))
        table.add_row("Execution", "Output Dir", str(payload.get("output_dir", "N/A")))

        table.add_row("Network Indicators", "Extracted URLs", str(network.get("url_count", 0)))
        table.add_row("Network Indicators", "Extracted Domains", str(network.get("domain_count", 0)))
        table.add_row("Network Indicators", "Extracted IPv4s", str(network.get("ipv4_count", 0)))

        table.add_row("Java Source Analysis", "Application Package", str(java_analysis.get("application_package", "N/A")))
        table.add_row("Java Source Analysis", "Java Files Scanned", str(java_stats.get("java_files_scanned", 0)))
        table.add_row("Java Source Analysis", "Classes Detected", str(java_stats.get("classes_detected", 0)))
        table.add_row("Java Source Analysis", "Behavior Types Detected", str(java_stats.get("behavior_types_detected", 0)))
        table.add_row("Java Source Analysis", "Behavior Occurrences", str(java_stats.get("behavior_occurrences", 0)))
        table.add_row("Java Source Analysis", "Important Sources", str(java_stats.get("important_sources", 0)))

        console.print(table)
    else:
        print()
        print(f"{Colors.DARK_BLUE}{Colors.BOLD}────────────────────────────────────────────────{Colors.RESET}")
        print(f"{Colors.BLUE}{Colors.BOLD}  [SUMMARY]{Colors.RESET} {Colors.WHITE}{Colors.BOLD}Java Analysis Summary{Colors.RESET}")
        print(f"{Colors.DARK_BLUE}{Colors.BOLD}────────────────────────────────────────────────{Colors.RESET}")
        print_info(f"Target APK: {payload.get('apk_path')}")
        print_info(f"Application Package: {java_analysis.get('application_package')}")
        print_info(f"URLs: {network.get('url_count')}")
        print_info(f"Domains: {network.get('domain_count')}")
        print_info(f"IPv4s: {network.get('ipv4_count')}")
        print_info(f"Java files scanned: {java_stats.get('java_files_scanned')}")
        print_info(f"Classes detected: {java_stats.get('classes_detected')}")
        print_info(f"Behavior types detected: {java_stats.get('behavior_types_detected')}")
        print_info(f"Behavior occurrences: {java_stats.get('behavior_occurrences')}")


def load_config_and_cli_args() -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="JADX-ANALYZER CLI - Android Static Security Analysis")
    parser.add_argument("--config", type=str, default=str(DEFAULT_CONFIG_PATH), help="Path to configuration YAML or JSON")
    parser.add_argument("--apk", type=str, help="Path to APK file")
    parser.add_argument("--jadx", type=str, help="Path to JADX binary")
    parser.add_argument("--output", type=str, help="Path to output decompilation directory")
    parser.add_argument("--result", type=str, help="Path to output analysis result JSON")
    parser.add_argument("--package", type=str, help="Application package name (e.g., owasp.mstg.uncrackable3)")

    args = parser.parse_args()

    config_data = {}
    config_file_path = Path(args.config)

    if config_file_path.is_file():
        config_data = load_yaml_or_json(config_file_path)

    raw_apk = args.apk or config_data.get("apk_path")
    raw_jadx = args.jadx or config_data.get("jadx_path")
    raw_output = args.output or config_data.get("output_dir")
    raw_result = args.result or config_data.get("analysis_result_path") or config_data.get("result_path")
    raw_package = args.package or config_data.get("application_package") or config_data.get("package_name")

    if not raw_apk:
        raise ValueError("Missing mandatory configuration or CLI argument: --apk / 'apk_path'")
    if not raw_jadx:
        raise ValueError("Missing mandatory configuration or CLI argument: --jadx / 'jadx_path'")
    if not raw_output:
        raise ValueError("Missing mandatory configuration or CLI argument: --output / 'output_dir'")

    apk_path = Path(raw_apk).resolve()
    jadx_path = Path(raw_jadx).resolve()
    output_dir = Path(raw_output).resolve()
    result_path = Path(raw_result).resolve() if raw_result else DEFAULT_RESULT_PATH.resolve()

    return {
        "apk_path": apk_path,
        "jadx_path": jadx_path,
        "output_dir": output_dir,
        "result_path": result_path,
        "application_package": raw_package
    }


def main():
    print_banner()
    try:
        print_info("Reading CLI configuration & input arguments...")
        params = load_config_and_cli_args()
        print_success("Configuration & paths validated.")

        print_info(f"Target APK: {params['apk_path']}")
        print_info(f"Output Dir: {params['output_dir']}")
        if params.get("application_package"):
            print_info(f"Application Package: {params['application_package']}")

        print_info("Initiating core analysis engine...")
        payload = run_analysis(
            apk_path=params["apk_path"],
            jadx_path=params["jadx_path"],
            output_dir=params["output_dir"],
            result_path=params["result_path"],
            application_package=params.get("application_package")
        )

        print_success("Analysis pipeline executed successfully.")
        display_summary(payload)

        print()
        print_success("Analysis completed.")
        print_info(f"Result file saved to: {payload['result_path']}")
        print()

    except Exception as err:
        print_error(f"Execution failed: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
