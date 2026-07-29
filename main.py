import json
import sys
from pathlib import Path

from modules.apk_info import get_apk_info
from modules.jadx_runner import run_jadx
from modules.permissions import get_permissions


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

    config = load_config()

    jadx_result = run_jadx(
        config
    )

    print(
        "\n[+] Extracting APK information..."
    )

    apk_info = get_apk_info(
        config
    )

    print(
        "[+] APK information extracted."
    )

    print(
        "\n[+] Extracting permissions..."
    )

    permissions = get_permissions(
        config
    )

    print(
        "[+] Permissions extracted."
    )

    result = {
        "jadx": jadx_result,

        "apk_info": apk_info,

        "permissions": permissions
    }

    save_result(
        result
    )

    print(
        "\n[+] Analysis completed."
    )

    print(
        "[+] Result file:"
    )

    print(
        RESULT_FILE
    )


if __name__ == "__main__":

    try:

        main()

    except Exception as error:

        print(
            f"\n[ERROR] {error}"
        )

        sys.exit(1)