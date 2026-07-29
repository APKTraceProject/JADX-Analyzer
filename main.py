import json
import subprocess
import sys
from pathlib import Path


# =========================
# CONFIGURATION
# =========================

CONFIG_FILE = Path("config.json")


def load_config():
    """Load paths from the config file."""

    if not CONFIG_FILE.is_file():
        raise FileNotFoundError(
            f"Config file not found:\n{CONFIG_FILE}"
        )

    with CONFIG_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:
        config = json.load(file)

    return (
        Path(config["apk_path"]),
        Path(config["jadx_path"]),
        Path(config["output_dir"])
    )


APK_PATH, JADX_PATH, OUTPUT_DIR = load_config()

# =========================
# VALIDATION
# =========================

def validate_paths():
    """Check required paths."""

    if not APK_PATH.is_file():
        raise FileNotFoundError(
            f"APK file not found:\n{APK_PATH}"
        )

    if not JADX_PATH.is_file():
        raise FileNotFoundError(
            f"JADX executable not found:\n{JADX_PATH}"
        )


# =========================
# JADX
# =========================

def run_jadx():
    """Run JADX on the APK."""

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    command = [
        str(JADX_PATH),
        "--output-dir",
        str(OUTPUT_DIR),
        str(APK_PATH)
    ]

    print("[+] Running JADX...")
    print(f"[+] APK: {APK_PATH}")
    print(f"[+] Output: {OUTPUT_DIR}\n")

    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    output_created = (
        OUTPUT_DIR.exists()
        and any(OUTPUT_DIR.iterdir())
    )

    if result.returncode == 0:

        print(
            "[+] JADX completed successfully."
        )

    elif output_created:

        print(
            "[+] JADX completed successfully."
        )

        print(
            "[+] Decompiled output was created."
        )

    else:

        raise RuntimeError(
            "JADX failed and no output "
            f"was created. Exit code: "
            f"{result.returncode}"
        )

    print(
        "\n[+] Output directory:"
    )

    print(
        OUTPUT_DIR.resolve()
    )


# =========================
# MAIN
# =========================

def main():

    try:

        validate_paths()

        run_jadx()

    except Exception as error:

        print(
            f"\n[ERROR] {error}"
        )

        sys.exit(1)


if __name__ == "__main__":

    main()