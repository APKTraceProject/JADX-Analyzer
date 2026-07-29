import subprocess
from pathlib import Path


def run_jadx(
    config: dict
) -> dict:
    """Run JADX on the target APK."""

    apk_path = Path(
        config["apk_path"]
    )

    jadx_path = Path(
        config["jadx_path"]
    )

    output_dir = Path(
        config["output_dir"]
    )

    if not apk_path.is_file():

        raise FileNotFoundError(
            f"APK file not found:\n"
            f"{apk_path}"
        )

    if not jadx_path.is_file():

        raise FileNotFoundError(
            f"JADX executable not found:\n"
            f"{jadx_path}"
        )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    command = [
        str(jadx_path),

        "--output-dir",

        str(output_dir),

        str(apk_path)
    ]

    print(
        f"  APK: {apk_path.name}"
    )

    print(
        f"  Output: {output_dir}"
    )

    print(
        "  Running JADX..."
    )

    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    output_created = (
        output_dir.exists()
        and any(
            output_dir.iterdir()
        )
    )

    if result.returncode == 0:

        return {
            "status": "success",

            "exit_code": (
                result.returncode
            )
        }

    if output_created:

        return {
            "status": (
                "completed_with_warnings"
            ),

            "exit_code": (
                result.returncode
            )
        }

    raise RuntimeError(
        "JADX failed and no output "
        "was created. "
        f"Exit code: "
        f"{result.returncode}"
    )