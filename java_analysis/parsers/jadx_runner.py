import subprocess
from pathlib import Path
from typing import Dict, Any
from java_analysis.parsers.base_parser import BaseParser


class JadxRunner(BaseParser):
    """Handles JADX decompilation execution."""

    def parse(self, apk_path: Path, jadx_path: Path, output_dir: Path) -> Dict[str, Any]:
        """Decompile target APK using JADX binary."""
        return run_jadx(apk_path=apk_path, jadx_path=jadx_path, output_dir=output_dir)


def run_jadx(apk_path: Path, jadx_path: Path, output_dir: Path) -> Dict[str, Any]:
    """Run JADX executable on target APK with explicit paths."""
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK file not found:\n{apk_path}")

    if not jadx_path.is_file():
        raise FileNotFoundError(f"JADX executable not found:\n{jadx_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        str(jadx_path),
        "--output-dir",
        str(output_dir),
        str(apk_path)
    ]

    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    output_created = output_dir.exists() and any(output_dir.iterdir())

    if result.returncode == 0:
        return {
            "status": "success",
            "exit_code": result.returncode
        }

    if output_created:
        return {
            "status": "completed_with_warnings",
            "exit_code": result.returncode
        }

    raise RuntimeError(
        f"JADX failed and no output was created. Exit code: {result.returncode}"
    )
