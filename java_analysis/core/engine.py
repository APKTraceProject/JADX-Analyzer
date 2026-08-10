from pathlib import Path
from typing import Dict, Any, Optional
from java_analysis.parsers.jadx_runner import JadxRunner
from java_analysis.analyzers.java_code_analyzer import JavaCodeAnalyzer
from java_analysis.analyzers.network_analyzer import NetworkAnalyzer
from java_analysis.reporters.json_reporter import JsonReporter
from java_analysis.core.utils import load_rules


class AnalysisEngine:
    """Core orchestrator for Java decompilation and source analysis pipeline."""

    def execute(
        self,
        apk_path: Path,
        jadx_path: Path,
        output_dir: Path,
        result_path: Path,
        rules_path: Optional[Path] = None,
        application_package: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute complete end-to-end analysis workflow with explicit arguments."""
        return run_analysis(
            apk_path=apk_path,
            jadx_path=jadx_path,
            output_dir=output_dir,
            result_path=result_path,
            rules_path=rules_path,
            application_package=application_package
        )


def run_analysis(
    apk_path: Path,
    jadx_path: Path,
    output_dir: Path,
    result_path: Path,
    rules_path: Optional[Path] = None,
    application_package: Optional[str] = None
) -> Dict[str, Any]:
    """Run Java analysis pipeline (jadx decompilation, java source behavior, network indicators)."""

    # 1. JADX Decompilation
    jadx_runner = JadxRunner()
    jadx_result = jadx_runner.parse(
        apk_path=apk_path,
        jadx_path=jadx_path,
        output_dir=output_dir
    )

    # 2. Load behavior analysis rules
    rules = load_rules(rules_path=rules_path)

    # 3. Java Code Behavior & Network Analysis
    java_analyzer = JavaCodeAnalyzer()
    java_analysis = java_analyzer.analyze(
        output_dir=output_dir,
        rules=rules,
        application_package=application_package
    )

    network_analyzer = NetworkAnalyzer()
    network_analysis = network_analyzer.analyze(output_dir=output_dir)

    # 4. Build Combined Report
    report_data = {
        "jadx": jadx_result,
        "network": network_analysis,
        "java_analysis": java_analysis
    }

    # 5. Save JSON Report
    reporter = JsonReporter()
    saved_file = reporter.report(result_path=result_path, data=report_data)

    # 6. Return Structured Execution Summary Payload
    return {
        "status": "success",
        "apk_path": str(apk_path),
        "output_dir": str(output_dir),
        "result_path": str(saved_file),
        "jadx_status": jadx_result.get("status"),
        "network": network_analysis,
        "java_analysis": java_analysis,
        "report": report_data
    }
