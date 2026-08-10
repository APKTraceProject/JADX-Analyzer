# APK Trace - Java Analysis Module

**APK Trace - Java Analysis Module** is a static security analysis engine focusing strictly on **Java Source Code Analysis and Network Indicator Extraction** from decompiled Android APKs. It decompiles Android APK files using [JADX](https://github.com/skylot/jadx), inspects decompiled Java source code for security-sensitive API usages and behavior patterns driven by internal static rules (`config/rules.yaml` / `config/rules.json`), extracts network indicators, and produces structured security analysis reports.

---

## Features

- **Automated JADX Decompilation**: Decompiles APK bytecode into Java source files.
- **Rule-Based Behavior Detection**: Configurable YAML/JSON rule patterns detecting sensitive API access (camera, microphone, location, SMS, contacts), reflection, dynamic code loading, WebView security issues, custom TLS, and runtime command execution.
- **Network Indicator Extraction**: Identifies HTTP/HTTPS/WebSocket URLs, IPv4 addresses, and domain names embedded in Java source string literals with precise file line references.
- **Source Classification & Origin Tracking**: Categorizes decompiled code into `application`, `androidx`, `google`, `third_party`, or `unknown` packages.
- **Rich Terminal UI**: Command-line interface with formatted summary tables using `rich`.
- **Structured JSON Reporting**: Produces detailed JSON reports mapping evidence back to source file lines and code context windows.

---

## Architecture

The project is structured into modular layers inside the `java_analysis/` package:

- **`java_analysis/core/`**: Pipeline execution engine (`engine.py`) and helper utilities (`utils.py`).
- **`java_analysis/models/`**: Strongly-typed dataclasses (`finding.py`, `location.py`, `context.py`).
- **`java_analysis/parsers/`**: External binary runners (`jadx_runner.py`).
- **`java_analysis/analyzers/`**: Java source code security analyzers (`java_code_analyzer.py`) and network indicator extractors (`network_analyzer.py`).
- **`java_analysis/reporters/`**: Report serialization layer (`json_reporter.py`).

For full technical details, see the [Java Analysis Architecture Documentation](docs/JAVA_ANALYSIS_ARCHITECTURE.md).

---

## Output JSON Schema Example

Below is an example of the structured output generated in `output/analysis_result.json`:

```json
{
  "jadx": {
    "status": "success",
    "output_dir": "output/jadx_output"
  },
  "network": {
    "url_count": 12,
    "domain_count": 5,
    "ipv4_count": 1,
    "urls": [
      {
        "url": "https://api.example.com/v1/login",
        "source_file": "sources/com/example/app/NetworkClient.java",
        "line": 42
      }
    ],
    "domains": ["api.example.com"],
    "ipv4s": ["192.168.1.1"]
  },
  "java_analysis": {
    "analysis_type": "evidence_based_java_behavior_mapping",
    "application_package": "com.example.app",
    "statistics": {
      "java_files_scanned": 150,
      "classes_detected": 180,
      "behavior_types_detected": 4,
      "behavior_occurrences": 12,
      "important_sources": 3
    },
    "behavior_summary": [
      {
        "behavior_id": "camera_access",
        "name": "Camera Access",
        "category": "sensitive_api",
        "priority": "medium",
        "source_files": ["sources/com/example/app/CameraActivity.java"],
        "evidence": [...]
      }
    ],
    "important_sources": [...]
  }
}
```

---

## Quickstart

### 1. Prerequisites

- Python 3.8+
- JADX installed and accessible in system path or specified binary path

### 2. Installation

Clone the repository and install required Python dependencies:

```bash
pip install -r requirements.txt
```

### 3. Configuration

Configure target paths in `config/cli_config.yaml` or copy from `config/cli_config.example.yaml`:

```yaml
apk_path: sample.apk
jadx_path: jadx
output_dir: output/jadx_output
analysis_result_path: output/analysis_result.json
```

---

## Usage Examples

### Run with Default Configuration File

```bash
python3 cli.py
```

### Specify Configuration or Target Paths via CLI Flags

```bash
python3 cli.py --apk path/to/app.apk --jadx /usr/local/bin/jadx --output output/decompiled --result output/report.json
```

### CLI Command Options

```
usage: cli.py [-h] [--config CONFIG] [--apk APK] [--jadx JADX]
              [--output OUTPUT] [--result RESULT]

JADX-ANALYZER CLI - Android Static Security Analysis

options:
  -h, --help       show this help message and exit
  --config CONFIG  Path to configuration YAML or JSON (default: config/cli_config.yaml)
  --apk APK        Path to target APK file
  --jadx JADX      Path to JADX binary
  --output OUTPUT  Path to output decompilation directory
  --result RESULT  Path to output analysis result JSON
```

---

## Project Structure

```
PROJECT_ROOT/
├── config/
│   ├── cli_config.example.yaml
│   ├── cli_config.yaml
│   ├── rules.yaml
│   └── rules.json
├── docs/
│   └── JAVA_ANALYSIS_ARCHITECTURE.md
├── java_analysis/
│   ├── __init__.py
│   ├── core/
│   ├── models/
│   ├── parsers/
│   ├── analyzers/
│   └── reporters/
├── cli.py
├── .gitignore
├── README.md
└── requirements.txt
```

---

## License

MIT License
