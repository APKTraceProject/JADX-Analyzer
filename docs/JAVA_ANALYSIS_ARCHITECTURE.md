# Java Analysis Architecture (`java_analysis`)

## Overview

The `java_analysis` package serves as the core static security analysis engine for **APK Trace**. It provides a focused, high-throughput pipeline that decompiles Android APK files using JADX into Java source code, inspects decompiled Java source code for security-sensitive API usages and behavior patterns driven by rule definitions (`config/rules.yaml` / `config/rules.json`), extracts network indicators (URLs, domains, IP addresses), and reports structured findings.

---

## Directory Structure

```
java_analysis/
├── __init__.py
├── core/
│   ├── __init__.py
│   ├── engine.py                  <-- Core orchestrator
│   └── utils.py                   <-- Common utilities & static rules loader
├── models/
│   ├── __init__.py
│   ├── context.py                 <-- Surrounding code context lines
│   ├── finding.py                 <-- Behavioral finding dataclass
│   └── location.py                <-- Source location & match dataclass
├── parsers/
│   ├── __init__.py
│   ├── base_parser.py
│   └── jadx_runner.py             <-- JADX decompilation wrapper
├── analyzers/
│   ├── __init__.py
│   ├── base_analyzer.py
│   ├── java_code_analyzer.py      <-- Java source behavior detector
│   └── network_analyzer.py       <-- Network indicator extractor
└── reporters/
    ├── __init__.py
    ├── base_reporter.py
    └── json_reporter.py          <-- Structured JSON output generator
```

---

## Component Layers & Responsibilities

### 1. `parsers/` (Decompilation Layer)
- **`base_parser.py` (`BaseParser`)**: Abstract base interface for parser implementations.
- **`jadx_runner.py` (`JadxRunner`)**: Subprocess wrapper executing the JADX decompilation binary against target APK files, producing decompiled Java source files in the output directory.

### 2. `analyzers/` (Source Analysis Layer & Network Extraction)
- **`base_analyzer.py` (`BaseAnalyzer`)**: Abstract base interface for analyzer implementations.
- **`java_code_analyzer.py` (`JavaCodeAnalyzer`)**: Scans decompiled Java files using compiled regex pattern rules (`config/rules.yaml` / `config/rules.json`) to detect sensitive API usages, runtime process executions, reflection, cryptographic operations, dynamic code loading, device identifier access, and privileged behaviors. Classifies source origin (`application`, `androidx`, `google`, `third_party`, `unknown`) and extracts location evidence with surrounding code context windows.
- **`network_analyzer.py` (`NetworkAnalyzer`)**: Extracts HTTP/HTTPS/WebSocket URLs, IPv4 addresses, and domain names from Java string literals across decompiled source files with source line references.

### 3. `core/` (Pipeline Orchestration & Utilities)
- **`engine.py` (`AnalysisEngine`)**: The main pipeline orchestrator executing the analysis workflow:
  1. Executes JADX decompilation phase (`JadxRunner`).
  2. Automatically loads internal static behavior rules (`load_rules` from `config/rules.yaml` or `config/rules.json`).
  3. Executes Java source code behavior analysis (`JavaCodeAnalyzer`).
  4. Executes network indicator extraction (`NetworkAnalyzer`).
  5. Formats structured result payload and writes JSON report (`JsonReporter`).
- **`utils.py`**: Shared helper utilities:
  - Locates decompiled Java source directories (`find_source_directory`, `find_java_files`).
  - Safely reads Java source files (`read_source_file`).
  - Validates network indicators (IPv4 addresses, domain names with TLD checks).
  - Loads internal static rules files supporting both YAML and JSON formats (`load_yaml_or_json`, `load_rules`).

### 4. `models/` (Data Models Layer)
- **`location.py` (`Location`)**: Dataclass representing precise source code evidence locations, including line numbers, matched code snippets, evidence labels, source origin classification, and code context.
- **`context.py` (`CodeContext`)**: Dataclass defining surrounding code line windows for match context.
- **`finding.py` (`Finding`)**: Dataclass encapsulating aggregated security behavior matches, categories, priorities, source files, affected classes, and associated evidence lists.

### 5. `reporters/` (Output Generation)
- **`base_reporter.py` (`BaseReporter`)**: Abstract base interface for report generators.
- **`json_reporter.py` (`JsonReporter`)**: Serializes the structured security analysis payload into formatted JSON reports (`analysis_result.json`).

---

## Static Behavior Rules (`config/rules.yaml` / `config/rules.json`)

The behavioral detection engine is driven by a static rules configuration file located internally at `config/rules.yaml` (or `config/rules.json`). Each rule specifies:
- `id`: Unique behavior identifier (e.g. `camera_access`, `command_execution`, `crypto_usage`).
- `name`: Human-readable behavior title.
- `category`: Functional domain (e.g. `sensitive_api`, `system_interaction`, `cryptography`).
- `priority`: Severity level (`high`, `medium`, `low`).
- `patterns`: Regular expression patterns paired with evidence descriptions to match within Java source files.

---

## Data Flow Pipeline

```
Target APK + JADX Binary
         │
         ▼
 ┌────────────────┐
 │   JadxRunner   │ ──► Decompiled Java Source Files
 └────────────────┘
         │
         ▼
 ┌────────────────────────────────────────┐
 │ Rules Engine (config/rules.yaml/json)  │
 └────────────────────────────────────────┘
         │
         ├──────────────────────────────┐
         ▼                              ▼
 ┌──────────────────────┐     ┌─────────────────────┐
 │  JavaCodeAnalyzer    │     │   NetworkAnalyzer   │
 └──────────────────────┘     └─────────────────────┘
   (Pattern Matching)           (URL/IP/Domain)
         │                             │
         └──────────────┬──────────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │     JsonReporter      │ ──► JSON Report Output
            └───────────────────────┘
```
