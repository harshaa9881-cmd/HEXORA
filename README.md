# HEXORA
# Hexora

### AI-Assisted Multi-Language Security Analysis & Vulnerability Assessment Platform

Hexora is a security analysis platform designed to identify vulnerabilities, insecure coding patterns, secrets, dangerous APIs, dependency risks, and potential data-flow issues across multiple programming languages.

The project combines **static code analysis, rule-based detection, security knowledge bases, compliance mapping, and automated reporting** to provide developers and security teams with actionable security findings.

---

## Features

* Multi-language source code security scanning
* Static analysis for common security vulnerabilities
* Secret and credential detection
* Dangerous API and insecure coding pattern detection
* Dependency security analysis
* Taint/data-flow analysis
* AST-based source code analysis
* Rule-based vulnerability detection
* OWASP and CWE-oriented security rules
* Compliance mapping
* Secure coding recommendations
* Parallel scanning engine
* Automated security report generation
* JSON, HTML, PDF and SARIF reporting
* Background scanning/service daemon support

---

## Supported Languages

Hexora currently contains language-specific scanners for:

* Python
* Java
* JavaScript
* TypeScript
* PHP
* C#
* Go
* Ruby
* Shell
* JSON
* YAML
* Configuration files

---

## Architecture

```text
                    ┌──────────────────────┐
                    │     Source Code      │
                    │  Application / Repo  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Scanner Engine     │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        AST Analysis     Rule Engine      Secret Scanner
              │                │                │
              └────────────────┼────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        Taint Analysis   Dependency Scan   Dangerous APIs
              │                │                │
              └────────────────┼────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Result Builder     │
                    │ Severity / CWE /     │
                    │ Security Findings    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Compliance Mapping   │
                    │ & Recommendations    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Report Generation  │
                    └──────────────────────┘
                         │    │    │    │
                         ▼    ▼    ▼    ▼
                       JSON HTML PDF SARIF
```

---

## Project Structure

```text
hexora/
│
├── core/
│   ├── ast_manager.py
│   ├── compliance_mapper.py
│   ├── dependency_scanner.py
│   ├── file_manager.py
│   ├── parallel_engine.py
│   ├── recommendation_engine.py
│   ├── result_builder.py
│   ├── rule_engine.py
│   ├── secret_scanner.py
│   ├── taint_engine.py
│   └── utils.py
│
├── languages/
│   ├── python_scanner.py
│   ├── javascript_scanner.py
│   ├── typescript_scanner.py
│   ├── java_scanner.py
│   ├── php_scanner.py
│   ├── csharp_scanner.py
│   ├── go_scanner.py
│   ├── ruby_scanner.py
│   ├── shell_scanner.py
│   ├── json_scanner.py
│   ├── yaml_scanner.py
│   └── config_scanner.py
│
├── rulepacks/
│   ├── cwe_rules.json
│   ├── owasp_2025.json
│   ├── dangerous_api_rules.json
│   ├── crypto_rules.json
│   ├── severity_map.json
│   ├── compliance_map.json
│   ├── sources.json
│   ├── sinks.json
│   └── sanitizers.json
│
├── reports/
│   ├── html_renderer.py
│   ├── json_renderer.py
│   ├── pdf_renderer.py
│   ├── sarif_renderer.py
│   └── dashboard_renderer.py
│
├── scanner_v2.py
└── service_daemon.py
```

---

## Security Analysis Pipeline

Hexora follows a modular analysis pipeline:

```text
Source Code
     ↓
File Discovery
     ↓
Language Detection
     ↓
Language-Specific Scanner
     ↓
AST / Pattern Analysis
     ↓
Rule Engine
     ↓
Secret Detection
     ↓
Dependency Analysis
     ↓
Taint / Data-Flow Analysis
     ↓
Severity Classification
     ↓
CWE / OWASP Mapping
     ↓
Compliance Mapping
     ↓
Security Recommendations
     ↓
Report Generation
```

---

## Rule-Based Detection

Hexora uses structured rule packs to define security checks and classify findings.

The rule packs cover areas including:

* OWASP security categories
* CWE mappings
* Cryptographic weaknesses
* Dangerous APIs
* Secure coding practices
* Sources and sinks
* Sanitizers
* Severity classification
* Compliance mappings

This architecture allows security rules to be extended without having to redesign the entire scanning engine.

---

## Reporting

Hexora includes multiple reporting formats:

| Format    | Purpose                           |
| --------- | --------------------------------- |
| JSON      | Machine-readable security results |
| HTML      | Human-readable security report    |
| PDF       | Shareable security assessment     |
| SARIF     | Integration with security tooling |
| Dashboard | Security findings overview        |

---

## Example Use Case

A developer can provide a source-code repository to Hexora for security analysis.

Hexora analyzes the project and identifies potential issues such as:

```text
Hardcoded Secrets
Insecure Cryptography
Dangerous APIs
Injection Risks
Unsafe Data Flow
Dependency Risks
Insecure Coding Patterns
```

The findings can then be classified by severity and mapped to relevant security frameworks and recommendations.

---

## Technology

### Programming

* Python

### Security Concepts

* Static Application Security Testing
* Source Code Analysis
* AST Analysis
* Taint Analysis
* Secret Detection
* Dependency Analysis
* Secure Coding
* Vulnerability Classification

### Security Standards / Knowledge Bases

* OWASP
* CWE
* Secure Coding Practices
* Compliance Mapping

### Output Standards

* JSON
* HTML
* PDF
* SARIF

---

## Installation

Clone the repository:

```bash
git clone https://github.com/harshaa9881-cmd/hexora.git
cd hexora
```

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

> If a `requirements.txt` file is not yet included, dependencies can be added based on the modules used by the project.

---

## Usage

The primary scanner can be executed using:

```bash
python scanner_v2.py
```

For service-based execution:

```bash
python service_daemon.py
```

Refer to the source code and scanner configuration for available options.

---

## Security Disclaimer

Hexora is intended for **authorized security testing, secure software development, vulnerability research, and defensive security analysis**.

Only scan source code and systems that you own or have explicit permission to assess.

---

## Project Status

**Active Development**

Hexora is an evolving security analysis platform. Detection coverage, language support, rule packs, reporting capabilities, and analysis accuracy can be expanded over time.

---

## Future Improvements

Planned areas for further development include:

* Improved interprocedural taint analysis
* Expanded vulnerability rule coverage
* Additional programming language support
* AI-assisted vulnerability explanation
* Improved false-positive reduction
* CI/CD security integration
* GitHub/GitLab repository integration
* Interactive security dashboard
* Automated remediation suggestions
* Enhanced compliance reporting

---

## Author

**HARSHINI PRIYA R**

Cybersecurity | Ethical Hacking | SOC | VAPT | GRC

GitHub:
https://github.com/harshaa9881-cmd

---

## License

This project is currently under development. Licensing information will be added in a future release.
