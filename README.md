# CIS Benchmark Checker for Windows

A powerful Python-based tool for auditing Windows systems against CIS (Center for Internet Security) Benchmarks, providing comprehensive security posture assessment.

## 🚀 Overview

This tool automates the verification of security configurations on Windows systems according to CIS Benchmark recommendations. It provides thorough checking of 100+ security controls, including:

- Registry settings (password policies, security options, etc.)
- Service configurations (startup type, status)
- Group Policy settings (audit policies, user rights)
- BitLocker encryption status
- Firewall rules
- Windows features
- Modern security features (Credential Guard, TPM, Secure Boot)
- Microsoft Edge security settings
- Windows Defender ATP features
- And much more!

## ✨ Key Features

- **Comprehensive Coverage**: 100+ security checks based on the CIS Benchmark
- **Modular Design**: Easily expandable architecture for adding new checks
- **Flexible Reporting**: Generate JSON and HTML reports
- **Filtering Options**: Run specific checks by type, category, or tag
- **Command-Line Interface**: Powerful CLI with multiple options
- **Web Interface**: Optional web UI for running checks and viewing reports
- **Detailed Logging**: Comprehensive logging of check results and errors

## 📋 Requirements

- Python 3.6+ (tested on Python 3.8+)
- Windows 10/11 system
- Administrative privileges (required for many checks)
- Required Python packages:
  ```
  pywin32==306
  typing-extensions>=4.4.0
  colorama>=0.4.6
  tqdm>=4.64.1
  tabulate>=0.9.0
  flask>=2.0.0 (optional, for web UI)
  ```

## 🔧 Installation

1. Clone or download this repository:
   ```
   git clone https://github.com/yourusername/cis-benchmark-checker.git
   cd cis-benchmark-checker
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run with administrative privileges (required for most checks)

## 🎮 Usage

### Basic Usage

Run the main script with administrative privileges:

```bash
python cis_benchmark_checker.py
```

### Command Line Interface (more options)

```bash
# Run all checks and generate an HTML report
python cli.py --html --output report.json

# Run only registry checks
python cli.py --type registry

# Run checks from a specific category
python cli.py --category "Windows Defender"

# Run checks with a specific tag
python cli.py --tag firewall

# List all checks without running them
python cli.py --list

# Show only failed checks in output
python cli.py --fail-only

# Change output format
python cli.py --format table
```

### Web Interface

Start the web UI for a more user-friendly experience:

```bash
python web_ui.py
```

Then open your browser to http://localhost:5000

## 🧱 Architecture

The tool is built with a modular architecture for flexibility and extensibility:

1. **Core Engine** (`cis_benchmark_checker.py`)
   - Orchestrates the execution of checks
   - Collects and aggregates results

2. **Check Modules**
   - `registry_checks.py` - Windows registry verification
   - `service_checks.py` - Windows service configuration checks
   - `gpo_checks.py` - Group Policy settings
   - `other_checks.py` - Additional checks (BitLocker, firewall, TPM, etc.)

3. **Configuration** (`checks_config.json`)
   - Defines all checks to be performed
   - Can be customized for your environment

4. **Interfaces**
   - `cli.py` - Command-line interface
   - `web_ui.py` - Web-based interface
   - `report_generator.py` - Creates HTML reports

5. **Utilities**
   - `logging_config.py` - Sets up logging
   - `utils.py` - Common utility functions
   - `config_validator.py` - Validates check configurations

## 📊 Check Types

### Registry Checks
Verify Windows registry settings against expected values:
```json
{
  "type": "registry",
  "description": "Ensure 'Minimum password length' is set to '14 or more character(s)'",
  "hive": "HKLM",
  "path": "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
  "key": "MinimumPasswordLength",
  "value_type": "REG_DWORD",
  "expected_value": 14,
  "comparison_op": "greater_than_or_equal"
}
```

### Service Checks
Ensure Windows services are properly configured:
```json
{
  "type": "service",
  "description": "Ensure 'Telnet' service is disabled",
  "name": "Telnet",
  "expected_status": "Stopped",
  "expected_startup": "Disabled"
}
```

### Group Policy Checks
Verify Group Policy settings including audit policies and user rights:
```json
{
  "type": "gpo",
  "subtype": "audit_policy",
  "description": "Ensure 'Audit Account Logon' is set to 'Success and Failure'",
  "category": "Account Logon",
  "expected_value": "Success and Failure"
}
```

### Modern Security Feature Checks
Validate modern Windows security features:
```json
{
  "type": "gpo",
  "subtype": "credential_guard",
  "description": "Ensure 'Windows Credential Guard' is enabled"
}
```

```json
{
  "type": "other",
  "subtype": "tpm",
  "description": "Ensure 'TPM (Trusted Platform Module)' is enabled and ready"
}
```

### Microsoft Edge Checks
Verify Microsoft Edge browser security settings:
```json
{
  "type": "other",
  "subtype": "edge_settings",
  "description": "Ensure 'Block third-party cookies' is enabled",
  "setting": "block_third_party_cookies"
}
```

### Windows Defender Checks
Check Windows Defender and ATP security features:
```json
{
  "type": "other",
  "subtype": "defender_atp",
  "description": "Ensure 'Tamper Protection' is enabled",
  "setting": "tamper_protection"
}
```

## 📝 Customizing Checks

You can customize the checks by modifying `checks_config.json` or creating your own configuration file. Use the `config_validator.py` script to ensure your configuration is valid:

```bash
python config_validator.py your_config.json
```

The web UI also includes a configuration editor.

## 📈 Reports and Analysis

### JSON Reports
Results are saved as JSON for easy parsing and analysis:
```bash
python cli.py --output report.json
```

### HTML Reports
Generate HTML reports for better readability:
```bash
python cli.py --html --output report.json
```

### Compare Reports
Track improvements over time by comparing results:
```bash
python cli.py --compare previous_report.json
```

## 🔍 Advanced Usage

### Testing
Verify the tool's functionality:
```bash
python test-script.py
```

### Targeted Security Areas
Focus on specific security areas:
```bash
python cli.py --tag password-policy
python cli.py --tag encryption
python cli.py --tag exploit-protection
```

### Filtering by Result
See only failing checks:
```bash
python cli.py --fail-only
```

## 🛠️ Troubleshooting

- Check the log file (`cis_benchmark_log.txt`) for detailed error messages
- Ensure you're running with administrative privileges
- Verify all required Python packages are installed
- For GPO checks, make sure `auditpol` and `secedit` commands are available

## 🤝 Contributing

Contributions are welcome! Feel free to submit pull requests for:
- Additional security checks
- Bug fixes
- Performance improvements
- New features or reporting options

## 📜 License

[Add your license information here]

---

Happy security benchmarking! 🔒
