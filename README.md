# HexaTester - Advanced Web Security Scanner

HexaTester is a comprehensive web security scanning tool designed for penetration testing and vulnerability assessment. It helps identify common web application vulnerabilities and security misconfigurations.

## Features

- **Header Security Check**: Detects missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- **TLS & Cipher Scan**: Evaluates SSL/TLS certificates and cipher suites
- **Fingerprinting**: Identifies technologies and frameworks (WordPress, React, ASP.NET, etc.)
- **CORS Check**: Tests for CORS misconfigurations
- **Error Disclosure**: Detects sensitive information in error pages
- **Cookie Security**: Checks cookie attributes (HttpOnly, Secure, SameSite)
- **Broken Access Control (BAC)**: Tests unauthorized access to endpoints
- **Rate Limiting**: Detects brute-force vulnerabilities
- **Open Redirect**: Identifies open redirect vulnerabilities
- **Mixed Content**: Finds HTTP assets on HTTPS sites
- **Subdomain Recon**: Discovers active subdomains
- **JS Analyzer**: Analyzes JavaScript files for secrets and endpoints
- **IDOR Scanner**: Detects Insecure Direct Object References
- **SSRF Scanner**: Identifies potential Server-Side Request Forgery endpoints

## Installation

### Requirements
- Python 3.8 or higher

### Steps
1. Ensure Python 3.8+ is installed on your system.
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Clone or download the tool files to your local machine.
4. Navigate to the tool directory and run:
   ```bash
   python main.py
   ```

## Usage

1. Run the tool:
   ```bash
   python main.py
   ```

2. Enter the target URL when prompted.

3. Select scan mode: `full`, `header`, `cors`, or `export`.

4. View results in the terminal and exported reports.

## Output

- **HTML Report**: `report_<timestamp>.html`
- **JSON Summary**: `ci_summary_<timestamp>.json`

## Warnings

This tool is for educational and authorized security testing only. Unauthorized use on third-party systems is illegal.

## Developer

Sardi Dev
© 2025 Sardi Dev — All Rights Reserved.
