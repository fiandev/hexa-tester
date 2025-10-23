#!/usr/bin/env python3
"""
HexaTester v1.0.1
Advanced Defensive Scan & CI Integration
"""

import json
import time
import os
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

# Note: Ensure dependencies are installed: pip install pycryptodome rich requests pyyaml beautifulsoup4

EXPORT_PATH = "./reports"
console = Console()


class SafeSession:
    def __init__(self, timeout=10):
        self.session = requests.Session()
        self.session.timeout = timeout
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )

    def get(self, url, **kwargs):
        return self.session.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(url, **kwargs)


class SimpleLinkParser:
    def __init__(self, base_url):
        self.base_url = base_url

    def parse(self, html):
        soup = BeautifulSoup(html, "html.parser")
        links = [
            urljoin(self.base_url, a.get("href"))
            for a in soup.find_all("a", href=True)
            if a.get("href")
        ]
        js_files = [
            urljoin(self.base_url, script.get("src"))
            for script in soup.find_all("script", src=True)
            if script.get("src")
        ]
        return links, js_files


# Placeholder for other classes and functions


def scan_headers(session, url):
    try:
        response = session.get(url)
        headers = response.headers
        missing = []
        required_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "X-Frame-Options",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
        }
        for header, name in required_headers.items():
            if header not in headers:
                missing.append(name)
        return missing
    except Exception as e:
        return [f"Error: {str(e)}"]


def scan_tls(session, url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "Not HTTPS"
    try:
        response = session.get(url, verify=True)
        cert = response.connection.sock.getpeercert()
        not_after = cert["notAfter"]
        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        if exp_date < datetime.now():
            return "Certificate expired"
        cipher = response.connection.cipher()
        return f"Certificate valid until {not_after}, Cipher: {cipher[0]}"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_fingerprint(session, url):
    try:
        response = session.get(url)
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        meta = re.search(
            r'<meta name="generator" content="([^"]+)"', response.text, re.I
        )
        generator = meta.group(1) if meta else ""
        text = response.text.lower()
        if "wordpress" in text:
            return "WordPress"
        if "react" in text:
            return "React"
        if "asp.net" in text:
            return "ASP.NET"
        return f"Server: {server}, Powered-By: {powered_by}, Generator: {generator}"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_cors(session, url):
    try:
        response = session.get(url)
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            return "CRITICAL: Origin allowed via GET (*)"
        options_response = session.options(url)
        acam = options_response.headers.get("Access-Control-Allow-Methods", "")
        return f"Access-Control-Allow-Origin: {acao}, Methods: {acam}"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_error_disclosure(session, url):
    try:
        error_url = urljoin(url, "/nonexistent")
        response = session.get(error_url)
        if response.status_code == 404:
            text = response.text.lower()
            if "stack trace" in text or "exception" in text or "file not found" in text:
                return "Potential error disclosure"
        return "No error disclosure detected"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_cookies(session, url):
    try:
        response = session.get(url)
        cookies = response.cookies
        issues = []
        for cookie in cookies:
            if not cookie.secure:
                issues.append(f"Cookie {cookie.name} not Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append(f"Cookie {cookie.name} not HttpOnly")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append(f"Cookie {cookie.name} no SameSite")
        return issues if issues else "Cookies secure"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_bac(session, url):
    try:
        endpoints = ["/admin", "/dashboard", "/config", "/api/users"]
        issues = []
        for endpoint in endpoints:
            test_url = urljoin(url, endpoint)
            response = session.get(test_url)
            if response.status_code == 200:
                issues.append(f"Access to {endpoint} without auth")
        return issues if issues else "No BAC issues"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_rate_limit(session, url):
    try:
        login_url = urljoin(url, "/login")
        for i in range(5):
            response = session.post(
                login_url, data={"username": "test", "password": "test"}
            )
            if response.status_code == 429:
                return "Rate limiting detected"
        return "No rate limiting"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_open_redirect(session, url):
    try:
        params = {"redirect": "http://evil.com", "url": "http://evil.com"}
        for param, value in params.items():
            test_url = url + "?" + param + "=" + value
            response = session.get(test_url)
            if response.url != url and "evil.com" in response.url:
                return f"Open redirect via {param}"
        return "No open redirect"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_mixed_content(session, url):
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        mixed = []
        for tag in soup.find_all(["img", "script", "link"], src=True):
            src = tag.get("src")
            if src and src.startswith("http://"):
                mixed.append(src)
        for tag in soup.find_all(["img", "script", "link"], href=True):
            href = tag.get("href")
            if href and href.startswith("http://"):
                mixed.append(href)
        return mixed if mixed else "No mixed content"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_subdomain_recon(session, url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        coEXPORT_PATHmmon_subs = ["www", "api", "admin", "dev", "test", "staging"]
        found = []
        for sub in common_subs:
            sub_url = f"https://{sub}.{domain}"
            try:
                response = session.get(sub_url, timeout=5)
                if response.status_code == 200:
                    found.append(sub_url)
            except:
                pass
        return found if found else "No subdomains found"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_js_analyzer(session, url):
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        js_files = [
            urljoin(url, script.get("src"))
            for script in soup.find_all("script", src=True)
            if script.get("src")
        ]
        secrets = []
        for js_url in js_files:
            try:
                js_response = session.get(js_url)
                text = js_response.text
                if re.search(r"api_key|secret|token", text, re.I):
                    secrets.append(f"Potential secret in {js_url}")
            except:
                pass
        return secrets if secrets else "No secrets found"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_idor(session, url):
    try:
        params = {"id": "1", "user_id": "1"}
        for param, value in params.items():
            test_url = url + "?" + param + "=" + value
            response = session.get(test_url)
            if response.status_code == 200:
                test_url2 = url + "?" + param + "=" + "999"
                response2 = session.get(test_url2)
                if response2.status_code == 200 and response.text != response2.text:
                    return f"Potential IDOR via {param}"
        return "No IDOR detected"
    except Exception as e:
        return f"Error: {str(e)}"


def scan_ssrf(session, url):
    try:
        response = session.get(url)
        text = response.text
        if re.search(r"169\.254\.169\.254|metadata\.google|aws\.amazon", text, re.I):
            return "Potential SSRF endpoint"
        return "No SSRF detected"
    except Exception as e:
        return f"Error: {str(e)}"


def make_header_panel(title, content):
    return Panel(content, title=title, style="bold blue")


def make_table(title, columns, rows):
    table = Table(title=title)
    for col in columns:
        table.add_column(col, style="cyan")
    for row in rows:
        table.add_row(*row)
    return table


def export_ci_summary(target, findings, timestamp):
    summary = {
        "tool_name": "HexaTester - PENTESTING",
        "tool_version": "6.1.2",
        "target": target,
        "timestamp": timestamp,
        "total_critical_findings": len(
            [f for f in findings if f.get("severity") == "CRITICAL"]
        ),
        "findings": findings,
    }
    with open(f"{EXPORT_PATH}/ci_summary_{timestamp}.json", "w") as f:
        json.dump(summary, f, indent=4)
    # YAML would need pyyaml
    # For now, skip YAML


def generate_html_report(target, findings, timestamp):
    html = f"""
    <html>
    <head><title>HexaTester Report</title></head>
    <body>
    <h1>HexaTester Report</h1>
    <p>Target: {target}</p>
    <p>Timestamp: {timestamp}</p>
    <table border="1">
    <tr><th>Module</th><th>Severity</th><th>Details</th></tr>
    """
    for finding in findings:
        html += f"<tr><td>{finding.get('module')}</td><td>{finding.get('severity')}</td><td>{finding.get('details')}</td></tr>"
    html += "</table></body></html>"
    with open(f"{EXPORT_PATH}/report_{timestamp}.html", "w") as f:
        f.write(html)


def main():
    rprint(
        Panel.fit(
            "🛡️ HexaTester - PENTESTING v6.1.2\nAdvanced Defensive Scan & CI Integration",
            style="bold blue",
        )
    )
    target = input("Enter target URL: ").strip()
    if not target.startswith("http"):
        target = "https://" + target
    console.print(f"[green]Target:[/green] {target}")

    mode = input("Select mode (full/header/cors/export): ").strip().lower()
    session = SafeSession()

    findings = []

    with Progress() as progress:
        task = progress.add_task("Scanning...", total=17)

        if mode in ["full", "header"]:
            missing = scan_headers(session, target)
            if missing:
                findings.append(
                    {
                        "module": "Headers",
                        "severity": "CRITICAL",
                        "details": f"{len(missing)} critical headers missing: {', '.join(missing)}",
                    }
                )
            progress.advance(task)

        if mode in ["full", "tls"]:
            tls_result = scan_tls(session, target)
            if "Error" not in tls_result:
                findings.append(
                    {"module": "TLS", "severity": "HIGH", "details": tls_result}
                )
            progress.advance(task)

        if mode in ["full", "fingerprint"]:
            fp_result = scan_fingerprint(session, target)
            findings.append(
                {"module": "Fingerprinting", "severity": "INFO", "details": fp_result}
            )
            progress.advance(task)

        if mode in ["full", "cors"]:
            cors_result = scan_cors(session, target)
            severity = "CRITICAL" if "CRITICAL" in cors_result else "INFO"
            findings.append(
                {"module": "CORS", "severity": severity, "details": cors_result}
            )
            progress.advance(task)

        if mode in ["full", "error"]:
            ed_result = scan_error_disclosure(session, target)
            if "Potential" in ed_result:
                findings.append(
                    {
                        "module": "Error Disclosure",
                        "severity": "HIGH",
                        "details": ed_result,
                    }
                )
            progress.advance(task)

        if mode in ["full", "cookie"]:
            cookie_result = scan_cookies(session, target)
            if isinstance(cookie_result, list):
                findings.append(
                    {
                        "module": "Cookies",
                        "severity": "HIGH",
                        "details": ", ".join(cookie_result),
                    }
                )
            progress.advance(task)

        if mode in ["full", "bac"]:
            bac_result = scan_bac(session, target)
            if isinstance(bac_result, list):
                findings.append(
                    {
                        "module": "BAC",
                        "severity": "CRITICAL",
                        "details": ", ".join(bac_result),
                    }
                )
            progress.advance(task)

        if mode in ["full", "rate"]:
            rl_result = scan_rate_limit(session, target)
            if "No" in rl_result:
                findings.append(
                    {"module": "Rate Limit", "severity": "HIGH", "details": rl_result}
                )
            progress.advance(task)

        if mode in ["full", "redirect"]:
            or_result = scan_open_redirect(session, target)
            if "Open" in or_result:
                findings.append(
                    {
                        "module": "Open Redirect",
                        "severity": "HIGH",
                        "details": or_result,
                    }
                )
            progress.advance(task)

        if mode in ["full", "mixed"]:
            mc_result = scan_mixed_content(session, target)
            if isinstance(mc_result, list):
                findings.append(
                    {
                        "module": "Mixed Content",
                        "severity": "MEDIUM",
                        "details": ", ".join(mc_result),
                    }
                )
            progress.advance(task)

        if mode in ["full", "subdomain"]:
            sr_result = scan_subdomain_recon(session, target)
            if isinstance(sr_result, list):
                findings.append(
                    {
                        "module": "Subdomain Recon",
                        "severity": "INFO",
                        "details": ", ".join(sr_result),
                    }
                )
            progress.advance(task)

        if mode in ["full", "js"]:
            js_result = scan_js_analyzer(session, target)
            if isinstance(js_result, list):
                findings.append(
                    {
                        "module": "JS Analyzer",
                        "severity": "HIGH",
                        "details": ", ".join(js_result),
                    }
                )
            progress.advance(task)

        if mode in ["full", "idor"]:
            idor_result = scan_idor(session, target)
            if "Potential" in idor_result:
                findings.append(
                    {"module": "IDOR", "severity": "HIGH", "details": idor_result}
                )
            progress.advance(task)

        if mode in ["full", "ssrf"]:
            ssrf_result = scan_ssrf(session, target)
            if "Potential" in ssrf_result:
                findings.append(
                    {"module": "SSRF", "severity": "CRITICAL", "details": ssrf_result}
                )
            progress.advance(task)

    # Display results
    table = make_table(
        "Scan Results",
        ["Module", "Severity", "Details"],
        [[f["module"], f["severity"], f["details"]] for f in findings],
    )
    console.print(table)

    # Export
    timestamp = int(time.time())
    export_ci_summary(target, findings, timestamp)
    generate_html_report(target, findings, timestamp)
    console.print("[green]Reports exported.[/green]")


if __name__ == "__main__":
    if not os.path.exists(EXPORT_PATH):
        os.makedirs(EXPORT_PATH)

    main()
