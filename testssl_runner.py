#!/usr/bin/env python3
#######################################################
# TestSSL Batch Runner with Detection Test
# Description: Run testssl.sh against multiple domains
#              with built-in detection testing
# Author: Security Testing Script
# Date: 2026-03-09
#######################################################

import csv
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime

RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
NC = '\033[0m'

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

PROG = sys.argv[0]

REPORT_COLUMNS = [
    "Host / IP", "Grade", "TLS 1.0", "TLS 1.1", "3DES", "RC4",
    "SWEET32", "BEAST", "LUCKY13", "BREACH", "HSTS", "OCSP Stapling",
    "Cert Expiry", "Chain OK", "Weak Protocols / Ciphers",
]

# Mutable runtime state, mirrors the bash script's globals
state = {
    'DOMAIN_FILE': "",
    'OUTPUT_DIR': "",
    'SHOW_OUTPUT': False,
    'DEFAULT_DIR': "testssl-output-" + datetime.now().strftime("%d-%m-%Y-%H%M"),
    'TESTSSL_PATH': "testssl.sh",
    'TESTSSL_CMD': "",
    'DOMAINS': [],
    'REPORT': False,
    'REPORT_PATH': "",
    'REPORT_DIR': "",
    'REPORT_JSON_DIR': "",
    'REPORT_ROWS': [],
}


def usage():
    print(f"""
{GREEN}TestSSL Batch Runner with Detection{NC}

{BLUE}Usage:{NC}
    {PROG} [MODE] [OPTIONS]

{BLUE}Arguments:{NC}
    <domain> [domain...]   Scan one or more domains/IPs given directly on the command
                           line, separated by spaces (e.g. example.com 10.0.0.5).
                           Defaults to showing output in the terminal if no -o/-os/
                           --report is given.

    -f <file>              Scan every domain listed in <file> (one per line).
                           Requires at least one of -o, -os, or --report.

    -o [directory]         Save each scan to its own file in [directory].
                           If [directory] is omitted, defaults to
                           testssl-output-DD-MM-YYYY-HHMM.

    -os                    Print each scan's output to the terminal.

    -t <path>              Use this testssl binary/path instead of auto-detecting
                           (and auto-installing) one.

    --report [dir]         Generate a summary.csv report (one row per host).
                           Saved to, in priority order:
                             1) [dir] if given
                             2) the -o directory, if set
                             3) the current directory, otherwise

    --detect               Show what testssl installation will be used (or
                           installed), without scanning anything.

    --interactive          Menu-driven mode: prompts for a domain file and
                           output options.

    -h, --help             Show this help message and exit.

{BLUE}Examples:{NC}
    # Scan a single domain directly (shows output in terminal by default)
    {PROG} example.com

    # Scan multiple domains/IPs directly, separated by spaces
    {PROG} app.example.com api.example.com stage.example.org qa.example.org example.net 192.168.1.100

    # Scan a single domain and also save the result to a directory
    {PROG} example.com -o my-results

    # Detection test mode
    {PROG} --detect

    # Interactive menu
    {PROG} --interactive

    # Save to default directory only
    {PROG} -f domains.txt -o

    # Save to custom directory
    {PROG} -f domains.txt -o my-scan-results

    # Show output in terminal only
    {PROG} -f domains.txt -os

    # Both save to directory AND show in terminal
    {PROG} -f domains.txt -o my-results -os

    # Use custom testssl path
    {PROG} -f domains.txt -o results -t /opt/testssl/testssl.sh

    # Report saved into the -o directory (/home/kali)
    {PROG} -f domains.txt -os -o /home/kali --report

    # Report saved into the current directory
    {PROG} -f domains.txt -os --report

    # Report saved into an explicit directory (/home/kali/test)
    {PROG} -f domains.txt -os --report /home/kali/test

{BLUE}TestSSL Detection:{NC}
    Script automatically detects testssl from these locations (in order):
    1. Command 'testssl' in PATH (Kali Linux apt installation)
    2. Command 'testssl.sh' in PATH
    3. /usr/bin/testssl or /usr/bin/testssl.sh
    4. /usr/local/bin/testssl or /usr/local/bin/testssl.sh
    5. Custom path specified with -t option
    6. ./testssl.sh in current directory
    7. ~/testssl.sh/testssl.sh in home directory

    If testssl isn't found anywhere above, it is installed automatically:
    1. 'apt install testssl.sh' (if running as root, or passwordless sudo is available)
    2. 'git clone' into ~/testssl.sh (no root required)
    3. Downloading a release archive with curl/wget, as a last resort
    A missing 'openssl' (required by testssl) is also auto-installed via apt if possible.

{BLUE}Domain File Format:{NC}
    example.com
    sub.example.com:8443
    192.168.1.100
    https://secure.example.com
""")
    sys.exit(1)


def print_info(msg):
    print(f"{BLUE}[INFO]{NC} {msg}")


def print_success(msg):
    print(f"{GREEN}[SUCCESS]{NC} {msg}")


def print_error(msg):
    print(f"{RED}[ERROR]{NC} {msg}")


def print_warning(msg):
    print(f"{YELLOW}[WARNING]{NC} {msg}")


def print_header(msg):
    print(f"{CYAN}{msg}{NC}")


def _try_run(cmd_parts):
    try:
        subprocess.run(cmd_parts, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def _locate_testssl():
    """Pure lookup: returns a usable testssl command/path, or None if not found."""
    if shutil.which("testssl"):
        print_success("Found testssl command in PATH")
        return "testssl"
    if shutil.which("testssl.sh"):
        print_success("Found testssl.sh command in PATH")
        return "testssl.sh"
    if os.path.isfile("/usr/bin/testssl"):
        print_success("Found testssl at /usr/bin/testssl")
        return "/usr/bin/testssl"
    if os.path.isfile("/usr/bin/testssl.sh"):
        print_success("Found testssl.sh at /usr/bin/testssl.sh")
        return "/usr/bin/testssl.sh"
    if os.path.isfile("/usr/local/bin/testssl"):
        print_success("Found testssl at /usr/local/bin/testssl")
        return "/usr/local/bin/testssl"
    if os.path.isfile("/usr/local/bin/testssl.sh"):
        print_success("Found testssl.sh at /usr/local/bin/testssl.sh")
        return "/usr/local/bin/testssl.sh"
    if state['TESTSSL_PATH'] and state['TESTSSL_PATH'] != "testssl.sh":
        if os.path.isfile(state['TESTSSL_PATH']):
            testssl_cmd = state['TESTSSL_PATH']
            _make_executable(testssl_cmd)
            print_success(f"Using custom testssl path: {state['TESTSSL_PATH']}")
            return testssl_cmd
        print_error(f"Custom testssl path not found: {state['TESTSSL_PATH']}")
        return None
    if os.path.isfile("./testssl.sh"):
        _make_executable("./testssl.sh")
        print_success("Found testssl.sh in current directory")
        return "./testssl.sh"
    home_testssl = os.path.join(os.path.expanduser("~"), "testssl.sh", "testssl.sh")
    if os.path.isfile(home_testssl):
        _make_executable(home_testssl)
        print_success("Found testssl.sh in home directory")
        return home_testssl
    return None


def _make_executable(path):
    try:
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _command_exists(name):
    return shutil.which(name) is not None


def _run_quiet(cmd, timeout=None):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, timeout=timeout)
        return proc.returncode, proc.stdout or ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _apt_prefix():
    """Returns the command prefix needed to run apt (possibly via sudo), or None
    if apt isn't available or root privileges can't be obtained."""
    apt_cmd = "apt-get" if _command_exists("apt-get") else ("apt" if _command_exists("apt") else None)
    if not apt_cmd:
        return None
    if os.geteuid() == 0:
        return [apt_cmd]
    if _command_exists("sudo"):
        return ["sudo", "-n", apt_cmd]
    return None


def ensure_openssl():
    if _command_exists("openssl"):
        return True

    print_warning("'openssl' not found — testssl requires it. Attempting to install it...")
    prefix = _apt_prefix()
    if not prefix:
        print_error("Could not find a way to install 'openssl' automatically (no apt/sudo access).")
        print_info("Please install it manually, e.g.: sudo apt install openssl")
        return False

    _run_quiet(prefix + ["update", "-y"], timeout=180)
    rc, out = _run_quiet(prefix + ["install", "-y", "openssl"], timeout=300)
    if rc == 0 and _command_exists("openssl"):
        print_success("Installed 'openssl' via apt")
        return True

    print_error("Automatic installation of 'openssl' failed:")
    print(out.strip()[-1000:])
    return False


def install_testssl():
    """Best-effort automatic installation of testssl. Returns True if a working
    testssl became available afterward."""
    print_warning("testssl not found — attempting automatic installation...")

    prefix = _apt_prefix()
    if prefix:
        print_info("Installing via apt (testssl.sh package)...")
        _run_quiet(prefix + ["update", "-y"], timeout=180)
        rc, out = _run_quiet(prefix + ["install", "-y", "testssl.sh"], timeout=300)
        if rc == 0 and (shutil.which("testssl") or shutil.which("testssl.sh")):
            print_success("Installed testssl.sh via apt")
            return True
        print_warning("apt install of testssl.sh failed or unavailable, trying git clone instead")
    else:
        print_warning("apt/sudo not available for a package install — trying git clone instead")

    target_dir = os.path.join(os.path.expanduser("~"), "testssl.sh")
    testssl_sh_path = os.path.join(target_dir, "testssl.sh")

    if not os.path.isfile(testssl_sh_path):
        if _command_exists("git"):
            print_info(f"Cloning testssl.sh into {target_dir} ...")
            if os.path.isdir(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
            rc, out = _run_quiet(
                ["git", "clone", "--depth", "1",
                 "https://github.com/drwetter/testssl.sh.git", target_dir],
                timeout=120,
            )
            if rc != 0:
                print_error("git clone of testssl.sh failed:")
                print(out.strip()[-1000:])
                return False
        else:
            print_warning("'git' not found — trying to download a release archive instead")
            archive_url = "https://github.com/drwetter/testssl.sh/archive/refs/heads/3.2.tar.gz"
            tmp_tar = os.path.join(tempfile.gettempdir(), "testssl_sh_archive.tar.gz")
            downloaded = False
            if _command_exists("curl"):
                rc, out = _run_quiet(["curl", "-fsSL", "-o", tmp_tar, archive_url], timeout=120)
                downloaded = rc == 0
            elif _command_exists("wget"):
                rc, out = _run_quiet(["wget", "-q", "-O", tmp_tar, archive_url], timeout=120)
                downloaded = rc == 0
            else:
                print_error("Neither 'git', 'curl', nor 'wget' is available — cannot auto-install testssl")
                return False

            if not downloaded or not os.path.isfile(tmp_tar):
                print_error("Failed to download testssl.sh archive")
                return False

            os.makedirs(target_dir, exist_ok=True)
            rc, out = _run_quiet(["tar", "xzf", tmp_tar, "-C", target_dir, "--strip-components=1"], timeout=60)
            if os.path.isfile(tmp_tar):
                os.remove(tmp_tar)
            if rc != 0:
                print_error("Failed to extract testssl.sh archive:")
                print(out.strip()[-1000:])
                return False

    if os.path.isfile(testssl_sh_path):
        _make_executable(testssl_sh_path)
        print_success(f"testssl.sh is now available at {testssl_sh_path}")
        return True

    print_error("Automatic installation did not produce a usable testssl.sh")
    return False


def detect_testssl():
    ensure_openssl()

    testssl_cmd = _locate_testssl()

    if not testssl_cmd:
        if install_testssl():
            testssl_cmd = _locate_testssl()

    if not testssl_cmd:
        print_error("testssl not found and automatic installation failed!")
        print_info("Tried the following locations:")
        print_info("  - Command 'testssl' in PATH")
        print_info("  - Command 'testssl.sh' in PATH")
        print_info("  - /usr/bin/testssl")
        print_info("  - /usr/bin/testssl.sh")
        print_info("  - /usr/local/bin/testssl")
        print_info("  - /usr/local/bin/testssl.sh")
        print_info("  - ./testssl.sh (current directory)")
        print_info(f"  - {os.path.expanduser('~')}/testssl.sh/testssl.sh")
        print("")
        print_info("Tried automatic installation via:")
        print_info("  - apt install testssl.sh (needs root or passwordless sudo)")
        print_info("  - git clone https://github.com/drwetter/testssl.sh.git")
        print_info("  - Downloading a release archive with curl/wget")
        print("")
        print_info("You can also install it manually and/or use -t to specify a custom path:")
        print_info("  Kali/Debian/Ubuntu: sudo apt install testssl.sh")
        print_info("  Or download from: https://github.com/drwetter/testssl.sh")
        return False

    state['TESTSSL_CMD'] = testssl_cmd

    if not _try_run([testssl_cmd, "--version"]) and not _try_run([testssl_cmd, "-h"]):
        print_warning("testssl found but may not be working correctly")

    return True


def check_testssl():
    return detect_testssl()


def run_detection_test():
    print("")
    print_header("═══════════════════════════════════════════════════════════════════")
    print_header("                  TestSSL Detection Test")
    print_header("═══════════════════════════════════════════════════════════════════")
    print("")

    print_info("Checking for testssl installation...")
    print("")

    print("1. Checking command 'testssl':")
    testssl_path = shutil.which("testssl")
    if testssl_path:
        print(f"   {GREEN}✓ Found: {testssl_path}{NC}")
        try:
            out = subprocess.run(["testssl", "--version"], capture_output=True, text=True)
            first_line = (out.stdout + out.stderr).splitlines()[:1]
            for line in first_line:
                print(f"   {line}")
        except OSError:
            pass
    else:
        print(f"   {RED}✗ Not found{NC}")
    print("")

    print("2. Checking command 'testssl.sh':")
    testssl_sh_path = shutil.which("testssl.sh")
    if testssl_sh_path:
        print(f"   {GREEN}✓ Found: {testssl_sh_path}{NC}")
        try:
            out = subprocess.run(["testssl.sh", "--version"], capture_output=True, text=True)
            first_line = (out.stdout + out.stderr).splitlines()[:1]
            for line in first_line:
                print(f"   {line}")
        except OSError:
            pass
    else:
        print(f"   {RED}✗ Not found{NC}")
    print("")

    print("3. Checking common installation paths:")
    paths = [
        "/usr/bin/testssl",
        "/usr/bin/testssl.sh",
        "/usr/local/bin/testssl",
        "/usr/local/bin/testssl.sh",
        "./testssl.sh",
        os.path.join(os.path.expanduser("~"), "testssl.sh", "testssl.sh"),
    ]
    for path in paths:
        if os.path.isfile(path):
            print(f"   {GREEN}✓ Found: {path}{NC}")
        else:
            print(f"   {RED}✗ Not found: {path}{NC}")
    print("")

    print_header("═══════════════════════════════════════════════════════════════════")
    print_info("Running detection logic from script...")
    print("")

    if detect_testssl():
        print("")
        print_success(f"Script will use: {state['TESTSSL_CMD']}")
        print("")
        print("Testing command:")
        cmd = state['TESTSSL_CMD']
        out = subprocess.run([cmd, "--version"], capture_output=True, text=True)
        lines = (out.stdout + out.stderr).splitlines()
        if not lines:
            out = subprocess.run([cmd, "-h"], capture_output=True, text=True)
            lines = (out.stdout + out.stderr).splitlines()[:5]
        else:
            lines = lines[:3]
        for line in lines:
            print(line)
    else:
        print("")
        print_error("No testssl installation found!")
        print("")
        print("Install testssl:")
        print("  Kali/Debian/Ubuntu: sudo apt install testssl.sh")
        print("  Or download: git clone https://github.com/drwetter/testssl.sh.git")

    print("")
    print_header("═══════════════════════════════════════════════════════════════════")
    print("")


def validate_domain_file():
    domain_file = state['DOMAIN_FILE']
    if not os.path.isfile(domain_file):
        print_error(f"Domain file not found: {domain_file}")
        sys.exit(1)

    if not os.access(domain_file, os.R_OK):
        print_error(f"Cannot read domain file: {domain_file}")
        sys.exit(1)

    with open(domain_file, "r") as f:
        domain_count = sum(1 for line in f if line.strip() != "")

    if domain_count == 0:
        print_error(f"Domain file is empty: {domain_file}")
        sys.exit(1)

    print_success(f"Found {domain_count} domain(s) in {domain_file}")


def sanitize_filename(domain):
    if domain.startswith("http://"):
        domain = domain[len("http://"):]
    elif domain.startswith("https://"):
        domain = domain[len("https://"):]
    return re.sub(r'[^a-zA-Z0-9.-]', '_', domain)


def create_output_dir():
    output_dir = state['OUTPUT_DIR']
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError:
            print_error(f"Failed to create output directory: {output_dir}")
            sys.exit(1)
        print_success(f"Created output directory: {output_dir}")
    else:
        print_info(f"Using existing output directory: {output_dir}")


def _find_finding(items, item_id):
    for item in items:
        if item.get("id") == item_id:
            return item
    return None


def _is_offered(items, item_id):
    entry = _find_finding(items, item_id)
    if not entry:
        return False
    finding = (entry.get("finding") or "").strip().lower()
    return not finding.startswith("not offered")


def _is_flagged(items, item_id):
    """True when testssl rates this finding above 'OK' (i.e. offered/vulnerable)."""
    entry = _find_finding(items, item_id)
    if not entry:
        return False
    return (entry.get("severity") or "").upper() != "OK"


def parse_testssl_json(json_path, fallback_host):
    row = {col: "-" for col in REPORT_COLUMNS}
    row["Host / IP"] = fallback_host
    row["Grade"] = "N/A"
    row["HSTS"] = "No"
    row["OCSP Stapling"] = "No"
    row["Cert Expiry"] = ""
    row["Chain OK"] = "No"
    row["Weak Protocols / Ciphers"] = "None"

    if not json_path or not os.path.isfile(json_path):
        return row

    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        scan_result = data["scanResult"][0]
    except (OSError, ValueError, KeyError, IndexError):
        return row

    row["Host / IP"] = scan_result.get("targetHost") or scan_result.get("ip") or fallback_host

    protocols = scan_result.get("protocols", [])
    ciphers = scan_result.get("ciphers", [])
    vulnerabilities = scan_result.get("vulnerabilities", [])
    server_defaults = scan_result.get("serverDefaults", [])
    header_response = scan_result.get("headerResponse", [])
    rating = scan_result.get("rating", [])

    grade_entry = _find_finding(rating, "overall_grade")
    if grade_entry and grade_entry.get("finding"):
        row["Grade"] = grade_entry["finding"].strip()

    tls1 = _is_offered(protocols, "TLS1")
    tls1_1 = _is_offered(protocols, "TLS1_1")
    des3 = _is_flagged(ciphers, "cipherlist_3DES_IDEA")
    rc4 = _is_flagged(vulnerabilities, "RC4")

    row["TLS 1.0"] = "Yes" if tls1 else "-"
    row["TLS 1.1"] = "Yes" if tls1_1 else "-"
    row["3DES"] = "Yes" if des3 else "-"
    row["RC4"] = "Yes" if rc4 else "-"
    row["SWEET32"] = "Yes" if _is_flagged(vulnerabilities, "SWEET32") else "-"
    row["BEAST"] = "Yes" if _is_flagged(vulnerabilities, "BEAST") else "-"
    row["LUCKY13"] = "Yes" if _is_flagged(vulnerabilities, "LUCKY13") else "-"
    row["BREACH"] = "Yes" if _is_flagged(vulnerabilities, "BREACH") else "-"

    hsts_entry = _find_finding(header_response, "HSTS")
    if hsts_entry:
        finding = (hsts_entry.get("finding") or "").strip().lower()
        row["HSTS"] = "No" if finding.startswith("not offered") else "Yes"

    ocsp_entry = _find_finding(server_defaults, "OCSP_stapling")
    if ocsp_entry:
        finding = (ocsp_entry.get("finding") or "").strip().lower()
        row["OCSP Stapling"] = "No" if finding.startswith("not offered") else "Yes"

    chain_entry = _find_finding(server_defaults, "cert_chain_of_trust")
    if chain_entry:
        finding = (chain_entry.get("finding") or "").strip().lower()
        row["Chain OK"] = "Yes" if finding.startswith("passed") or finding.startswith("ok") else "No"

    expiry_entry = _find_finding(server_defaults, "cert_notAfter")
    if expiry_entry and expiry_entry.get("finding"):
        m = re.match(r'(\d{4}-\d{2}-\d{2})', expiry_entry["finding"].strip())
        row["Cert Expiry"] = m.group(1) if m else expiry_entry["finding"].strip()

    weak = []
    if tls1:
        weak.append("TLS 1.0")
    if tls1_1:
        weak.append("TLS 1.1")
    if des3:
        weak.append("3DES")
    if rc4:
        weak.append("RC4")
    row["Weak Protocols / Ciphers"] = ", ".join(weak) if weak else "None"

    return row


def write_summary_report():
    report_dir = state['REPORT_DIR'] or "."
    if not os.path.isdir(report_dir):
        try:
            os.makedirs(report_dir, exist_ok=True)
        except OSError:
            print_error(f"Failed to create report directory: {report_dir}")
            return

    csv_path = os.path.join(report_dir, "summary.csv")
    try:
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=REPORT_COLUMNS)
            writer.writeheader()
            for row in state['REPORT_ROWS']:
                writer.writerow(row)
    except OSError as exc:
        print_error(f"Failed to write report: {csv_path} ({exc})")
        return

    print_success(f"Report saved to: {csv_path}")


def run_testssl(domain, index, total):
    if not domain or re.match(r'^[\s]*#', domain):
        return

    print_info(f"[{index}/{total}] Testing: {domain}")

    sanitized_name = sanitize_filename(domain)
    output_file = ""

    if state['OUTPUT_DIR']:
        output_file = os.path.join(state['OUTPUT_DIR'], f"{sanitized_name}.txt")

    testssl_cmd = state['TESTSSL_CMD']

    report_json_path = None
    if state['REPORT']:
        report_json_path = os.path.join(state['REPORT_JSON_DIR'], f"{sanitized_name}.json")

    def build_cmd(color):
        cmd = [testssl_cmd, "--color", color]
        if report_json_path:
            cmd += ["--jsonfile-pretty", report_json_path]
        cmd.append(domain)
        return cmd

    if state['OUTPUT_DIR'] and state['SHOW_OUTPUT']:
        print_info(f"Saving to: {output_file} (also showing in terminal)")
        result = _stream_and_tee(build_cmd("3"), output_file)
    elif state['OUTPUT_DIR']:
        print_info(f"Saving to: {output_file}")
        with open(output_file, "w") as f:
            proc = subprocess.run(build_cmd("0"), stdout=f, stderr=subprocess.STDOUT)
        result = proc.returncode
    elif state['SHOW_OUTPUT']:
        print_info("Displaying output in terminal")
        proc = subprocess.run(build_cmd("3"))
        result = proc.returncode
    elif state['REPORT']:
        print_info("Scanning (quiet — report only)")
        proc = subprocess.run(build_cmd("0"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = proc.returncode
    else:
        print_warning("No output destination specified, showing in terminal")
        proc = subprocess.run(build_cmd("3"))
        result = proc.returncode

    if result == 0:
        print_success(f"[{index}/{total}] Completed: {domain}")
    else:
        print_error(f"[{index}/{total}] Failed: {domain} (exit code: {result})")

    if report_json_path:
        state['REPORT_ROWS'].append(parse_testssl_json(report_json_path, domain))

    print("")


def _stream_and_tee(cmd, output_file):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             bufsize=1, universal_newlines=True)
    with open(output_file, "w") as f:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            f.write(ANSI_RE.sub('', line))
    proc.wait()
    return proc.returncode


def run_interactive_mode():
    os.system("clear")
    print("")
    print_header("═══════════════════════════════════════════════════════════════════")
    print_header("              TestSSL Batch Runner - Interactive Mode")
    print_header("═══════════════════════════════════════════════════════════════════")
    print("")

    print("Please select an option:")
    print("")
    print("  1) Test testssl detection")
    print("  2) Run testssl batch scan")
    print("  3) Exit")
    print("")
    choice = input("Enter your choice [1-3]: ")

    if choice == "1":
        run_detection_test()
        print("")
        input("Press Enter to continue...")
        run_interactive_mode()

    elif choice == "2":
        print("")
        state['DOMAIN_FILE'] = input("Enter path to domain file: ")
        if not os.path.isfile(state['DOMAIN_FILE']):
            print_error(f"File not found: {state['DOMAIN_FILE']}")
            print("")
            input("Press Enter to continue...")
            run_interactive_mode()
            return

        print("")
        print("Output options:")
        print("  1) Save to default directory (testssl-output-DD-MM-YYYY-HHMM)")
        print("  2) Save to custom directory")
        print("  3) Show in terminal only")
        print("  4) Save to directory AND show in terminal")
        print("")
        output_choice = input("Select output option [1-4]: ")

        if output_choice == "1":
            state['OUTPUT_DIR'] = state['DEFAULT_DIR']
            state['SHOW_OUTPUT'] = False
        elif output_choice == "2":
            state['OUTPUT_DIR'] = input("Enter output directory name: ")
            state['SHOW_OUTPUT'] = False
        elif output_choice == "3":
            state['OUTPUT_DIR'] = ""
            state['SHOW_OUTPUT'] = True
        elif output_choice == "4":
            state['OUTPUT_DIR'] = input("Enter output directory name (or press Enter for default): ")
            if not state['OUTPUT_DIR']:
                state['OUTPUT_DIR'] = state['DEFAULT_DIR']
            state['SHOW_OUTPUT'] = True
        else:
            print_error("Invalid option")
            print("")
            input("Press Enter to continue...")
            run_interactive_mode()
            return

        print("")
        print_info("Starting scan...")
        time.sleep(1)

        run_batch_scan()

        print("")
        input("Press Enter to continue...")
        run_interactive_mode()

    elif choice == "3":
        print("")
        print_info("Exiting...")
        sys.exit(0)

    else:
        print_error("Invalid choice")
        print("")
        input("Press Enter to continue...")
        run_interactive_mode()


def setup_report():
    if state['REPORT']:
        state['REPORT_ROWS'] = []
        state['REPORT_JSON_DIR'] = tempfile.mkdtemp(prefix="testssl_report_")


def teardown_report():
    if state['REPORT']:
        write_summary_report()
        if state['REPORT_JSON_DIR']:
            shutil.rmtree(state['REPORT_JSON_DIR'], ignore_errors=True)
            state['REPORT_JSON_DIR'] = ""


def run_batch_scan():
    print("")
    print_info("═══════════════════════════════════════════════════════════════")
    print_info("           TestSSL Batch Runner Starting")
    print_info("═══════════════════════════════════════════════════════════════")
    print("")

    if not check_testssl():
        sys.exit(1)

    validate_domain_file()

    if state['OUTPUT_DIR']:
        create_output_dir()

    setup_report()

    print_info("Configuration:")
    print(f"  Domain File: {state['DOMAIN_FILE']}")
    if state['OUTPUT_DIR']:
        print(f"  Output Directory: {state['OUTPUT_DIR']}")
    print(f"  Show Terminal Output: {'true' if state['SHOW_OUTPUT'] else 'false'}")
    print(f"  TestSSL Command: {state['TESTSSL_CMD']}")
    if state['REPORT']:
        print(f"  Report: {os.path.join(state['REPORT_DIR'] or '.', 'summary.csv')}")
    print("")

    with open(state['DOMAIN_FILE'], "r") as f:
        lines = f.readlines()

    domains = [line.rstrip("\n") for line in lines
               if line.strip() != "" and not re.match(r'^[\s]*#', line.strip())]
    total_domains = len(domains)
    print_info(f"Starting scan of {total_domains} domain(s)...")
    print("")

    start_time = time.time()

    index = 1
    for raw_domain in lines:
        domain = raw_domain.rstrip("\n")
        if not domain.strip() or re.match(r'^[\s]*#', domain.strip()):
            continue

        domain = domain.strip()

        run_testssl(domain, index, total_domains)
        index += 1

    end_time = time.time()
    duration = int(end_time - start_time)

    print("")
    print_info("═══════════════════════════════════════════════════════════════")
    print_success("           TestSSL Batch Runner Completed")
    print_info("═══════════════════════════════════════════════════════════════")
    print("")
    print_info("Summary:")
    print(f"  Total Domains Scanned: {total_domains}")
    print(f"  Total Duration: {duration} seconds")
    if state['OUTPUT_DIR']:
        print(f"  Results Saved To: {state['OUTPUT_DIR']}")
        try:
            file_count = len(os.listdir(state['OUTPUT_DIR']))
        except OSError:
            file_count = 0
        print(f"  Result Files: {file_count}")
    teardown_report()
    print("")
    print_success("All scans completed!")
    print("")


def run_domain_scan(domains):
    print("")
    print_info("═══════════════════════════════════════════════════════════════")
    print_info("           TestSSL Domain Scan Starting")
    print_info("═══════════════════════════════════════════════════════════════")
    print("")

    if not check_testssl():
        sys.exit(1)

    if state['OUTPUT_DIR']:
        create_output_dir()

    setup_report()

    total = len(domains)

    print_info("Configuration:")
    print(f"  Domain(s): {', '.join(domains)}")
    if state['OUTPUT_DIR']:
        print(f"  Output Directory: {state['OUTPUT_DIR']}")
    print(f"  Show Terminal Output: {'true' if state['SHOW_OUTPUT'] else 'false'}")
    print(f"  TestSSL Command: {state['TESTSSL_CMD']}")
    if state['REPORT']:
        print(f"  Report: {os.path.join(state['REPORT_DIR'] or '.', 'summary.csv')}")
    print("")

    print_info(f"Starting scan of {total} domain(s)...")
    print("")

    start_time = time.time()

    for index, domain in enumerate(domains, start=1):
        run_testssl(domain, index, total)

    end_time = time.time()
    duration = int(end_time - start_time)

    print("")
    print_info("═══════════════════════════════════════════════════════════════")
    print_success("           TestSSL Domain Scan Completed")
    print_info("═══════════════════════════════════════════════════════════════")
    print("")
    print_info("Summary:")
    print(f"  Total Domains Scanned: {total}")
    print(f"  Total Duration: {duration} seconds")
    if state['OUTPUT_DIR']:
        print(f"  Results Saved To: {state['OUTPUT_DIR']}")
        try:
            file_count = len(os.listdir(state['OUTPUT_DIR']))
        except OSError:
            file_count = 0
        print(f"  Result Files: {file_count}")
    teardown_report()
    print("")
    print_success("All scans completed!")
    print("")


def resolve_report_dir():
    if not state['REPORT']:
        return
    if state['REPORT_PATH']:
        state['REPORT_DIR'] = state['REPORT_PATH']
    elif state['OUTPUT_DIR']:
        state['REPORT_DIR'] = state['OUTPUT_DIR']
    else:
        state['REPORT_DIR'] = "."


def main():
    save_output = False
    mode = ""

    argv = sys.argv[1:]
    if len(argv) == 0:
        usage()

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--detect":
            mode = "detect"
            i += 1
        elif arg == "--interactive":
            mode = "interactive"
            i += 1
        elif arg == "-f":
            mode = "scan"
            state['DOMAIN_FILE'] = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
        elif arg == "-o":
            save_output = True
            if i + 1 < len(argv) and argv[i + 1] and not argv[i + 1].startswith("-"):
                state['OUTPUT_DIR'] = argv[i + 1]
                i += 2
            else:
                state['OUTPUT_DIR'] = state['DEFAULT_DIR']
                i += 1
        elif arg == "-os":
            state['SHOW_OUTPUT'] = True
            i += 1
        elif arg == "-t":
            state['TESTSSL_PATH'] = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
        elif arg == "--report":
            state['REPORT'] = True
            if i + 1 < len(argv) and argv[i + 1] and not argv[i + 1].startswith("-"):
                state['REPORT_PATH'] = argv[i + 1]
                i += 2
            else:
                i += 1
        elif arg in ("-h", "--help"):
            usage()
        elif not arg.startswith("-"):
            mode = "domain"
            state['DOMAINS'].append(arg)
            i += 1
        else:
            print_error(f"Unknown option: {arg}")
            usage()

    if mode == "detect":
        run_detection_test()
    elif mode == "interactive":
        run_interactive_mode()
    elif mode == "domain":
        if not save_output and not state['SHOW_OUTPUT'] and not state['REPORT']:
            state['SHOW_OUTPUT'] = True

        if save_output and not state['OUTPUT_DIR']:
            state['OUTPUT_DIR'] = state['DEFAULT_DIR']

        resolve_report_dir()

        run_domain_scan(state['DOMAINS'])
    elif mode == "scan":
        if not state['DOMAIN_FILE']:
            print_error("Domain file is required for scan mode (-f option)")
            usage()

        if not save_output and not state['SHOW_OUTPUT'] and not state['REPORT']:
            print_error("At least one output option must be specified (-o, -os, or --report)")
            usage()

        if save_output and not state['OUTPUT_DIR']:
            state['OUTPUT_DIR'] = state['DEFAULT_DIR']

        resolve_report_dir()

        run_batch_scan()
    else:
        print_error("No mode specified")
        usage()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")
        sys.exit(130)
