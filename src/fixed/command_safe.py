"""
OS Command Injection - Secure Implementations
===============================================
These are the corrected versions of the vulnerable examples in command_injection.py.

Core Fix: Avoid Shell Interpretation of User Input
----------------------------------------------------
There are three strategies, in order of preference:

1. USE A LIBRARY (best): Replace the shell command entirely with a Python library.
   - Instead of: os.system("ping google.com") → use: icmplib or socket
   - Instead of: os.system("convert file.pdf file.jpg") → use: Pillow, PyMuPDF
   - Instead of: os.popen("sha256sum file") → use: hashlib
   Library calls don't involve a shell, so injection is impossible.

2. PASS ARGUMENTS AS A LIST (correct): Use subprocess with a list, not a string.
   - subprocess.run(["ping", "-c", "4", hostname], shell=False)
   - Each list element is a separate argument passed directly to the program
   - The shell never sees or interprets the arguments
   - Metacharacters (;, &&, |) in user input become literal characters in the argument

3. STRICT ALLOWLIST VALIDATION (last resort): If you must pass to a shell,
   validate input against a strict allowlist before use.
   - Allowlist: "only allow a-z, A-Z, 0-9, ., -"
   - Blocklist (rejecting bad chars) is NOT sufficient — attackers find bypasses

NEVER USE shell=True with user-supplied data.
NEVER USE os.system() or os.popen() with user-supplied data.
"""

import os
import subprocess
import shlex
import re
import hashlib
from pathlib import Path
from typing import List, Dict


# =============================================================================
# FIX 1: Use a library instead of os.system()
# =============================================================================
# Replace shell ping with Python's socket library for connectivity checks.
# Or use a validated, allowlisted hostname with the list-form subprocess.

# Option A: Pure Python — no subprocess needed
import socket

def ping_host_safe_library(hostname: str) -> bool:
    """
    Safe Option A: Use Python's socket library instead of system ping.
    No shell involvement — injection is impossible.
    """
    # Input validation: allow only valid hostname characters
    if not re.match(r'^[a-zA-Z0-9._-]{1,253}$', hostname):
        raise ValueError(f"Invalid hostname format: {hostname!r}")

    # Try to connect to port 80 — lightweight "ping" equivalent
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((hostname, 80))
        return True
    except socket.error:
        return False


def ping_host_safe_subprocess(hostname: str) -> int:
    """
    Safe Option B: List-form subprocess, no shell.
    Each argument is separate — the OS passes them directly to ping.
    The shell never interprets the hostname string.
    """
    # STRICT INPUT VALIDATION: allowlist of safe hostname characters
    # Hostnames can contain: letters, digits, hyphens, dots
    if not re.match(r'^[a-zA-Z0-9._-]{1,253}$', hostname):
        raise ValueError(f"Invalid hostname format: {hostname!r}")

    # Additional check: reject IP addresses with suspicious patterns
    # (not strictly necessary with the above regex, but defense in depth)

    # SAFE: List form — hostname is a discrete argument, not shell-interpolated
    # "google.com; cat /etc/passwd" becomes the literal argument to ping,
    # which ping will try to resolve as a hostname (and fail harmlessly).
    result = subprocess.run(
        ["ping", "-c", "4", hostname],  # List form — no shell
        shell=False,                     # Explicit: no shell interpretation
        capture_output=True,
        text=True,
        timeout=30
    )
    return result.returncode


# =============================================================================
# FIX 2: File conversion with a library instead of subprocess
# =============================================================================
# Replace ImageMagick's convert with Pillow (PIL) for image conversions.
# Library calls don't involve a shell at all.

def convert_image_safe(input_path: str, output_format: str) -> str:
    """
    Safe: Use Pillow library for image conversion — no subprocess involved.
    If you need more complex conversions, use other format-specific libraries.
    """
    # Validate the output format against an allowlist
    ALLOWED_FORMATS = {'png', 'jpg', 'jpeg', 'webp', 'gif', 'bmp'}
    output_format_clean = output_format.lower().strip()
    if output_format_clean not in ALLOWED_FORMATS:
        raise ValueError(f"Unsupported output format: {output_format_clean!r}")

    # Validate the input path (prevent path traversal)
    input_path_obj = Path(input_path).resolve()
    allowed_base = Path('/uploads').resolve()  # Restrict to upload directory
    if not str(input_path_obj).startswith(str(allowed_base)):
        raise ValueError("Input path must be within the uploads directory")

    try:
        from PIL import Image  # pip install Pillow

        # SAFE: Library call — no shell, no injection possible
        with Image.open(input_path_obj) as img:
            output_path = input_path_obj.with_suffix('.' + output_format_clean)
            img.save(output_path)
            return str(output_path)
    except ImportError:
        # Fallback: subprocess with list form and validated inputs
        return convert_file_subprocess_safe(str(input_path_obj), output_format_clean)


def convert_file_subprocess_safe(input_path: str, output_format: str) -> str:
    """Fallback: subprocess with list form (safe even without Pillow)."""
    ALLOWED_FORMATS = frozenset({'png', 'jpg', 'jpeg', 'webp', 'gif', 'bmp', 'pdf'})
    if output_format not in ALLOWED_FORMATS:
        raise ValueError(f"Format not allowed: {output_format!r}")

    output_path = input_path.rsplit('.', 1)[0] + '.' + output_format

    # SAFE: List form — each argument is passed directly to the OS
    result = subprocess.run(
        ["convert", input_path, output_path],  # List, not string
        shell=False,
        capture_output=True,
        text=True,
        timeout=60
    )
    if result.returncode != 0:
        raise RuntimeError(f"Conversion failed: {result.stderr}")
    return output_path


# =============================================================================
# FIX 3: DNS resolution with socket library
# =============================================================================
def resolve_domain_safe(domain: str) -> str:
    """
    Safe: Use socket.getaddrinfo() — a Python standard library function.
    No subprocess, no shell. Injection is impossible.
    """
    # Validate domain format
    if not re.match(r'^[a-zA-Z0-9._-]{1,253}$', domain):
        raise ValueError(f"Invalid domain format: {domain!r}")

    # SAFE: Library call — no shell involved
    try:
        results = socket.getaddrinfo(domain, None)
        return str(results[0][4][0])  # Return first resolved IP
    except socket.gaierror as e:
        raise RuntimeError(f"DNS resolution failed for {domain}: {e}")


# =============================================================================
# FIX 4: File info with os.stat() — no shell needed
# =============================================================================
def get_file_info_safe(file_path: str) -> dict:
    """
    Safe: Use Python's os.stat() instead of running the stat command.
    Returns file metadata without involving a shell.
    """
    import stat as stat_module
    import time

    # Validate path to prevent path traversal (not injection, but important)
    path = Path(file_path).resolve()
    allowed_base = Path('/var/app/uploads').resolve()
    if not str(path).startswith(str(allowed_base)):
        raise ValueError("File path must be within the allowed directory")

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # SAFE: Python library call — no shell
    stat_result = path.stat()
    return {
        'path': str(path),
        'size_bytes': stat_result.st_size,
        'modified': time.ctime(stat_result.st_mtime),
        'created': time.ctime(stat_result.st_ctime),
        'is_file': path.is_file(),
        'is_dir': path.is_dir(),
        'permissions': oct(stat_module.S_IMODE(stat_result.st_mode)),
    }


# =============================================================================
# FIX 5: File operations with Python's shutil — no subprocess
# =============================================================================
import shutil
import tarfile

def backup_directory_safe(source_dir: str, dest_dir: str, compress: bool = True) -> bool:
    """
    Safe: Use shutil and tarfile libraries — no shell commands needed.
    """
    source_path = Path(source_dir).resolve()
    dest_path = Path(dest_dir).resolve()

    # Validate both paths
    allowed_base = Path('/var/app').resolve()
    if not str(source_path).startswith(str(allowed_base)):
        raise ValueError("Source directory must be within the allowed base")
    if not str(dest_path).startswith(str(allowed_base)):
        raise ValueError("Destination directory must be within the allowed base")

    if not source_path.is_dir():
        raise ValueError(f"Source is not a directory: {source_dir}")

    # SAFE: Python library calls — no shell
    if compress:
        archive_path = dest_path.with_suffix('.tar.gz')
        with tarfile.open(archive_path, 'w:gz') as tar:
            tar.add(source_path, arcname=source_path.name)
    else:
        shutil.copytree(source_path, dest_path, dirs_exist_ok=True)

    return True


# =============================================================================
# FIX 6: File type detection with Python-magic library
# =============================================================================
def process_uploaded_files_safe(filenames: List[str]) -> Dict[str, str]:
    """
    Safe: Use python-magic library for MIME type detection — no subprocess.
    Install: pip install python-magic
    """
    results = {}

    try:
        import magic  # python-magic library

        for filename in filenames:
            # Validate the filename — path traversal check
            file_path = Path(filename).resolve()
            allowed_upload_dir = Path('/var/app/uploads').resolve()
            if not str(file_path).startswith(str(allowed_upload_dir)):
                results[filename] = 'ERROR: Path not in upload directory'
                continue
            if not file_path.exists():
                results[filename] = 'ERROR: File not found'
                continue

            # SAFE: Library call — no shell
            mime_type = magic.from_file(str(file_path), mime=True)
            results[filename] = mime_type

    except ImportError:
        # Fallback: use subprocess list form with validated paths
        for filename in filenames:
            file_path = Path(filename).resolve()
            if not file_path.exists():
                results[filename] = 'ERROR: File not found'
                continue

            # SAFE: List form subprocess — filename is a discrete argument
            result = subprocess.run(
                ["file", "--mime-type", "-b", str(file_path)],
                shell=False,  # Critical: no shell
                capture_output=True,
                text=True,
                timeout=10
            )
            results[filename] = result.stdout.strip()

    return results


# =============================================================================
# FIX 7: Replace eval() with a safe expression evaluator
# =============================================================================
# For math formulas: use the ast module to safely parse arithmetic expressions
# without allowing arbitrary code execution.

import ast
import operator

SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

def safe_eval_math(expression: str) -> float:
    """
    Safe: Parse arithmetic expressions using Python's AST module.
    Only allows numbers and basic arithmetic operators — no function calls,
    no imports, no attribute access, no arbitrary code.

    This is safer than eval() because:
    - Uses ast.parse() to build a syntax tree (no execution yet)
    - Walks the tree manually, only allowing specific node types
    - Raises ValueError for any disallowed construct
    """
    # Length limit prevents DoS via complex expressions
    if len(expression) > 200:
        raise ValueError("Expression too long")

    def _eval(node):
        if isinstance(node, ast.Num):  # Python < 3.8
            return node.n
        elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        elif isinstance(node, ast.BinOp):
            op_type = type(node.op)
            if op_type not in SAFE_OPERATORS:
                raise ValueError(f"Operator not allowed: {op_type.__name__}")
            left = _eval(node.left)
            right = _eval(node.right)
            return SAFE_OPERATORS[op_type](left, right)
        elif isinstance(node, ast.UnaryOp):
            op_type = type(node.op)
            if op_type not in SAFE_OPERATORS:
                raise ValueError(f"Unary operator not allowed: {op_type.__name__}")
            return SAFE_OPERATORS[op_type](_eval(node.operand))
        else:
            raise ValueError(f"Expression contains disallowed construct: {type(node).__name__}")

    try:
        tree = ast.parse(expression, mode='eval')
        return float(_eval(tree.body))
    except (SyntaxError, ValueError) as e:
        raise ValueError(f"Invalid expression: {e}")

# Test: safe_eval_math("2 + 3 * 4") → 14.0
# Test: safe_eval_math("__import__('os').system('...')") → ValueError


# =============================================================================
# FIX 8: File operations with allowlist + Python libraries
# =============================================================================
SAFE_FILE_OPERATIONS = {
    'compress': lambda p: _compress_file(p),
    'checksum': lambda p: _checksum_file(p),
    'lines': lambda p: _count_lines(p),
}

def _compress_file(file_path: str) -> str:
    import gzip
    output_path = file_path + '.gz'
    with open(file_path, 'rb') as f_in:
        with gzip.open(output_path, 'wb') as f_out:
            f_out.writelines(f_in)
    return output_path

def _checksum_file(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def _count_lines(file_path: str) -> int:
    with open(file_path, 'r', errors='replace') as f:
        return sum(1 for _ in f)

def run_file_operation_safe(operation: str, filename: str) -> str:
    """
    Safe: Operations implemented as Python functions — no shell commands.
    User input (operation name) validated against an allowlist.
    """
    if operation not in SAFE_FILE_OPERATIONS:
        raise ValueError(f"Unknown operation: {operation!r}. Allowed: {list(SAFE_FILE_OPERATIONS)}")

    # Validate file path
    file_path = Path(filename).resolve()
    allowed_base = Path('/var/app/files').resolve()
    if not str(file_path).startswith(str(allowed_base)):
        raise ValueError("File must be within the allowed directory")
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {filename}")

    # SAFE: Call Python function — no shell
    result = SAFE_FILE_OPERATIONS[operation](str(file_path))
    return str(result)
