"""
Allowlisted tool registry. Every real external tool call in this project
goes through run_tool() — a list of args is passed straight to subprocess
(shell=False), never a shell string, so there is no command injection
surface. Availability is checked with shutil.which before attempting to
run, and every call has a hard timeout.
"""
import shutil
import subprocess
from typing import Optional

MAX_OUTPUT_CHARS = 6000

ALLOWED_BINARIES = {
    "file", "strings", "objdump", "readelf", "openssl",
    "exiftool", "binwalk", "steghide", "zbarimg", "7z", "unzip",
}


def is_installed(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_tool(binary: str, args: list[str], timeout: int = 15,
             input_bytes: Optional[bytes] = None) -> dict:
    """Returns {status, returncode, stdout, stderr}. status is one of:
    'ran', 'not_installed', 'timeout', 'error'."""
    if binary not in ALLOWED_BINARIES:
        return {"status": "error", "returncode": None, "stdout": "",
                "stderr": f"'{binary}' is not in the allowlisted tool registry."}
    if not is_installed(binary):
        return {"status": "not_installed", "returncode": None, "stdout": "",
                "stderr": f"'{binary}' is not installed on this backend."}
    try:
        proc = subprocess.run(
            [binary, *args],
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
        )
        stdout = proc.stdout.decode("latin-1", errors="replace")[:MAX_OUTPUT_CHARS]
        stderr = proc.stderr.decode("latin-1", errors="replace")[:MAX_OUTPUT_CHARS]
        return {"status": "ran", "returncode": proc.returncode, "stdout": stdout, "stderr": stderr}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "returncode": None, "stdout": "",
                "stderr": f"'{binary}' exceeded the {timeout}s time limit."}
    except Exception as e:
        return {"status": "error", "returncode": None, "stdout": "", "stderr": str(e)}
