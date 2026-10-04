import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import solvers.reverse_solver as rs

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _gcc_available():
    import shutil
    return shutil.which("gcc") is not None


pytestmark = pytest.mark.skipif(not _gcc_available(), reason="gcc not available to compile test binaries")


@pytest.fixture(scope="module")
def compiled_binaries():
    src = os.path.join(FIXTURE_DIR, "hello.c")
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    with open(src, "w") as f:
        f.write(
            "#include <stdio.h>\n"
            "int main() {\n"
            "    char buf[16];\n"
            '    printf("Enter name: ");\n'
            "    fgets(buf, sizeof(buf), stdin);\n"
            '    printf("Hello, %s", buf);\n'
            "    return 0;\n"
            "}\n"
        )
    protected = os.path.join(FIXTURE_DIR, "hello_protected")
    unprotected = os.path.join(FIXTURE_DIR, "hello_noprotect")
    subprocess.run(["gcc", "-o", protected, src, "-fstack-protector-all", "-pie",
                     "-Wl,-z,relro,-z,now"], check=True)
    subprocess.run(["gcc", "-o", unprotected, src, "-fno-stack-protector", "-no-pie",
                     "-Wl,-z,norelro"], check=True)
    return protected, unprotected


def test_checksec_detects_full_protections(compiled_binaries):
    protected, _ = compiled_binaries
    r = rs.elf_checksec(protected)
    assert r["status"] == "ran"
    assert r["arch"] == "x64"
    assert r["pie"] == "PIE enabled"
    assert r["relro"] == "Full RELRO"
    assert r["stack_canary"] == "Canary found"


def test_checksec_detects_missing_protections(compiled_binaries):
    _, unprotected = compiled_binaries
    r = rs.elf_checksec(unprotected)
    assert r["status"] == "ran"
    assert r["pie"] == "No PIE (fixed load address)"
    assert r["relro"] == "No RELRO"
    assert r["stack_canary"] == "No canary found"


def test_checksec_rejects_non_elf():
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"not an ELF file at all")
        path = f.name
    r = rs.elf_checksec(path)
    assert r["status"] == "error"
    os.unlink(path)


def test_run_file_identifies_elf(compiled_binaries):
    protected, _ = compiled_binaries
    r = rs.run_file(protected)
    assert r["status"] == "ran"
    assert "ELF" in r["stdout"]


def test_run_strings_finds_literal_string(compiled_binaries):
    protected, _ = compiled_binaries
    r = rs.run_strings(protected)
    assert r["status"] == "ran"
    assert "Hello, %s" in r["stdout"]


def test_run_objdump_disassembles(compiled_binaries):
    protected, _ = compiled_binaries
    r = rs.run_objdump_disasm(protected)
    assert r["status"] == "ran"
    assert "main" in r["stdout"] or "<main>" in r["stdout"]
