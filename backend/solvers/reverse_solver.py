"""
Real reverse-engineering and binary-exploitation static analysis.
Runs the actual `file`, `strings`, and `objdump` binaries, and implements
checksec-equivalent ELF security-mitigation detection ourselves with
pyelftools (no dependency on the external checksec script).
"""
import os
from . import tool_registry as tr


def run_file(path: str) -> dict:
    r = tr.run_tool("file", [path], timeout=10)
    return {"tool": "file", "command": f"file {os.path.basename(path)}", **r}


def run_strings(path: str, min_len: int = 6) -> dict:
    r = tr.run_tool("strings", ["-n", str(min_len), path], timeout=15)
    return {"tool": "strings", "command": f"strings -n {min_len} {os.path.basename(path)}", **r}


def run_objdump_disasm(path: str, max_lines: int = 150) -> dict:
    r = tr.run_tool("objdump", ["-d", path], timeout=20)
    if r["status"] == "ran":
        lines = r["stdout"].splitlines()
        r = {**r, "stdout": "\n".join(lines[:max_lines]),
             "truncated": len(lines) > max_lines, "total_lines": len(lines)}
    return {"tool": "objdump", "command": f"objdump -d {os.path.basename(path)}", **r}


def elf_checksec(path: str) -> dict:
    """Our own checksec implementation: real static analysis of the ELF headers."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"tool": "elf_checksec", "status": "not_installed", "stderr": "pyelftools not installed."}

    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            if elf.get_machine_arch() is None:
                return {"tool": "elf_checksec", "status": "error", "stderr": "Not a valid ELF file."}

            e_type = elf.header["e_type"]
            pie = (e_type == "ET_DYN")

            nx = False
            relro = "No RELRO"
            has_interp = False
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_GNU_STACK":
                    nx = not bool(seg["p_flags"] & 0x1)  # PF_X not set -> NX enabled
                if seg["p_type"] == "PT_GNU_RELRO":
                    relro = "Partial RELRO"
                if seg["p_type"] == "PT_INTERP":
                    has_interp = True

            bind_now = False
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
                    elif tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):  # DF_BIND_NOW
                        bind_now = True
                    elif tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):  # DF_1_NOW
                        bind_now = True
            if relro == "Partial RELRO" and bind_now:
                relro = "Full RELRO"

            has_canary = False
            symtab = elf.get_section_by_name(".symtab") or elf.get_section_by_name(".dynsym")
            stripped = elf.get_section_by_name(".symtab") is None
            if symtab is not None:
                for sym in symtab.iter_symbols():
                    if "__stack_chk_fail" in sym.name:
                        has_canary = True
                        break

            pie_label = "PIE enabled" if (pie and has_interp) else (
                "PIE (or shared library)" if pie else "No PIE (fixed load address)")

            return {
                "tool": "elf_checksec", "status": "ran",
                "command": f"Python/pyelftools: inspect ELF headers, segments, and symbols of {os.path.basename(path)}",
                "arch": elf.get_machine_arch(),
                "nx_stack": "NX enabled" if nx else "NX disabled (stack executable)",
                "pie": pie_label,
                "relro": relro,
                "stack_canary": "Canary found" if has_canary else "No canary found",
                "stripped": stripped,
            }
    except Exception as e:
        return {"tool": "elf_checksec", "status": "error", "stderr": str(e)}
