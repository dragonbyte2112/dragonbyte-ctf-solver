"""
The agent loop: receive challenge -> identify file -> classify category ->
run approved tools for that category -> capture real output -> aggregate
evidence -> return every step for display. Hard caps on step count and
wall-clock time prevent runaway loops/cost, per the project's resource-limit
requirement.
"""
import re
import tempfile
import time

import analyzer
from . import crypto_solver as cs
from . import stego_solver as ss
from . import forensics_solver as fs
from . import reverse_solver as rs
from . import web_solver as ws

MAX_STEPS = 20
TIME_BUDGET_SEC = 25


class Budget:
    def __init__(self):
        self.start = time.time()
        self.steps = 0

    def ok(self) -> bool:
        return self.steps < MAX_STEPS and (time.time() - self.start) < TIME_BUDGET_SEC

    def spend(self):
        self.steps += 1


def _step(evidence: list, budget: Budget, category: str, result: dict):
    budget.spend()
    flags = []
    for key in ("stdout", "decrypted", "plaintext_guess", "preview", "extracted_preview"):
        val = result.get(key)
        if isinstance(val, str):
            flags.extend(analyzer.find_flags(val))
    if "flag_candidates" in result:
        flags.extend(result["flag_candidates"])
    evidence.append({
        "step": len(evidence) + 1,
        "category": category,
        "tool": result.get("tool", "unknown"),
        "command": result.get("command", ""),
        "status": result.get("status", "unknown"),
        "output": result,
        "flags_found": list(dict.fromkeys(flags)),
    })


def solve(text: str = "", file_bytes: bytes = None, filename: str = "") -> dict:
    evidence = []
    budget = Budget()
    all_flags = set()

    det = analyzer.run_deterministic_analysis(text=text, file_bytes=file_bytes)
    evidence.append({
        "step": 1, "category": "Automatic Challenge File Analysis", "tool": "deterministic_engine",
        "command": "signature detection + string extraction + auto-decode chain + flag regex",
        "status": "ran",
        "output": {
            "category_guess": det.category_guess, "file_signature": det.file_signature,
            "decode_steps": det.decode_steps, "strings_count": len(det.strings),
            "hex_preview": det.hex_preview,
        },
        "flags_found": det.flag_candidates,
    })
    budget.spend()
    all_flags.update(det.flag_candidates)

    category = det.category_guess
    tmpfile_path = None

    if file_bytes:
        tmp = tempfile.NamedTemporaryFile(suffix="_" + (filename or "upload"), delete=False)
        tmp.write(file_bytes)
        tmp.close()
        tmpfile_path = tmp.name

    try:
        # ---- Steganography branch ----
        if category == "Steganography" and tmpfile_path and budget.ok():
            for fn in (ss.run_exiftool, ss.run_binwalk_scan):
                if not budget.ok():
                    break
                _step(evidence, budget, "Steganography", fn(tmpfile_path))
            if budget.ok():
                _step(evidence, budget, "Steganography", ss.run_zbarimg(tmpfile_path))
            if budget.ok():
                _step(evidence, budget, "Steganography", ss.lsb_extract(tmpfile_path))
            if budget.ok():
                r = ss.run_binwalk_extract(tmpfile_path)
                _step(evidence, budget, "Steganography", r)
            if budget.ok():
                _step(evidence, budget, "Steganography", ss.run_steghide_extract(tmpfile_path))

        # ---- Reverse Engineering branch ----
        elif category == "Reverse Engineering" and tmpfile_path and budget.ok():
            for fn in (rs.run_file, rs.elf_checksec, rs.run_strings):
                if not budget.ok():
                    break
                _step(evidence, budget, "Reverse Engineering", fn(tmpfile_path))
            if budget.ok():
                _step(evidence, budget, "Reverse Engineering", rs.run_objdump_disasm(tmpfile_path))

        # ---- Digital Forensics branch ----
        elif category == "Digital Forensics" and tmpfile_path and budget.ok():
            _step(evidence, budget, "Digital Forensics", fs.run_exiftool(tmpfile_path))
            if budget.ok():
                _step(evidence, budget, "Digital Forensics", fs.analyze_pcap(tmpfile_path))

        # ---- Miscellaneous / archives ----
        elif category == "Miscellaneous" and tmpfile_path and budget.ok():
            _step(evidence, budget, "Miscellaneous", fs.list_archive(tmpfile_path))
            if budget.ok():
                with tempfile.TemporaryDirectory() as outdir:
                    r = fs.extract_archive_safe(tmpfile_path, outdir)
                    extracted_flags = []
                    for item in r.get("extracted", [])[:50]:
                        try:
                            with open(item["path"], "rb") as fh:
                                data = fh.read()
                            strs = analyzer.extract_strings(data)
                            for s in strs:
                                extracted_flags.extend(analyzer.find_flags(s))
                        except Exception:
                            pass
                    r["tool"], r["command"] = "safe_archive_extract", "path-traversal-safe, size-capped extraction"
                    r["flag_candidates"] = list(dict.fromkeys(extracted_flags))
                    _step(evidence, budget, "Miscellaneous", r)

        # ---- Cryptography branch (operates on pasted text, not file) ----
        if text.strip() and budget.ok():
            t = text.strip()
            if t.isalpha() or (sum(c.isalpha() or c.isspace() for c in t) / len(t) > 0.9 and len(t) > 20):
                _step(evidence, budget, "Cryptography", {**cs.caesar_crack(t), "tool": "caesar_crack",
                                                          "command": "brute force 26 shifts, English-frequency scoring"})
                if budget.ok():
                    _step(evidence, budget, "Cryptography", {**cs.vigenere_crack(t), "tool": "vigenere_crack",
                                                              "command": "IC-based key length + per-column chi-squared"})
            hex_candidate = t.replace(" ", "")
            looks_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", hex_candidate)) and len(hex_candidate) % 2 == 0 and len(hex_candidate) >= 4
            if looks_hex:
                try:
                    data = bytes.fromhex(hex_candidate)
                    if budget.ok():
                        _step(evidence, budget, "Cryptography", {**cs.xor_single_byte_crack(data), "tool": "xor_single_byte",
                                                                  "command": "brute force 256 single-byte XOR keys, scored"})
                    if budget.ok():
                        _step(evidence, budget, "Cryptography", {**cs.xor_repeating_key_crack(data), "tool": "xor_repeating_key",
                                                                  "command": "Hamming-distance key-length estimate + per-column crack"})
                except Exception:
                    pass
            hash_id = cs.identify_hash(t)
            if hash_id["possible_types"] != ["Unrecognized format"] and budget.ok():
                _step(evidence, budget, "Cryptography", {**hash_id, "tool": "identify_hash", "command": "regex length/format match"})
                if budget.ok():
                    _step(evidence, budget, "Cryptography", {**cs.crack_hash_common(t), "tool": "crack_hash_common",
                                                              "command": f"hash common {len(cs.COMMON_PASSWORDS)}-word list against md5/sha1/sha256"})

        # ---- Web CTF: static review if text looks like HTML/JS ----
        if text.strip() and ("<html" in text.lower() or "<script" in text.lower() or "function(" in text) and budget.ok():
            _step(evidence, budget, "Web CTF", ws.static_source_review(text))

    finally:
        if tmpfile_path:
            import os
            try:
                os.unlink(tmpfile_path)
            except Exception:
                pass

    for ev in evidence:
        all_flags.update(ev.get("flags_found", []))

    return {
        "category": category,
        "steps_run": len(evidence),
        "steps_limit_hit": not budget.ok() and budget.steps >= MAX_STEPS,
        "time_limit_hit": (time.time() - budget.start) >= TIME_BUDGET_SEC,
        "evidence": evidence,
        "all_flag_candidates": list(all_flags),
    }
