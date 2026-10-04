"""
Real steganography analysis: actually invokes exiftool, binwalk, steghide,
and zbarimg as subprocesses, plus a pure-Python LSB extractor using PIL.
Every result here reflects a real tool's real exit code and output.
"""
import os
import tempfile
from . import tool_registry as tr

COMMON_STEGHIDE_PASSWORDS = ["", "password", "123456", "flag", "ctf", "dragonbyte", "admin", "steghide"]


def run_exiftool(path: str) -> dict:
    r = tr.run_tool("exiftool", [path], timeout=10)
    return {"tool": "exiftool", "command": f"exiftool {os.path.basename(path)}", **r}


def run_binwalk_scan(path: str) -> dict:
    r = tr.run_tool("binwalk", [path], timeout=20)
    return {"tool": "binwalk", "command": f"binwalk {os.path.basename(path)}", **r}


def run_binwalk_extract(path: str, max_total_size: int = 20 * 1024 * 1024) -> dict:
    with tempfile.TemporaryDirectory() as outdir:
        r = tr.run_tool("binwalk", ["-e", "-C", outdir, path], timeout=30)
        extracted = []
        total = 0
        if r["status"] == "ran":
            for root, _, files in os.walk(outdir):
                for f in files:
                    fp = os.path.join(root, f)
                    size = os.path.getsize(fp)
                    total += size
                    if total > max_total_size:
                        return {"tool": "binwalk", "command": f"binwalk -e {os.path.basename(path)}",
                                "status": "aborted", "stdout": r["stdout"],
                                "stderr": "Extraction aborted: exceeded size safety limit (possible decompression bomb).",
                                "extracted_files": extracted}
                    with open(fp, "rb") as fh:
                        content = fh.read()
                    extracted.append({"name": f, "size": size,
                                       "preview": content[:200].decode("latin-1", "replace")})
        return {"tool": "binwalk", "command": f"binwalk -e {os.path.basename(path)}",
                **r, "extracted_files": extracted}


def run_steghide_extract(path: str) -> dict:
    attempts = []
    for pw in COMMON_STEGHIDE_PASSWORDS:
        with tempfile.TemporaryDirectory() as outdir:
            outfile = os.path.join(outdir, "extracted.bin")
            r = tr.run_tool("steghide", ["extract", "-sf", path, "-p", pw, "-xf", outfile, "-f"], timeout=10)
            success = r["status"] == "ran" and r["returncode"] == 0 and os.path.exists(outfile)
            content_preview = None
            if success:
                with open(outfile, "rb") as fh:
                    content_preview = fh.read()[:500].decode("latin-1", "replace")
            attempts.append({"password_tried": pw or "(empty)", "success": success,
                              "stderr": r["stderr"][:300]})
            if success:
                return {"tool": "steghide", "command": f"steghide extract -sf {os.path.basename(path)} -p ...",
                        "status": "ran", "success": True, "password": pw or "(empty)",
                        "extracted_preview": content_preview, "attempts": attempts}
    return {"tool": "steghide", "command": f"steghide extract -sf {os.path.basename(path)} -p ...",
            "status": "ran", "success": False,
            "note": f"Tried {len(COMMON_STEGHIDE_PASSWORDS)} common passwords, none worked. "
                    "Not every image has steghide data - a failure here is expected for most files.",
            "attempts": attempts}


def run_zbarimg(path: str) -> dict:
    r = tr.run_tool("zbarimg", [path], timeout=10)
    return {"tool": "zbarimg", "command": f"zbarimg {os.path.basename(path)}", **r}


def lsb_extract(path: str, max_bytes: int = 2000) -> dict:
    """Pure-Python LSB steganography extraction via PIL - real pixel-level computation."""
    try:
        from PIL import Image
    except ImportError:
        return {"tool": "lsb_extract", "status": "not_installed", "stderr": "Pillow not installed."}
    try:
        img = Image.open(path)
        img = img.convert("RGB")
    except Exception as e:
        return {"tool": "lsb_extract", "status": "error", "stderr": f"Could not open as image: {e}"}

    pixels = list(img.getdata())
    bits = []
    for pix in pixels:
        for channel in pix[:3]:
            bits.append(channel & 1)
            if len(bits) >= max_bytes * 8:
                break
        if len(bits) >= max_bytes * 8:
            break

    byte_vals = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        byte_vals.append(byte)

    raw = bytes(byte_vals)
    printable = raw.decode("latin-1", "replace")
    printable_ratio = sum(1 for c in printable if c.isprintable()) / max(len(printable), 1)

    return {"tool": "lsb_extract", "status": "ran",
            "command": f"Python/PIL: extract least-significant bit of each R,G,B channel, pixel order, from {os.path.basename(path)}",
            "bytes_examined": len(raw), "printable_ratio": round(printable_ratio, 2),
            "preview": printable[:300],
            "note": "High printable_ratio suggests real hidden text; low ratio suggests no LSB data at bit-depth 1 "
                    "in this channel order, try other tools (zsteg covers more bit-plane/channel combinations)."}
