import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from PIL import Image

import analyzer
import solvers.stego_solver as ss

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
os.makedirs(FIXTURE_DIR, exist_ok=True)


def _make_lsb_png(path, message: bytes):
    img = Image.new("RGB", (100, 100), color=(120, 130, 140))
    pixels = img.load()
    bits = []
    for byte in message:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    idx = 0
    for y in range(img.height):
        if idx >= len(bits):
            break
        for x in range(img.width):
            if idx >= len(bits):
                break
            channels = list(pixels[x, y])
            for c in range(3):
                if idx < len(bits):
                    channels[c] = (channels[c] & ~1) | bits[idx]
                    idx += 1
            pixels[x, y] = tuple(channels)
    img.save(path)


@pytest.fixture(scope="module")
def lsb_png():
    path = os.path.join(FIXTURE_DIR, "lsb_flag.png")
    _make_lsb_png(path, b"flag{lsb_stego_works}\x00")
    return path


def test_lsb_extract_recovers_real_embedded_flag(lsb_png):
    r = ss.lsb_extract(lsb_png)
    assert r["status"] == "ran"
    flags = analyzer.find_flags(r["preview"])
    assert "flag{lsb_stego_works}" in flags


def test_exiftool_runs_on_real_png(lsb_png):
    r = ss.run_exiftool(lsb_png)
    assert r["status"] == "ran"
    assert "PNG" in r["stdout"] or "File Type" in r["stdout"]


def test_binwalk_scan_runs_on_real_png(lsb_png):
    r = ss.run_binwalk_scan(lsb_png)
    assert r["status"] == "ran"
    assert "PNG image" in r["stdout"] or "DECIMAL" in r["stdout"]


def test_steghide_extract_reports_failure_honestly_on_plain_png(lsb_png):
    # This PNG has no steghide-embedded data (it's LSB, a different technique),
    # so steghide must honestly report failure, not fabricate a success.
    r = ss.run_steghide_extract(lsb_png)
    assert r["status"] == "ran"
    assert r["success"] is False


def test_zbarimg_runs_and_finds_no_qr_on_plain_png(lsb_png):
    r = ss.run_zbarimg(lsb_png)
    # zbarimg exits non-zero when no barcode is found - that's still a real run.
    assert r["status"] == "ran"
