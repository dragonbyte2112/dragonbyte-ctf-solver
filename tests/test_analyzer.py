import sys, os, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import analyzer


def test_detect_signature_png():
    png_bytes = bytes.fromhex("89504e470d0a1a0a") + b"\x00" * 20
    sig = analyzer.detect_signature(png_bytes)
    assert sig is not None
    assert sig["name"] == "PNG image"
    assert sig["category"] == "Steganography"


def test_detect_signature_elf():
    elf_bytes = bytes.fromhex("7f454c46") + b"\x00" * 20
    sig = analyzer.detect_signature(elf_bytes)
    assert sig["category"] == "Reverse Engineering"


def test_detect_signature_unknown():
    assert analyzer.detect_signature(b"\x01\x02\x03\x04\x05\x06\x07\x08") is None


def test_extract_strings():
    data = b"\x00\x00hello\x00\x00world!!\x00\x01"
    strings = analyzer.extract_strings(data, min_len=4)
    assert "hello" in strings
    assert "world!!" in strings


def test_try_base64_roundtrip():
    original = "flag{test_flag}"
    encoded = base64.b64encode(original.encode()).decode()
    assert analyzer.try_base64(encoded) == original


def test_try_hex_roundtrip():
    original = "flag{hex_test}"
    encoded = original.encode().hex()
    assert analyzer.try_hex(encoded) == original


def test_try_rot13():
    assert analyzer.try_rot13("synt{ebg13}") == "flag{rot13}"


def test_decode_chain_finds_flag_through_base64():
    encoded = base64.b64encode(b"flag{nested_base64}").decode()
    steps = analyzer.decode_chain(encoded)
    outputs = [s["output"] for s in steps]
    assert "flag{nested_base64}" in outputs


def test_decode_chain_double_base64():
    inner = base64.b64encode(b"flag{double_wrap}").decode()
    outer = base64.b64encode(inner.encode()).decode()
    steps = analyzer.decode_chain(outer)
    outputs = [s["output"] for s in steps]
    assert "flag{double_wrap}" in outputs


def test_find_flags():
    text = "here is flag{abc123} and also CTF{another_one}"
    flags = analyzer.find_flags(text)
    assert "flag{abc123}" in flags
    assert "CTF{another_one}" in flags


def test_find_flags_none():
    assert analyzer.find_flags("no flags here") == []


def test_detect_category_base64():
    cat = analyzer.detect_category(base64.b64encode(b"hello world test").decode())
    assert cat == "Base64-encoded data"


def test_detect_category_hex():
    assert analyzer.detect_category("48656c6c6f576f726c6421") == "Hex-encoded data"


def test_detect_category_morse():
    assert analyzer.detect_category(".... . .-.. .-.. ---") == "Morse code"


def test_run_deterministic_analysis_text_only():
    encoded = base64.b64encode(b"flag{full_pipeline}").decode()
    result = analyzer.run_deterministic_analysis(text=encoded)
    assert "flag{full_pipeline}" in result.flag_candidates


def test_run_deterministic_analysis_file_only():
    file_bytes = bytes.fromhex("89504e470d0a1a0a") + b"junk\x00" + b"flag{in_file}" + b"\x00" * 5
    result = analyzer.run_deterministic_analysis(file_bytes=file_bytes)
    assert result.file_signature["name"] == "PNG image"
    assert "flag{in_file}" in result.flag_candidates


def test_run_deterministic_analysis_empty():
    result = analyzer.run_deterministic_analysis(text="", file_bytes=None)
    assert result.flag_candidates == []
    assert result.category_guess == "Unclassified"


def test_toolkit_has_all_categories():
    for cat in ["Cryptography", "Steganography", "Digital Forensics",
                "Reverse Engineering", "Binary Exploitation", "Web CTF",
                "OSINT", "Miscellaneous"]:
        assert cat in analyzer.TOOLKIT
        assert len(analyzer.TOOLKIT[cat]) > 0
