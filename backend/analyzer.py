"""
DragonByte CTF AI - deterministic analysis engine.
No AI calls here. Pure, testable, fast logic: file signature detection,
string extraction, the auto-decode chain, flag detection, and the
command-reference "toolkit" for each of the 9 CTF categories.
"""
import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,15}\{[^}]{1,100}\}")

MORSE_MAP = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9',
}

PRINTABLE_RE = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]*\Z")

# (magic hex prefix, human name, suggested category)
SIGNATURES = [
    ("89504e47", "PNG image", "Steganography"),
    ("ffd8ff", "JPEG image", "Steganography"),
    ("47494638", "GIF image", "Steganography"),
    ("424d", "BMP image", "Steganography"),
    ("25504446", "PDF document", "Miscellaneous"),
    ("504b0304", "ZIP / Office / APK archive", "Miscellaneous"),
    ("7f454c46", "ELF binary", "Reverse Engineering"),
    ("4d5a", "PE binary (EXE/DLL)", "Reverse Engineering"),
    ("1f8b", "GZIP archive", "Miscellaneous"),
    ("d4c3b2a1", "PCAP capture", "Digital Forensics"),
    ("a1b2c3d4", "PCAP capture", "Digital Forensics"),
    ("0a0d0d0a", "PCAPNG capture", "Digital Forensics"),
    ("52494646", "RIFF (WAV/AVI)", "Steganography"),
    ("494433", "MP3 (ID3)", "Steganography"),
    ("d0cf11e0", "Legacy Office document", "Miscellaneous"),
]

CATEGORIES = [
    "Web CTF", "Cryptography", "Digital Forensics", "Steganography",
    "Reverse Engineering", "Binary Exploitation", "OSINT",
    "Miscellaneous", "Automatic Challenge File Analysis",
]

TOOLKIT = {
    "Cryptography": [
        ("Identify encoding layers", 'echo "<ciphertext>" | base64 -d | xxd'),
        ("RSA - factor small n", 'python3 -c "from sympy import factorint; print(factorint(<n>))"'),
        ("RSA - decrypt with p,q known",
         "python3 -c \"\nfrom sympy import mod_inverse\np,q,e,c=<p>,<q>,<e>,<c>\n"
         "phi=(p-1)*(q-1); d=mod_inverse(e,phi)\nm=pow(c,d,p*q); print(bytes.fromhex(hex(m)[2:]))\""),
        ("Vigenere - Kasiski/IC analysis", "python3 vigenere_crack.py ciphertext.txt"),
        ("XOR with known crib",
         "python3 -c \"\nct=bytes.fromhex('<hex>'); crib=b'flag{'\n"
         "for i in range(len(ct)-len(crib)):\n  print(i, bytes(a^b for a,b in zip(ct[i:i+len(crib)],crib)))\""),
        ("Hash identify + crack", "hashid '<hash>'  &&  hashcat -m <mode> hash.txt wordlist.txt"),
        ("JWT decode", "python3 -c \"import base64,json; print(json.loads(base64.urlsafe_b64decode('<payload>'+'==')))\""),
    ],
    "Steganography": [
        ("Check embedded files", "binwalk -e challenge.png"),
        ("Metadata check", "exiftool challenge.jpg"),
        ("Steghide extract", 'steghide extract -sf challenge.jpg -p ""'),
        ("Zsteg LSB check", "zsteg challenge.png"),
        ("Strings for flag", "strings challenge.png | grep -i flag"),
        ("Audio spectrogram", "sox challenge.wav -n spectrogram -o spec.png"),
    ],
    "Digital Forensics": [
        ("HTTP objects from pcap", "tshark -r capture.pcapng --export-objects http,./extracted/"),
        ("Filter suspicious traffic", "tshark -r capture.pcapng -Y 'http.request || dns'"),
        ("Memory process list", "volatility3 -f memdump.raw windows.pslist"),
        ("Memory file scan", "volatility3 -f memdump.raw windows.filescan"),
        ("File carving", "foremost -i disk.img -o carved/"),
        ("Doc metadata", "exiftool file.docx"),
    ],
    "Reverse Engineering": [
        ("Identify file", "file challenge.bin"),
        ("Security mitigations", "checksec --file=challenge.bin"),
        ("Readable strings", "strings -n 6 challenge.bin"),
        ("Disassemble", "objdump -d challenge.bin"),
        ("Unpack if packed", "upx -d challenge.bin"),
        ("Interactive debug", "gdb -q ./challenge.bin"),
    ],
    "Binary Exploitation": [
        ("Check protections", "checksec --file=./challenge"),
        ("Find ROP gadgets", "ROPgadget --binary ./challenge"),
        ("Find libc leak gadget", "one_gadget libc.so.6"),
        ("pwntools exploit skeleton", "python3 -c \"from pwn import *; p=process('./challenge'); p.interactive()\""),
    ],
    "Web CTF": [
        ("Headers / fingerprint", "curl -I http://TARGET"),
        ("Tech stack detect", "whatweb http://TARGET"),
        ("Port/service scan", "nmap -sV -p- TARGET"),
        ("robots.txt / common paths", "curl http://TARGET/robots.txt"),
        ("Directory brute force", "gobuster dir -u http://TARGET -w wordlist.txt"),
        ("SQLi test - authorized scope only", "sqlmap -u 'http://TARGET/page?id=1' --batch"),
    ],
    "OSINT": [
        ("Image GPS metadata", "exiftool photo.jpg"),
        ("Domain registration", "whois domain.com"),
        ("DNS records", "dig domain.com ANY"),
        ("Email/username recon - authorized", "theHarvester -d domain.com -b all"),
    ],
    "Miscellaneous": [
        ("QR code decode", "zbarimg qrcode.png"),
        ("Archive listing", "7z l archive.7z"),
        ("Recursive unpack", "binwalk -Me archive.zip"),
        ("File signature check", "file mystery.dat"),
    ],
}


def detect_signature(data: bytes) -> Optional[dict]:
    head = binascii.hexlify(data[:8]).decode()
    for magic, name, cat in SIGNATURES:
        if head.startswith(magic):
            return {"name": name, "category": cat, "magic": magic}
    return None


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def _is_printable(s: str) -> bool:
    try:
        return bool(PRINTABLE_RE.match(s.encode("latin-1", errors="ignore")))
    except Exception:
        return False


def try_base64(s: str) -> Optional[str]:
    t = s.strip()
    if not t or len(t) % 4 not in (0, 2, 3):
        pass
    try:
        decoded = base64.b64decode(t + "=" * (-len(t) % 4), validate=False).decode("latin-1")
        return decoded if _is_printable(decoded) else None
    except Exception:
        return None


def try_hex(s: str) -> Optional[str]:
    t = re.sub(r"\s", "", s.strip())
    if not re.fullmatch(r"[0-9a-fA-F]+", t or "") or len(t) % 2 or len(t) < 4:
        return None
    try:
        decoded = bytes.fromhex(t).decode("latin-1")
        return decoded if _is_printable(decoded) else None
    except Exception:
        return None


def try_binary(s: str) -> Optional[str]:
    t = re.sub(r"\s", "", s.strip())
    if not re.fullmatch(r"[01]+", t or "") or len(t) % 8 or len(t) < 8:
        return None
    try:
        return "".join(chr(int(t[i:i + 8], 2)) for i in range(0, len(t), 8))
    except Exception:
        return None


def try_rot13(s: str) -> str:
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def try_url(s: str) -> Optional[str]:
    decoded = urllib.parse.unquote(s)
    return decoded if decoded != s else None


def try_morse(s: str) -> Optional[str]:
    t = s.strip()
    if not re.fullmatch(r"[.\-\s/]+", t or ""):
        return None
    words = re.split(r"\s{2,}|/", t)
    out = []
    for w in words:
        out.append("".join(MORSE_MAP.get(c, "") for c in w.strip().split()))
    result = " ".join(out)
    return result if re.search(r"[A-Z0-9]", result) else None


def find_flags(s: str) -> list[str]:
    return list(dict.fromkeys(FLAG_RE.findall(s)))


def decode_chain(text: str, max_depth: int = 4) -> list[dict]:
    steps = []
    frontier = [text]
    seen = {text}
    for depth in range(max_depth):
        nxt = []
        for s in frontier:
            tries = {
                "Base64": try_base64(s), "Hex": try_hex(s), "Binary": try_binary(s),
                "ROT13": try_rot13(s), "URL": try_url(s), "Morse": try_morse(s),
            }
            for name, res in tries.items():
                if res and res != s and res not in seen:
                    seen.add(res)
                    steps.append({"depth": depth, "technique": name, "output": res})
                    nxt.append(res)
        frontier = nxt
        if not frontier:
            break
    return steps


def detect_category(text: str) -> str:
    t = text.strip()
    if re.match(r"^-----BEGIN", t) or re.search(r"\b[pqne]\s*=\s*\d+", t):
        return "RSA / Public-key Crypto"
    stripped = re.sub(r"\s", "", t)
    if re.fullmatch(r"[01]+", stripped or "") and len(stripped) % 8 == 0 and len(stripped) > 8:
        return "Binary-encoded text"
    if re.fullmatch(r"[0-9a-fA-F]+", stripped or "") and len(stripped) > 8:
        return "Hex-encoded data"
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", t or "") and t.rstrip().endswith("="):
        return "Base64-encoded data"
    if re.fullmatch(r"[.\-\s/]+", t or "") and len(t) > 4:
        return "Morse code"
    if re.fullmatch(r"[A-Za-z\s]+", t or "") and len(t) > 20:
        return "Classical cipher (Caesar / Vigenere / Substitution)"
    return "Unclassified"


@dataclass
class AnalysisResult:
    category_guess: str
    file_signature: Optional[dict] = None
    decode_steps: list[dict] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    flag_candidates: list[str] = field(default_factory=list)
    hex_preview: str = ""


def run_deterministic_analysis(text: str = "", file_bytes: Optional[bytes] = None) -> AnalysisResult:
    result = AnalysisResult(category_guess="Unclassified")

    if file_bytes:
        sig = detect_signature(file_bytes)
        result.file_signature = sig
        result.category_guess = sig["category"] if sig else "Automatic Challenge File Analysis"
        result.strings = extract_strings(file_bytes)
        result.hex_preview = binascii.hexlify(file_bytes[:64]).decode()
        for s in result.strings:
            result.flag_candidates.extend(find_flags(s))

    if text.strip():
        if result.category_guess in ("Unclassified", ""):
            result.category_guess = detect_category(text)
        result.decode_steps = decode_chain(text)
        result.flag_candidates.extend(find_flags(text))
        for step in result.decode_steps:
            result.flag_candidates.extend(find_flags(step["output"]))

    result.flag_candidates = list(dict.fromkeys(result.flag_candidates))
    return result
