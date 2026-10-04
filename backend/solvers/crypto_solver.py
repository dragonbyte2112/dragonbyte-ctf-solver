"""
Real cryptography attacks. Everything here actually computes a result -
no canned answers. Where an attack genuinely cannot succeed (e.g. RSA
modulus too large to factor), it says so rather than guessing.
"""
import hashlib
import re
import string
from itertools import cycle

import analyzer

FLAG_RE = analyzer.FLAG_RE

ENGLISH_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07,
}
COMMON_WORDS = {"the", "and", "flag", "is", "of", "to", "a", "in", "ctf", "you", "this"}

# Rank-based scoring (classic CTF single-byte/repeating-key XOR fitness function).
# Space is the single most common character in real English text and must be
# included, or short-sample scoring (e.g. one column of a Vigenere/XOR split)
# gets dominated by noise. Non-printable bytes are penalized hard since a
# correct key recovers readable text, not control characters.
_FREQ_RANK = " etaoinshrdlucmfwypvbgkjqxz"


def _column_score(text: str) -> float:
    """Pure character-frequency ranking, no word/flag bonuses. Used for
    single-byte key recovery on a COLUMN of ciphertext (every Nth byte of a
    repeating-key cipher), which is a sparse, non-contiguous subsequence -
    it will never itself look like a sentence or contain a flag pattern,
    even when the key byte is exactly correct. Scoring it with full-text
    heuristics (common words, flag-format bonus) causes false positives,
    since a short, fragmented sample can coincidentally contain a brace
    character and trigger a flag-shaped match purely by chance."""
    if not text:
        return -999.0
    score = 0.0
    for ch in text.lower():
        idx = _FREQ_RANK.find(ch)
        if idx >= 0:
            score += (len(_FREQ_RANK) - idx)
        elif ch.isprintable():
            score += 0.2
        else:
            score -= 15
    return score / len(text)


def english_score(text: str) -> float:
    if not text:
        return -999.0
    score = 0.0
    for ch in text.lower():
        idx = _FREQ_RANK.find(ch)
        if idx >= 0:
            score += (len(_FREQ_RANK) - idx)
        elif ch.isdigit() or ch in ".,!?'\"-_{}":
            score += 2  # neutral/plausible in flag-style text, small reward
        elif ch.isprintable():
            score += 0.2
        else:
            score -= 15  # control/non-printable bytes are a strong negative signal
    base = score / len(text)

    # Flat (non-averaged) bonuses: these are strong, specific signals that
    # should dominate over per-character noise on short samples. The whole
    # point of this scorer is finding CTF flags, so a literal flag-format
    # match is the single best evidence a candidate is correct.
    words = re.findall(r"[a-z]+", text.lower())
    word_bonus = sum(15 for w in words if w in COMMON_WORDS)

    # Flag-format bonus: only fires when the match covers most of the text,
    # i.e. the candidate basically IS the flag (the common case for short
    # Caesar/single-byte-XOR flag strings). On longer multi-sentence text,
    # a flag-shaped substring can appear by pure chance in otherwise wrong
    # decodings; requiring majority coverage avoids rewarding that coincidence
    # while still catching the case this bonus exists for.
    flag_bonus = 0
    m = FLAG_RE.search(text)
    if m and len(m.group(0)) / len(text) >= 0.5:
        flag_bonus = 300
    return base + word_bonus + flag_bonus


def caesar_crack(text: str) -> dict:
    candidates = []
    for shift in range(26):
        shifted = "".join(
            chr((ord(c) - 65 - shift) % 26 + 65) if c.isupper() else
            chr((ord(c) - 97 - shift) % 26 + 97) if c.islower() else c
            for c in text
        )
        candidates.append({"shift": shift, "text": shifted, "score": english_score(shifted)})
    candidates.sort(key=lambda c: -c["score"])
    return {"method": "Caesar brute force (all 26 shifts, scored by English letter frequency)",
            "best": candidates[0], "top3": candidates[:3]}


def _vigenere_decrypt(text: str, key: str) -> str:
    out = []
    ki = 0
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = ord(key[ki % len(key)].lower()) - 97
            out.append(chr((ord(c) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def _index_of_coincidence(s: str) -> float:
    s = [c for c in s.lower() if c.isalpha()]
    n = len(s)
    if n < 2:
        return 0.0
    freqs = {c: s.count(c) for c in set(s)}
    return sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1))


def vigenere_crack(text: str, max_key_len: int = 12) -> dict:
    letters_only = "".join(c for c in text if c.isalpha())
    if len(letters_only) < 20:
        return {"method": "Vigenere (Kasiski/IC)", "error": "Text too short for reliable key-length estimation."}

    # Estimate key length by average IC across splits
    best_len, best_ic_diff = 1, 999.0
    for klen in range(1, max_key_len + 1):
        cols = ["".join(letters_only[i] for i in range(j, len(letters_only), klen)) for j in range(klen)]
        avg_ic = sum(_index_of_coincidence(c) for c in cols) / klen
        diff = abs(avg_ic - 0.068)  # English IC ~0.067
        if diff < best_ic_diff:
            best_ic_diff, best_len = diff, klen

    # Derive key: for each column, try all 26 shifts and pick best chi-squared fit
    cols = ["".join(letters_only[i] for i in range(j, len(letters_only), best_len)) for j in range(best_len)]
    key_chars = []
    for col in cols:
        best_shift, best_score = 0, -1e9
        for shift in range(26):
            shifted = "".join(chr((ord(c) - 65 - shift) % 26 + 65) if c.isupper()
                               else chr((ord(c) - 97 - shift) % 26 + 97) for c in col)
            sc = english_score(shifted)
            if sc > best_score:
                best_score, best_shift = sc, shift
        key_chars.append(chr(best_shift + 97))
    key = "".join(key_chars)
    decrypted = _vigenere_decrypt(text, key)
    return {"method": f"Vigenere - IC-estimated key length {best_len}, per-column chi-squared fit",
            "estimated_key": key, "decrypted": decrypted, "score": english_score(decrypted)}


def xor_single_byte_crack(data: bytes) -> dict:
    results = []
    for key in range(256):
        out = bytes(b ^ key for b in data)
        try:
            text = out.decode("latin-1")
        except Exception:
            continue
        results.append({"key": key, "key_char": chr(key) if 32 <= key < 127 else f"0x{key:02x}",
                         "text": text, "score": english_score(text)})
    results.sort(key=lambda r: -r["score"])
    return {"method": "Single-byte XOR brute force (all 256 keys, scored)", "top5": results[:5]}


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _recover_key_for_length(data: bytes, klen: int) -> bytes:
    key = bytearray()
    for i in range(klen):
        column = data[i::klen]
        best = max(range(256), key=lambda k: _column_score(bytes(b ^ k for b in column).decode("latin-1", "replace")))
        key.append(best)
    return bytes(key)


FLAG_CRIBS = [b"flag{", b"FLAG{", b"ctf{", b"CTF{", b"dragonbyte{", b"flag_", b"key{"]


def _xor_crib_drag(data: bytes, max_key_len_from_crib: int = 16):
    """Known-plaintext attack: assume the ciphertext starts with a common
    flag prefix, XOR it against the start of the data to recover candidate
    key bytes directly, then test every divisor key length against the
    full ciphertext for a genuine flag-format match. This is the standard
    technique real CTF players use for exactly this challenge type and is
    far more reliable than blind frequency analysis on short ciphertext."""
    for crib in FLAG_CRIBS:
        if len(crib) > len(data):
            continue
        derived = bytes(c ^ d for c, d in zip(crib, data[:len(crib)]))
        for klen in range(1, min(len(crib), max_key_len_from_crib) + 1):
            key_guess = derived[:klen]
            decrypted = bytes(a ^ key_guess[i % klen] for i, a in enumerate(data)).decode("latin-1", "replace")
            match = FLAG_RE.search(decrypted)
            # Require both a flag-format match AND that the surrounding text is
            # plausible (not just noise that coincidentally contains braces) -
            # otherwise a wrong single-byte guess can "accidentally" produce
            # something brace-shaped purely by chance, especially on short klen.
            if match and _column_score(decrypted) >= 12:
                return {"key": key_guess, "decrypted": decrypted, "crib_used": crib.decode()}
    return None


def xor_repeating_key_crack(data: bytes, max_keylen: int = 30) -> dict:
    """
    Two-stage attack. Stage 1: crib-drag against common flag prefixes - if
    the ciphertext genuinely hides a flag starting with one of these, this
    recovers the exact key with certainty. Stage 2 (fallback): brute-force
    every key length from 1 to max_keylen, fully recover each via per-column
    single-byte frequency analysis, and keep whichever produces the
    best-scoring plaintext. Stage 2 alone is known to be unreliable on
    short ciphertext (too few samples per column for frequency stats to
    converge) - that is a real, well-known limitation of this classical
    technique, which is exactly why Stage 1 exists.
    """
    if len(data) < 4:
        return {"method": "Repeating-key XOR", "error": "Input too short."}

    crib_hit = _xor_crib_drag(data)
    if crib_hit:
        return {"method": f"Repeating-key XOR - crib-drag using prefix '{crib_hit['crib_used']}' "
                           f"(known-plaintext attack, confirmed by a real flag-format match)",
                "estimated_key": crib_hit["key"].decode("latin-1", "replace"),
                "estimated_key_hex": crib_hit["key"].hex(), "decrypted": crib_hit["decrypted"],
                "confidence": "high - verified flag-format match"}

    max_keylen = min(max_keylen, len(data) // 2 or 1)
    candidates = []
    for klen in range(1, max_keylen + 1):
        key = _recover_key_for_length(data, klen)
        decrypted = bytes(a ^ b for a, b in zip(data, cycle(key))).decode("latin-1", "replace")
        candidates.append({"klen": klen, "key": key, "decrypted": decrypted, "score": english_score(decrypted)})
    # A multiple of the true key length can score a near-identical (even
    # fractionally higher, via meaningless case-sensitivity ties) decode,
    # since case differences don't affect this scorer. Prefer the smallest
    # key length among near-ties rather than trusting a razor-thin margin.
    best_score = max(c["score"] for c in candidates)
    near_ties = [c for c in candidates if best_score - c["score"] <= 1.0]
    best_result = min(near_ties, key=lambda c: c["klen"])

    return {"method": f"Repeating-key XOR - no known flag prefix matched; falling back to brute-forced "
                       f"key lengths 1-{max_keylen}, each fully decoded and scored (best: length {best_result['klen']})",
            "estimated_key": best_result["key"].decode("latin-1", "replace"),
            "estimated_key_hex": best_result["key"].hex(), "decrypted": best_result["decrypted"],
            "confidence": "low - statistical guess only, not verified"}


def rsa_attack(n: int = None, e: int = None, c: int = None) -> dict:
    if n is None:
        return {"method": "RSA", "error": "n is required."}
    from sympy import factorint, integer_nthroot
    from sympy.ntheory.modular import crt  # noqa
    MAX_BITS = 128  # keep factoring bounded so it can't hang the server
    if n.bit_length() > MAX_BITS:
        # Still try Fermat's method for close primes (fast even for large n) and small-e root attack.
        notes = [f"n is {n.bit_length()} bits - full factorization skipped (would not finish in reasonable time)."]
        if e is not None and c is not None and e <= 5:
            root, exact = integer_nthroot(c, e)
            if exact:
                m = root
                return {"method": f"RSA small-e ({e}) integer-root attack", "plaintext_int": m,
                         "plaintext_bytes_hex": hex(m)[2:], "notes": notes}
        a, b = _fermat_factor(n, max_iters=200000)
        if a and b:
            return _rsa_finish(a, b, e, c, "Fermat's method (p, q very close)", notes)
        return {"method": "RSA", "error": "Modulus too large for in-process factoring; "
                                            "try factordb.com or a dedicated factoring tool.", "notes": notes}

    factors = factorint(n)
    prime_factors = [p for p in factors for _ in range(factors[p])]
    if len(prime_factors) != 2:
        return {"method": "RSA factorization", "factors": dict((str(k), v) for k, v in factors.items()),
                "error": "n did not factor into exactly two primes with this method."}
    p, q = prime_factors
    return _rsa_finish(p, q, e, c, "sympy.factorint (complete factorization, n small enough to factor directly)", [])


def _fermat_factor(n: int, max_iters: int = 100000):
    import math
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iters):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None, None


def _rsa_finish(p: int, q: int, e, c, method_note: str, notes: list) -> dict:
    result = {"method": f"RSA - {method_note}", "p": p, "q": q, "notes": notes}
    if e is not None and c is not None:
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
            m = pow(c, d, p * q)
            try:
                plaintext = bytes.fromhex(hex(m)[2:].rstrip("L")).decode("latin-1", "replace")
            except Exception:
                plaintext = str(m)
            result.update({"d": d, "plaintext_int": m, "plaintext_guess": plaintext})
        except Exception as ex:
            result["decrypt_error"] = str(ex)
    return result


HASH_PATTERNS = [
    (r"^[a-f0-9]{32}$", "MD5 or NTLM (32 hex chars)"),
    (r"^[a-f0-9]{40}$", "SHA-1 (40 hex chars)"),
    (r"^[a-f0-9]{64}$", "SHA-256 (64 hex chars)"),
    (r"^[a-f0-9]{96}$", "SHA-384 (96 hex chars)"),
    (r"^[a-f0-9]{128}$", "SHA-512 (128 hex chars)"),
    (r"^\$2[aby]\$", "bcrypt"),
    (r"^\$1\$", "MD5 crypt"),
    (r"^\$6\$", "SHA-512 crypt"),
]

COMMON_PASSWORDS = ["password", "123456", "flag", "admin", "letmein", "qwerty",
                    "ctf", "dragonbyte", "password123", "welcome", "root", "toor"]


def identify_hash(h: str) -> dict:
    h = h.strip()
    matches = [name for pat, name in HASH_PATTERNS if re.match(pat, h, re.IGNORECASE)]
    return {"input": h, "length": len(h), "possible_types": matches or ["Unrecognized format"]}


def crack_hash_common(h: str) -> dict:
    """Try a small built-in common-password list against md5/sha1/sha256. Real computation, no external wordlist."""
    h = h.strip().lower()
    algos = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
    for algo_name, algo in algos.items():
        for pw in COMMON_PASSWORDS:
            if algo(pw.encode()).hexdigest() == h:
                return {"cracked": True, "algorithm": algo_name, "password": pw}
    return {"cracked": False, "note": f"No match in built-in {len(COMMON_PASSWORDS)}-word list "
                                       "against md5/sha1/sha256. Use hashcat with a real wordlist for more coverage."}
