import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import solvers.crypto_solver as cs


def _caesar_encrypt(s, shift):
    out = []
    for c in s:
        if c.isupper():
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
        elif c.islower():
            out.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)


def _vigenere_encrypt(pt, key):
    out, ki = [], 0
    for c in pt:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = ord(key[ki % len(key)].lower()) - 97
            out.append(chr((ord(c) - base + k) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def test_caesar_crack_recovers_shift():
    pt = "this is a secret message hidden inside a caesar cipher for the ctf challenge"
    ct = _caesar_encrypt(pt, 11)
    r = cs.caesar_crack(ct)
    assert r["best"]["shift"] == 11
    assert r["best"]["text"] == pt


def test_caesar_crack_with_flag():
    pt = "flag{this_is_the_real_secret_answer}"
    ct = _caesar_encrypt(pt, 17)
    r = cs.caesar_crack(ct)
    assert r["best"]["shift"] == 17
    assert "flag{this_is_the_real_secret_answer}" in r["best"]["text"]


def test_vigenere_crack_recovers_key():
    pt = ("the quick brown fox jumps over the lazy dog and this pangram contains every letter of "
          "the alphabet at least once which helps frequency analysis work correctly here and we "
          "need quite a bit more text than a single short sentence because classical cryptanalysis "
          "genuinely requires enough ciphertext for the statistics to converge on the right answer")
    key = "dragon"
    ct = _vigenere_encrypt(pt, key)
    r = cs.vigenere_crack(ct, max_key_len=10)
    assert r["estimated_key"] == key
    assert r["decrypted"] == pt


def test_xor_single_byte_crack():
    pt = b"flag{single_byte_xor_cracked}"
    ct = bytes(b ^ 0x42 for b in pt)
    r = cs.xor_single_byte_crack(ct)
    assert r["top5"][0]["key"] == 0x42
    assert r["top5"][0]["text"] == "flag{single_byte_xor_cracked}"


def test_xor_repeating_key_crack_short_key():
    pt = b"flag{xor_repeating_key_works}"
    key = b"key"
    ct = bytes(a ^ key[i % len(key)] for i, a in enumerate(pt))
    r = cs.xor_repeating_key_crack(ct)
    assert r["decrypted"] == pt.decode()


def test_xor_repeating_key_crack_longer_key():
    pt = (b"a much longer piece of plaintext used specifically to validate that the repeating "
          b"key xor cracking routine can correctly recover a slightly longer secret keyword "
          b"from ciphertext alone using only frequency analysis per column of the cipher")
    key = b"secretkey"
    ct = bytes(a ^ key[i % len(key)] for i, a in enumerate(pt))
    r = cs.xor_repeating_key_crack(ct, max_keylen=20)
    assert r["estimated_key"].encode() == key
    assert r["decrypted"] == pt.decode()


def test_rsa_attack_small_primes():
    p, q, e = 10007, 10009, 65537
    n = p * q
    phi = (p - 1) * (q - 1)
    msg = int.from_bytes(b"hi", "big")
    c = pow(msg, e, n)
    r = cs.rsa_attack(n=n, e=e, c=c)
    assert {r["p"], r["q"]} == {p, q}
    assert r["plaintext_guess"] == "hi"


def test_identify_hash_md5():
    import hashlib
    h = hashlib.md5(b"test").hexdigest()
    r = cs.identify_hash(h)
    assert "MD5" in r["possible_types"][0]


def test_crack_hash_common_finds_known_password():
    import hashlib
    h = hashlib.md5(b"flag").hexdigest()
    r = cs.crack_hash_common(h)
    assert r["cracked"] is True
    assert r["password"] == "flag"


def test_crack_hash_common_no_match():
    import hashlib
    h = hashlib.sha256(b"not_in_the_wordlist_xyz123").hexdigest()
    r = cs.crack_hash_common(h)
    assert r["cracked"] is False
