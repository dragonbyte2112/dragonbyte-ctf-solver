import os
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import solvers.forensics_solver as fs

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
os.makedirs(FIXTURE_DIR, exist_ok=True)


@pytest.fixture(scope="module")
def pcap_file():
    from scapy.all import wrpcap, Ether, IP, UDP, TCP, DNS, DNSQR, Raw
    path = os.path.join(FIXTURE_DIR, "test.pcap")
    dns_pkt = Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="flagserver.example.com"))
    http_payload = b"GET /secret?token=flag{pcap_analysis_works} HTTP/1.1\r\nHost: example.com\r\n\r\n"
    http_pkt = Ether() / IP(dst="10.0.0.1") / TCP(dport=80) / Raw(load=http_payload)
    wrpcap(path, [dns_pkt, http_pkt])
    return path


def test_analyze_pcap_finds_real_dns_query(pcap_file):
    r = fs.analyze_pcap(pcap_file)
    assert r["status"] == "ran"
    assert r["packet_count"] == 2
    assert any("flagserver.example.com" in q for q in r["dns_queries"])


def test_analyze_pcap_finds_real_http_request(pcap_file):
    r = fs.analyze_pcap(pcap_file)
    assert r["http_requests_found"] == 1
    assert "GET /secret" in r["http_sample"][0]


def test_analyze_pcap_extracts_flag_from_real_payload(pcap_file):
    r = fs.analyze_pcap(pcap_file)
    assert "flag{pcap_analysis_works}" in r["flag_candidates"]


def test_analyze_pcap_rejects_non_pcap():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"this is not a real pcap file")
        path = f.name
    r = fs.analyze_pcap(path)
    assert r["status"] == "error"
    os.unlink(path)


def test_extract_archive_safe_normal_zip():
    path = os.path.join(FIXTURE_DIR, "normal.zip")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("notes.txt", "just some notes")
        zf.writestr("secret.txt", "flag{zip_extraction_works}")
    with tempfile.TemporaryDirectory() as outdir:
        r = fs.extract_archive_safe(path, outdir)
        assert r["status"] == "ran"
        names = {e["name"] for e in r["extracted"]}
        assert names == {"notes.txt", "secret.txt"}
        assert r["rejected"] == []


def test_extract_archive_safe_rejects_path_traversal():
    path = os.path.join(FIXTURE_DIR, "traversal.zip")
    with zipfile.ZipFile(path, "w") as zf:
        zi = zipfile.ZipInfo("../../etc/evil.txt")
        zf.writestr(zi, "this should never escape the output directory")
        zf.writestr("normal_file.txt", "this one is fine")
    with tempfile.TemporaryDirectory() as outdir:
        r = fs.extract_archive_safe(path, outdir)
        extracted_names = {e["name"] for e in r["extracted"]}
        assert extracted_names == {"normal_file.txt"}
        assert len(r["rejected"]) == 1
        assert r["rejected"][0]["reason"] == "path traversal attempt"
        # Confirm nothing actually escaped the sandbox directory on disk
        assert not os.path.exists(os.path.join(outdir, "..", "..", "etc", "evil.txt"))


def test_extract_archive_safe_enforces_size_cap():
    path = os.path.join(FIXTURE_DIR, "bomb_like.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.txt", "A" * 1000)
    with tempfile.TemporaryDirectory() as outdir:
        original_cap = fs.MAX_EXTRACT_SIZE
        fs.MAX_EXTRACT_SIZE = 500  # artificially small to trigger the guard
        try:
            r = fs.extract_archive_safe(path, outdir)
            assert r["status"] == "aborted"
            assert "size" in r["reason"]
        finally:
            fs.MAX_EXTRACT_SIZE = original_cap


def test_list_archive_zip():
    path = os.path.join(FIXTURE_DIR, "normal.zip")
    r = fs.list_archive(path)
    assert r["archive_type"] == "zip"
    names = {e["name"] for e in r["entries"]}
    assert "notes.txt" in names
