"""
Real digital forensics analysis: actual PCAP packet parsing (via scapy,
pure Python - no tshark binary needed), and safe archive extraction that
genuinely enforces path-traversal and decompression-bomb protection
rather than just claiming to.
"""
import os
import tarfile
import zipfile
from . import tool_registry as tr

MAX_EXTRACT_SIZE = 50 * 1024 * 1024  # 50 MB total, matches "prevent decompression bombs"
MAX_EXTRACT_FILES = 500


def run_exiftool(path: str) -> dict:
    r = tr.run_tool("exiftool", [path], timeout=10)
    return {"tool": "exiftool", "command": f"exiftool {os.path.basename(path)}", **r}


def analyze_pcap(path: str, max_packets: int = 5000) -> dict:
    try:
        from scapy.all import rdpcap, DNS, Raw, TCP
        from scapy.layers.inet import IP
    except ImportError:
        return {"tool": "scapy_pcap_analysis", "status": "not_installed", "stderr": "scapy not installed."}
    try:
        packets = rdpcap(path, count=max_packets)
    except Exception as e:
        return {"tool": "scapy_pcap_analysis", "status": "error", "stderr": f"Could not parse as PCAP: {e}"}

    dns_queries = []
    http_requests = []
    flag_strings = []
    import re
    flag_re = re.compile(r"[A-Za-z0-9_]{2,15}\{[^}]{1,100}\}")

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt[DNS].qd is not None:
            try:
                dns_queries.append(pkt[DNS].qd.qname.decode("latin-1", "replace"))
            except Exception:
                pass
        if pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
                text = payload.decode("latin-1", "replace")
                if text.startswith(("GET ", "POST ", "PUT ", "HEAD ")) or "HTTP/1." in text[:200]:
                    http_requests.append(text[:300])
                flag_strings.extend(flag_re.findall(text))
            except Exception:
                pass

    return {
        "tool": "scapy_pcap_analysis", "status": "ran",
        "command": f"Python/scapy: rdpcap({os.path.basename(path)}), inspect DNS/TCP/Raw layers",
        "packet_count": len(packets),
        "dns_queries": list(dict.fromkeys(dns_queries))[:50],
        "http_requests_found": len(http_requests),
        "http_sample": http_requests[:10],
        "flag_candidates": list(dict.fromkeys(flag_strings)),
    }


def _safe_member_path(outdir: str, member_name: str) -> str | None:
    dest = os.path.normpath(os.path.join(outdir, member_name))
    if not dest.startswith(os.path.normpath(outdir) + os.sep):
        return None  # path traversal attempt (e.g. ../../etc/passwd)
    return dest


def list_archive(path: str) -> dict:
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                entries = [{"name": i.filename, "size": i.file_size, "compressed": i.compress_size}
                           for i in zf.infolist()]
            return {"tool": "zipfile", "status": "ran", "archive_type": "zip", "entries": entries[:200]}
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                entries = [{"name": m.name, "size": m.size} for m in tf.getmembers()]
            return {"tool": "tarfile", "status": "ran", "archive_type": "tar", "entries": entries[:200]}
    except Exception as e:
        return {"tool": "archive_list", "status": "error", "stderr": str(e)}
    # fall back to 7z for formats python stdlib doesn't read (7z, rar)
    r = tr.run_tool("7z", ["l", path], timeout=15)
    return {"tool": "7z", "command": f"7z l {os.path.basename(path)}", "archive_type": "unknown", **r}


def extract_archive_safe(path: str, outdir: str) -> dict:
    """Extracts with explicit path-traversal rejection and a cumulative size cap."""
    extracted, total_size, rejected = [], 0, []
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if len(extracted) >= MAX_EXTRACT_FILES:
                        return _bomb_abort(extracted, rejected, "max file count exceeded")
                    dest = _safe_member_path(outdir, info.filename)
                    if dest is None:
                        rejected.append({"name": info.filename, "reason": "path traversal attempt"})
                        continue
                    total_size += info.file_size
                    if total_size > MAX_EXTRACT_SIZE:
                        return _bomb_abort(extracted, rejected, "cumulative size limit exceeded (possible zip bomb)")
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with zf.open(info) as src, open(dest, "wb") as dst:
                        dst.write(src.read())
                    extracted.append({"name": info.filename, "size": info.file_size, "path": dest})
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                for member in tf.getmembers():
                    if len(extracted) >= MAX_EXTRACT_FILES:
                        return _bomb_abort(extracted, rejected, "max file count exceeded")
                    dest = _safe_member_path(outdir, member.name)
                    if dest is None:
                        rejected.append({"name": member.name, "reason": "path traversal attempt"})
                        continue
                    total_size += member.size
                    if total_size > MAX_EXTRACT_SIZE:
                        return _bomb_abort(extracted, rejected, "cumulative size limit exceeded (possible tar bomb)")
                    if member.isfile():
                        tf.extract(member, outdir, filter="data")
                        extracted.append({"name": member.name, "size": member.size, "path": dest})
        else:
            return {"status": "error", "stderr": "Unsupported archive format for safe extraction (try 7z list only)."}
    except Exception as e:
        return {"status": "error", "stderr": str(e), "extracted": extracted, "rejected": rejected}

    return {"status": "ran", "extracted": extracted, "rejected": rejected,
            "total_size_bytes": total_size}


def _bomb_abort(extracted, rejected, reason):
    return {"status": "aborted", "reason": reason, "extracted": extracted, "rejected": rejected}
