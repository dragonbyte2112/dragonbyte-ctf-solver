import sys, os, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
import main
import ai_engine

client = TestClient(main.app)


def test_health_no_provider():
    os.environ.pop("ANTHROPIC_API_KEY", None)
    ai_engine.AI_PROVIDER = ""
    main.ai_engine.AI_PROVIDER = ""
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_toolkit_endpoint():
    r = client.get("/api/toolkit")
    assert r.status_code == 200
    data = r.json()
    assert "Cryptography" in data
    assert len(data["Cryptography"]) > 0


def test_categories_endpoint():
    r = client.get("/api/categories")
    assert "Web CTF" in r.json()["categories"]


def test_analyze_text_only_no_ai():
    encoded = base64.b64encode(b"flag{api_test}").decode()
    r = client.post("/api/analyze", data={"text": encoded, "use_ai": "false"})
    assert r.status_code == 200
    body = r.json()
    assert body["error"] is None
    assert "flag{api_test}" in body["result"]["all_flag_candidates"]
    assert body["ai"] is None


def test_analyze_reports_ai_unavailable_when_unconfigured():
    main.ai_engine.AI_PROVIDER = ""
    r = client.post("/api/analyze", data={"text": "hello", "use_ai": "true"})
    body = r.json()
    assert body["ai"]["available"] is False
    assert "AI_PROVIDER" in body["ai"]["error"]


def test_analyze_with_mocked_ai_provider(monkeypatch):
    async def fake_anthropic(system, user):
        return "Mocked AI analysis: this looks like Base64, decode it with base64 -d."
    monkeypatch.setattr(main.ai_engine, "call_anthropic", fake_anthropic)
    main.ai_engine.AI_PROVIDER = "anthropic"
    os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"

    encoded = base64.b64encode(b"flag{mocked_ai}").decode()
    r = client.post("/api/analyze", data={"text": encoded, "use_ai": "true"})
    body = r.json()
    assert body["ai"]["available"] is True
    assert "Mocked AI analysis" in body["ai"]["text"]
    assert "flag{mocked_ai}" in body["result"]["all_flag_candidates"]
    os.environ.pop("ANTHROPIC_API_KEY", None)
    main.ai_engine.AI_PROVIDER = ""


def test_analyze_file_upload_real_png():
    # A genuinely valid PNG (not just magic bytes) so the real tool chain
    # (exiftool/binwalk/steghide/zbarimg/lsb_extract) runs against a file
    # each tool can actually open, exercising the real orchestrator path.
    from PIL import Image
    import io
    img = Image.new("RGB", (10, 10), color=(1, 2, 3))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue() + b"flag{file_upload_test}"

    r = client.post(
        "/api/analyze",
        data={"text": "", "use_ai": "false"},
        files={"file": ("challenge.png", png_bytes, "image/png")},
    )
    body = r.json()
    assert body["error"] is None
    assert body["result"]["category"] == "Steganography"
    assert "flag{file_upload_test}" in body["result"]["all_flag_candidates"]
    tools_run = {ev["tool"] for ev in body["result"]["evidence"]}
    assert "exiftool" in tools_run
    assert "binwalk" in tools_run


def test_analyze_oversized_file_rejected():
    main.MAX_FILE_SIZE = 10  # shrink limit for this test
    r = client.post(
        "/api/analyze",
        data={"text": "", "use_ai": "false"},
        files={"file": ("big.bin", b"0123456789ABCDEF", "application/octet-stream")},
    )
    body = r.json()
    assert body["error"] is not None
    assert "limit" in body["error"]
    main.MAX_FILE_SIZE = 25 * 1024 * 1024  # restore


def test_analyze_elf_runs_checksec():
    import subprocess, tempfile
    src = tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w")
    src.write("int main(){return 0;}")
    src.close()
    binpath = src.name + ".bin"
    subprocess.run(["gcc", "-o", binpath, src.name], check=True)
    with open(binpath, "rb") as f:
        elf_bytes = f.read()

    r = client.post(
        "/api/analyze",
        data={"text": "", "use_ai": "false"},
        files={"file": ("challenge", elf_bytes, "application/octet-stream")},
    )
    body = r.json()
    assert body["result"]["category"] == "Reverse Engineering"
    tools_run = {ev["tool"]: ev for ev in body["result"]["evidence"]}
    assert "elf_checksec" in tools_run
    assert tools_run["elf_checksec"]["status"] == "ran"
    os.unlink(src.name)
    os.unlink(binpath)
