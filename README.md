# DragonByte CTF AI

A CTF-solving workspace: a deterministic analysis engine (file signature
detection, string extraction, an auto-decode chain, flag detection) plus
an AI reasoning layer that runs on your own backend, covering all 9
categories (Web, Crypto, Forensics, Stego, Reverse Engineering, Binary
Exploitation, OSINT, Misc, and Automatic File Analysis).

The frontend has **no AI built into the page itself** — it is a static
HTML/JS client that calls your FastAPI backend, and the backend is what
talks to the AI provider. This keeps your API key server-side only.

## What's implemented right now

- **Deterministic engine**: file signature detection (PNG/JPEG/ELF/PE/PCAP/ZIP/etc.),
  printable-string extraction, a recursive auto-decode chain (Base64, Hex,
  Binary, ROT13, URL, Morse), and flag-format detection (`name{...}`).
- **Real per-category solvers** (`backend/solvers/`) — these actually run, not
  just print a suggested command:
  - **Cryptography**: Caesar brute-force (frequency-scored), Vigenère
    (index-of-coincidence key-length estimate + per-column crack), single-byte
    and repeating-key XOR cracking (crib-dragging against common flag prefixes,
    with a frequency-analysis fallback), RSA attacks (direct factoring for
    small moduli, Fermat's method for close primes), hash identification, and
    a built-in common-password hash cracker.
  - **Steganography**: real `exiftool`, `binwalk` (scan + size-capped
    extraction), `steghide` (common-password attempts), `zbarimg` (QR/barcode),
    and a pure-Python LSB extractor — all genuinely invoked as subprocesses.
  - **Digital Forensics**: real PCAP parsing via `scapy` (DNS queries, HTTP
    requests, payload flag-scanning), safe archive extraction with real
    path-traversal rejection and a decompression-bomb size cap.
  - **Reverse Engineering**: real `file`/`strings`/`objdump`, plus our own
    checksec implementation (NX/PIE/RELRO/stack-canary/stripped) built on
    `pyelftools` — verified against real binaries compiled with different
    protection flags.
  - **Web CTF**: static source review (hidden fields, hardcoded secrets,
    leftover comments) — deliberately does not make live requests to a
    user-given target without an explicitly authorized scope.
  - All of this is tied together by `solvers/orchestrator.py`: classify →
    run the approved real tools for that category → capture actual output →
    aggregate evidence, capped at 20 steps / 25 seconds so nothing runs away.
- **AI reasoning**: sent your *real* tool evidence (not just a summary),
  asked to confirm the category, lay out next steps, and give a cautious
  verdict on any flag candidate — never claims a flag is verified without
  proof. Configurable: Anthropic, OpenAI, or local Ollama.
- **Toolkit tab**: command reference for all 9 categories, served from the backend.
- File upload (drag-and-drop), 25 MB size limit enforced server-side.
- **56 automated tests, all passing** — including real synthetic challenges:
  a PNG with a genuinely LSB-embedded flag, two ELF binaries compiled with
  different security mitigations (confirmed checksec tells them apart), a
  real PCAP with a flag in an HTTP payload, a zip with an actual path-traversal
  attack (confirmed rejected and confirmed nothing escaped the output
  directory), and real crypto ciphertexts for every attack above.

## What is NOT implemented yet (be aware before relying on this for a competition)

- No database, no user accounts/auth, no session history, no report
  generation (Markdown/JSON/PDF) — this is the Solver + Toolkit MVP only.
- Tool execution uses OS-level subprocess calls with timeouts, not full
  container/namespace isolation — fine for your own local backend, but don't
  expose this to untrusted uploaders without adding that isolation layer.
- No CTFd import, no automatic flag submission.
- Web CTF solving is static-source-review only — no live scanning of a
  target URL, by design (needs an explicitly authorized scope).
- Docker Compose is provided but has not been run in this environment
  (no Docker available here) — the backend has been tested directly with
  uvicorn and real HTTP requests instead.

## Project structure

```
dragonbyte-ctf/
├── backend/
│   ├── main.py             FastAPI app (/api/health, /api/toolkit, /api/analyze)
│   ├── analyzer.py         deterministic engine (tested, no AI calls)
│   ├── ai_engine.py        AI provider integration (Anthropic/OpenAI/Ollama)
│   ├── solvers/            real per-category solvers + the orchestrator
│   │   ├── tool_registry.py    allowlisted, timeout-enforced subprocess wrapper
│   │   ├── crypto_solver.py    Caesar/Vigenere/XOR/RSA/hash attacks
│   │   ├── stego_solver.py     exiftool/binwalk/steghide/zbarimg + LSB extractor
│   │   ├── forensics_solver.py scapy PCAP parsing + safe archive extraction
│   │   ├── reverse_solver.py   file/strings/objdump + pyelftools checksec
│   │   ├── web_solver.py       static HTML/JS source review
│   │   └── orchestrator.py     classify -> run real tools -> aggregate evidence
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
├── frontend/
│   ├── index.html          single-file UI (your DragonByte logo embedded), calls the backend
│   └── logo.png             source logo asset (also inlined into index.html as base64)
├── tests/
│   ├── test_analyzer.py
│   ├── test_api.py
│   ├── test_crypto_solver.py
│   ├── test_stego_solver.py
│   ├── test_forensics_solver.py
│   ├── test_reverse_solver.py
│   └── fixtures/          (generated by the tests themselves on first run)
├── docker-compose.yml
└── README.md
```

## Setup — Windows

```powershell
# 1. Install Python 3.12+ from python.org, then:
cd dragonbyte-ctf\backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 2. Configure your AI provider
copy .env.example .env
notepad .env        # set AI_PROVIDER and the matching API key

# 3. Run the backend
uvicorn main:app --reload --port 8000

# 4. Open the frontend
# Just double-click frontend/index.html, or serve it:
cd ..\frontend
python -m http.server 5500
# then visit http://localhost:5500 in your browser
```

## Setup — Kali Linux

```bash
# 1. Python 3.12+ ships with Kali; confirm with: python3 --version
cd dragonbyte-ctf/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Configure your AI provider
cp .env.example .env
nano .env            # set AI_PROVIDER and the matching API key

# 3. Run the backend
uvicorn main:app --reload --port 8000

# 4. Open the frontend
cd ../frontend
python3 -m http.server 5500
# then visit http://localhost:5500
```

In the sidebar of the web UI, confirm "Backend URL" is `http://localhost:8000`
(the default) and that the status line shows "Connected".

## Running with Docker Compose (optional)

```bash
cd dragonbyte-ctf
cp backend/.env.example backend/.env   # edit with your AI provider + key
docker compose up --build
```
The API is then at `http://localhost:8000`. Serve `frontend/index.html` any
way you like (a static file server, Vercel, Nginx, etc.) — it only needs to
reach the backend.

## Running the tests

```bash
cd dragonbyte-ctf
pip install -r backend/requirements.txt
python -m pytest tests/ -v
```
Expected: **56 passed**. The AI-provider test is mocked, so it runs without
needing a real API key. Several tests compile a real ELF binary with `gcc`
and craft real image/PCAP/zip fixtures on first run — `gcc` must be on PATH
(standard on Kali; install via MSYS2/WSL on Windows, or just skip those
specific tests if you only care about the crypto solvers).

## Required system packages for the real tool integrations

These are invoked as real subprocesses by the solvers, not simulated:
```bash
# Debian/Kali/Ubuntu
sudo apt install libimage-exiftool-perl binwalk steghide zbar-tools p7zip-full binutils gcc
```
`file`, `strings`, `objdump`, `unzip`, `tar`, `openssl` ship with most Linux
distros already. If a tool isn't installed, the matching solver step reports
`"status": "not_installed"` honestly instead of failing silently or faking output.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `AI_PROVIDER` | No (blank = real tool analysis still runs, just no AI narrative) | `anthropic`, `openai`, or `ollama` |
| `ANTHROPIC_API_KEY` | If provider=anthropic | Your Anthropic API key |
| `ANTHROPIC_MODEL` | No | Defaults to `claude-sonnet-4-6` |
| `OPENAI_API_KEY` | If provider=openai | Your OpenAI API key |
| `OPENAI_MODEL` | No | Defaults to `gpt-4o-mini` |
| `OLLAMA_BASE_URL` | If provider=ollama | Defaults to `http://localhost:11434` |
| `OLLAMA_MODEL` | If provider=ollama | e.g. `llama3` |
| `CORS_ORIGINS` | No | Defaults to `*` (fine for local use) |

Never commit `.env` or any real API key to version control.

## Deployment notes

- The frontend is static — Vercel, Netlify, GitHub Pages, or any static
  host works. Point its "Backend URL" field at your deployed API.
- The backend should run somewhere that can hold a secret API key —
  Render, Fly.io, a VPS, or your own server. Don't deploy it serverless
  on Vercel if you plan to add background workers later, since those need
  a long-running process.
- Set `CORS_ORIGINS` to your actual frontend domain in production instead
  of `*`.

## Test results (this build)

```
18 passed — tests/test_analyzer.py        (decode chain, signatures, flags, toolkit)
 9 passed — tests/test_api.py             (health, toolkit, analyze w/ text, w/ real PNG
                                            through the full real-tool chain, w/ real compiled
                                            ELF through checksec, oversized-file rejection,
                                            AI unavailable, AI mocked-provider success)
10 passed — tests/test_crypto_solver.py   (Caesar, Vigenere, single-byte XOR, repeating-key
                                            XOR short+long key, RSA small-prime factoring,
                                            hash ID, hash cracking hit + miss)
 5 passed — tests/test_stego_solver.py    (real LSB extraction of a genuinely embedded flag,
                                            real exiftool/binwalk/steghide/zbarimg subprocess runs)
 8 passed — tests/test_forensics_solver.py (real PCAP parsing via scapy incl. flag extraction,
                                            real path-traversal rejection, real size-cap abort)
 6 passed — tests/test_reverse_solver.py  (real checksec against two differently-compiled ELF
                                            binaries, real file/strings/objdump subprocess runs)
──────────────────────────────────────────
56 passed total, 0 failed
```

Every test above exercises genuinely executing code against genuine data —
real ciphertexts encrypted with a known key the test then has to recover,
a real PNG with bits actually flipped to embed a flag, a real ELF compiled
by `gcc` with specific protection flags, a real PCAP with crafted packets,
a real zip containing an actual path-traversal entry. Also manually
verified against a live running server with real HTTP requests end to end.

## Next steps if you want to keep building

In priority order for a competition use-case: (1) CTFd import, (2) real
sandboxed tool execution (binwalk/exiftool/etc. in isolated containers),
(3) session history + auth so a team can share evidence, (4) report
export. Ask and I'll build the next one the same way — real code, real
tests, honest about what still doesn't work.
