"""
DragonByte CTF AI - FastAPI backend.

Run:
  uvicorn main:app --reload --port 8000

Endpoints:
  GET  /api/health             -> status + whether AI is configured
  GET  /api/toolkit            -> command reference for all 9 categories
  POST /api/analyze            -> run deterministic analysis + AI reasoning
"""
import asyncio
import os
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import analyzer
import ai_engine
from solvers import orchestrator

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB, matches "enforce file-size limits"
MAX_STRINGS_SENT_TO_AI = 25

app = FastAPI(title="DragonByte CTF AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


class HealthResponse(BaseModel):
    status: str
    ai_provider_configured: bool
    ai_provider: Optional[str]


@app.get("/api/health", response_model=HealthResponse)
def health():
    provider = ai_engine.AI_PROVIDER or None
    configured = False
    if provider == "anthropic":
        configured = bool(os.getenv("ANTHROPIC_API_KEY"))
    elif provider == "openai":
        configured = bool(os.getenv("OPENAI_API_KEY"))
    elif provider == "ollama":
        configured = True  # no key required; reachability isn't checked here
    return HealthResponse(status="ok", ai_provider_configured=configured, ai_provider=provider)


@app.get("/api/toolkit")
def toolkit():
    return {cat: [{"label": label, "command": cmd} for label, cmd in cmds]
            for cat, cmds in analyzer.TOOLKIT.items()}


@app.get("/api/categories")
def categories():
    return {"categories": analyzer.CATEGORIES}


@app.post("/api/analyze")
async def analyze(
    text: str = Form(default=""),
    use_ai: bool = Form(default=True),
    file: Optional[UploadFile] = File(default=None),
):
    """
    Runs the full agent loop: deterministic engine -> real per-category tool
    execution (crypto attacks, exiftool/binwalk/steghide/zbarimg, PCAP parsing,
    safe archive extraction, ELF checksec, etc.) -> evidence aggregation ->
    optional AI reasoning grounded in that real evidence. See solvers/orchestrator.py.
    """
    file_bytes = None
    file_meta = None

    if file is not None:
        raw = await file.read()
        if len(raw) > MAX_FILE_SIZE:
            return {"error": f"File exceeds the {MAX_FILE_SIZE // (1024*1024)} MB limit and was not analyzed.",
                    "result": None, "ai": None}
        file_bytes = raw
        file_meta = {"filename": file.filename, "size_bytes": len(raw)}

    # The orchestrator runs real subprocesses (blocking I/O), so it runs in a
    # worker thread rather than blocking the async event loop.
    result = await asyncio.to_thread(
        orchestrator.solve, text=text, file_bytes=file_bytes, filename=(file.filename if file else "")
    )
    result["file_meta"] = file_meta

    ai_payload = None
    if use_ai:
        ai_payload = await ai_engine.get_ai_analysis_from_evidence(
            category_guess=result["category"],
            evidence=result["evidence"],
            flag_candidates=result["all_flag_candidates"],
        )

    return {"error": None, "result": result, "ai": ai_payload}
