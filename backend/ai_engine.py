"""
AI integration layer for DragonByte CTF AI.

Configurable provider:
  AI_PROVIDER=anthropic   -> uses ANTHROPIC_API_KEY, ANTHROPIC_MODEL
  AI_PROVIDER=openai      -> uses OPENAI_API_KEY, OPENAI_MODEL
  AI_PROVIDER=ollama      -> uses OLLAMA_BASE_URL, OLLAMA_MODEL (local, no key needed)

If no provider is configured, the analyzer still works (deterministic engine),
and this module reports clearly that AI assistance is unavailable rather than
fabricating a result.
"""
import os
from typing import Optional

import httpx

AI_PROVIDER = os.getenv("AI_PROVIDER", "").lower().strip()


class AIUnavailable(Exception):
    pass


SYSTEM_PROMPT = (
    "You are DragonByte CTF AI, a cybersecurity CTF solving assistant. "
    "You are given the results of real, already-executed deterministic analysis "
    "(file signature, extracted strings, an automatic decode chain, and candidate "
    "flag matches) for exactly one of these categories: Web CTF, Cryptography, "
    "Digital Forensics, Steganography, Reverse Engineering, Binary Exploitation, "
    "OSINT, Miscellaneous, or Automatic Challenge File Analysis.\n\n"
    "Your job:\n"
    "1. Confirm or correct the detected category, with your reasoning.\n"
    "2. Lay out a concrete, ordered analysis plan using real tools for that category.\n"
    "3. Interpret the strings/decode output already provided - do not re-invent data "
    "that wasn't given to you.\n"
    "4. If a flag candidate was found, state whether it looks like a genuine flag "
    "format match or likely noise, and what would verify it.\n"
    "5. If no flag was found, give the single next command the user should run, "
    "and why.\n"
    "Never claim a flag is verified - only the user's own tool execution can verify one. "
    "Be concise and concrete. Use actual command syntax, not vague advice."
)


def build_prompt_from_evidence(category_guess: str, evidence: list, flag_candidates: list) -> str:
    """Builds the AI prompt from the orchestrator's real evidence steps - i.e.
    actual tool names, actual commands, actual captured output. The AI never
    sees anything here that wasn't genuinely produced by a real tool run."""
    parts = [f"Detected category: {category_guess}", ""]
    for ev in evidence:
        parts.append(f"--- Step {ev['step']}: {ev['tool']} ({ev['status']}) ---")
        if ev.get("command"):
            parts.append(f"Command/method: {ev['command']}")
        out = ev.get("output", {})
        if isinstance(out, dict):
            for key in ("stdout", "decrypted", "plaintext_guess", "preview",
                        "extracted_preview", "dns_queries", "http_sample",
                        "nx_stack", "pie", "relro", "stack_canary", "arch"):
                if key in out and out[key]:
                    val = str(out[key])
                    parts.append(f"  {key}: {val[:400]}")
        if ev.get("flags_found"):
            parts.append(f"  flags found in this step: {ev['flags_found']}")
        parts.append("")
    if flag_candidates:
        parts.append(f"All flag-format candidates found across every step: {flag_candidates}")
    else:
        parts.append("No flag-format candidates found by any tool yet.")
    return "\n".join(parts)


def build_user_prompt(category_guess: str, text_excerpt: str, file_info: Optional[dict],
                       decode_steps: list, strings_sample: list, flag_candidates: list) -> str:
    parts = [f"Detected category (heuristic): {category_guess}"]
    if file_info:
        parts.append(f"File signature: {file_info.get('name')} (suggests {file_info.get('category')})")
    if text_excerpt:
        parts.append(f"Input text/ciphertext (truncated): {text_excerpt[:500]}")
    if decode_steps:
        chain = " -> ".join(f"{s['technique']}:{s['output'][:60]}" for s in decode_steps[:8])
        parts.append(f"Auto-decode chain results: {chain}")
    if strings_sample:
        parts.append("Sample extracted strings: " + " | ".join(strings_sample[:25]))
    if flag_candidates:
        parts.append(f"Flag-format candidates already found: {flag_candidates}")
    else:
        parts.append("No flag-format candidates found yet by the deterministic engine.")
    return "\n".join(parts)


async def call_anthropic(system: str, user: str) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise AIUnavailable("ANTHROPIC_API_KEY is not set.")
    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 1000,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


async def call_openai(system: str, user: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise AIUnavailable("OPENAI_API_KEY is not set.")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
            json={
                "model": model,
                "max_tokens": 1000,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


async def call_ollama(system: str, user: str) -> str:
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3")
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(
            f"{base}/api/chat",
            json={
                "model": model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("message", {}).get("content", "")


async def get_ai_analysis_from_evidence(category_guess: str, evidence: list, flag_candidates: list) -> dict:
    """Same as get_ai_analysis, but grounded in the orchestrator's real,
    already-executed tool evidence rather than just the basic deterministic
    summary. Returns {'available': bool, 'provider': str, 'text': str, 'error': str|None}"""
    user_prompt = build_prompt_from_evidence(category_guess, evidence, flag_candidates)
    return await _dispatch(user_prompt)


async def get_ai_analysis(category_guess: str, text_excerpt: str, file_info: Optional[dict],
                           decode_steps: list, strings_sample: list, flag_candidates: list) -> dict:
    """Returns {'available': bool, 'provider': str, 'text': str, 'error': str|None}"""
    user_prompt = build_user_prompt(category_guess, text_excerpt, file_info, decode_steps,
                                     strings_sample, flag_candidates)
    return await _dispatch(user_prompt)


async def _dispatch(user_prompt: str) -> dict:
    provider = AI_PROVIDER
    try:
        if provider == "anthropic":
            text = await call_anthropic(SYSTEM_PROMPT, user_prompt)
        elif provider == "openai":
            text = await call_openai(SYSTEM_PROMPT, user_prompt)
        elif provider == "ollama":
            text = await call_ollama(SYSTEM_PROMPT, user_prompt)
        else:
            return {"available": False, "provider": None, "text": "",
                    "error": "No AI_PROVIDER configured. Set AI_PROVIDER=anthropic|openai|ollama "
                             "and the matching API key in your .env file."}
        return {"available": True, "provider": provider, "text": text, "error": None}
    except AIUnavailable as e:
        return {"available": False, "provider": provider, "text": "", "error": str(e)}
    except httpx.HTTPStatusError as e:
        return {"available": False, "provider": provider, "text": "",
                "error": f"AI provider returned {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"available": False, "provider": provider, "text": "", "error": f"AI call failed: {e}"}
