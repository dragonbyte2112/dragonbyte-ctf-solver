"""
AI integration layer for DragonByte CTF AI.

Configurable providers:
AI_PROVIDER=gemini      -> uses GEMINI_API_KEY, GEMINI_MODEL
AI_PROVIDER=anthropic   -> uses ANTHROPIC_API_KEY, ANTHROPIC_MODEL
AI_PROVIDER=openai      -> uses OPENAI_API_KEY, OPENAI_MODEL
AI_PROVIDER=ollama      -> uses OLLAMA_BASE_URL, OLLAMA_MODEL

If no provider is configured, the analyzer still works using the
deterministic engine and reports clearly that AI assistance is unavailable.
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


def build_prompt_from_evidence(
    category_guess: str,
    evidence: list,
    flag_candidates: list,
) -> str:
    """
    Build the AI prompt from the orchestrator's real evidence steps.
    The AI only sees information genuinely produced by the tool run.
    """

    parts = [f"Detected category: {category_guess}", ""]

    for ev in evidence:
        parts.append(
            f"--- Step {ev['step']}: {ev['tool']} ({ev['status']}) ---"
        )

        if ev.get("command"):
            parts.append(f"Command/method: {ev['command']}")

        out = ev.get("output", {})

        if isinstance(out, dict):
            for key in (
                "stdout",
                "decrypted",
                "plaintext_guess",
                "preview",
                "extracted_preview",
                "dns_queries",
                "http_sample",
                "nx_stack",
                "pie",
                "relro",
                "stack_canary",
                "arch",
            ):
                if key in out and out[key]:
                    val = str(out[key])
                    parts.append(f"  {key}: {val[:400]}")

        if ev.get("flags_found"):
            parts.append(
                f"  flags found in this step: {ev['flags_found']}"
            )

        parts.append("")

    if flag_candidates:
        parts.append(
            f"All flag-format candidates found across every step: "
            f"{flag_candidates}"
        )
    else:
        parts.append(
            "No flag-format candidates found by any tool yet."
        )

    return "\n".join(parts)


def build_user_prompt(
    category_guess: str,
    text_excerpt: str,
    file_info: Optional[dict],
    decode_steps: list,
    strings_sample: list,
    flag_candidates: list,
) -> str:

    parts = [f"Detected category (heuristic): {category_guess}"]

    if file_info:
        parts.append(
            f"File signature: {file_info.get('name')} "
            f"(suggests {file_info.get('category')})"
        )

    if text_excerpt:
        parts.append(
            f"Input text/ciphertext (truncated): {text_excerpt[:500]}"
        )

    if decode_steps:
        chain = " -> ".join(
            f"{s['technique']}:{s['output'][:60]}"
            for s in decode_steps[:8]
        )
        parts.append(
            f"Auto-decode chain results: {chain}"
        )

    if strings_sample:
        parts.append(
            "Sample extracted strings: "
            + " | ".join(strings_sample[:25])
        )

    if flag_candidates:
        parts.append(
            f"Flag-format candidates already found: {flag_candidates}"
        )
    else:
        parts.append(
            "No flag-format candidates found yet by the deterministic engine."
        )

    return "\n".join(parts)


# ============================================================
# GEMINI
# ============================================================

async def call_gemini(system: str, user: str) -> str:
    """
    Call Google Gemini API.

    Environment variables:
      GEMINI_API_KEY
      GEMINI_MODEL

    Default model:
      gemini-2.5-flash
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise AIUnavailable(
            "GEMINI_API_KEY is not set."
        )

    model = os.getenv(
        "GEMINI_MODEL",
        "gemini-2.5-flash",
    )

    url = (
        "https://generativelanguage.googleapis.com/"
        f"v1beta/models/{model}:generateContent"
    )

    payload = {
        "system_instruction": {
            "parts": [
                {
                    "text": system
                }
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": user
                    }
                ]
            }
        ],
        "generationConfig": {
            "maxOutputTokens": 1000
        }
    }

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            url,
            params={
                "key": api_key
            },
            headers={
                "content-type": "application/json"
            },
            json=payload,
        )

        resp.raise_for_status()

        data = resp.json()

        candidates = data.get("candidates", [])

        if not candidates:
            raise AIUnavailable(
                "Gemini returned no candidates."
            )

        content = candidates[0].get("content", {})
        parts = content.get("parts", [])

        text_parts = []

        for part in parts:
            if part.get("text"):
                text_parts.append(
                    part["text"]
                )

        result = "".join(text_parts).strip()

        if not result:
            raise AIUnavailable(
                "Gemini returned an empty response."
            )

        return result


# ============================================================
# ANTHROPIC
# ============================================================

async def call_anthropic(system: str, user: str) -> str:

    api_key = os.getenv("ANTHROPIC_API_KEY")

    if not api_key:
        raise AIUnavailable(
            "ANTHROPIC_API_KEY is not set."
        )

    model = os.getenv(
        "ANTHROPIC_MODEL",
        "claude-sonnet-4-6",
    )

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
                "messages": [
                    {
                        "role": "user",
                        "content": user,
                    }
                ],
            },
        )

        resp.raise_for_status()

        data = resp.json()

        return "".join(
            block.get("text", "")
            for block in data.get("content", [])
            if block.get("type") == "text"
        )


# ============================================================
# OPENAI
# ============================================================

async def call_openai(system: str, user: str) -> str:

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise AIUnavailable(
            "OPENAI_API_KEY is not set."
        )

    model = os.getenv(
        "OPENAI_MODEL",
        "gpt-4o-mini",
    )

    async with httpx.AsyncClient(timeout=60) as client:

        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",

            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },

            json={
                "model": model,
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "system",
                        "content": system,
                    },
                    {
                        "role": "user",
                        "content": user,
                    },
                ],
            },
        )

        resp.raise_for_status()

        data = resp.json()

        return data["choices"][0]["message"]["content"]


# ============================================================
# OLLAMA
# ============================================================

async def call_ollama(system: str, user: str) -> str:

    base = os.getenv(
        "OLLAMA_BASE_URL",
        "http://localhost:11434",
    )

    model = os.getenv(
        "OLLAMA_MODEL",
        "llama3",
    )

    async with httpx.AsyncClient(timeout=120) as client:

        resp = await client.post(
            f"{base}/api/chat",

            json={
                "model": model,
                "stream": False,
                "messages": [
                    {
                        "role": "system",
                        "content": system,
                    },
                    {
                        "role": "user",
                        "content": user,
                    },
                ],
            },
        )

        resp.raise_for_status()

        data = resp.json()

        return data.get(
            "message",
            {}
        ).get(
            "content",
            ""
        )


# ============================================================
# PUBLIC ANALYSIS FUNCTIONS
# ============================================================

async def get_ai_analysis_from_evidence(
    category_guess: str,
    evidence: list,
    flag_candidates: list,
) -> dict:
    """
    AI analysis grounded in the orchestrator's real evidence.
    """

    user_prompt = build_prompt_from_evidence(
        category_guess,
        evidence,
        flag_candidates,
    )

    return await _dispatch(user_prompt)


async def get_ai_analysis(
    category_guess: str,
    text_excerpt: str,
    file_info: Optional[dict],
    decode_steps: list,
    strings_sample: list,
    flag_candidates: list,
) -> dict:
    """
    Returns:
      available
      provider
      text
      error
    """

    user_prompt = build_user_prompt(
        category_guess,
        text_excerpt,
        file_info,
        decode_steps,
        strings_sample,
        flag_candidates,
    )

    return await _dispatch(user_prompt)


# ============================================================
# PROVIDER DISPATCHER
# ============================================================

async def _dispatch(user_prompt: str) -> dict:

    provider = AI_PROVIDER

    try:

        if provider == "gemini":

            text = await call_gemini(
                SYSTEM_PROMPT,
                user_prompt,
            )

        elif provider == "anthropic":

            text = await call_anthropic(
                SYSTEM_PROMPT,
                user_prompt,
            )

        elif provider == "openai":

            text = await call_openai(
                SYSTEM_PROMPT,
                user_prompt,
            )

        elif provider == "ollama":

            text = await call_ollama(
                SYSTEM_PROMPT,
                user_prompt,
            )

        else:

            return {
                "available": False,
                "provider": None,
                "text": "",
                "error": (
                    "No AI_PROVIDER configured. "
                    "Set AI_PROVIDER=gemini|anthropic|openai|ollama "
                    "and the matching API key in your .env file."
                ),
            }

        return {
            "available": True,
            "provider": provider,
            "text": text,
            "error": None,
        }

    except AIUnavailable as e:

        return {
            "available": False,
            "provider": provider,
            "text": "",
            "error": str(e),
        }

    except httpx.HTTPStatusError as e:

        return {
            "available": False,
            "provider": provider,
            "text": "",
            "error": (
                f"AI provider returned "
                f"{e.response.status_code}: "
                f"{e.response.text[:500]}"
            ),
        }

    except Exception as e:

        return {
            "available": False,
            "provider": provider,
            "text": "",
            "error": f"AI call failed: {e}",
        }