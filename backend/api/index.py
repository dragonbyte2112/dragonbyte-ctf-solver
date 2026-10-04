"""
Vercel serverless entrypoint. Vercel's Python runtime looks for an ASGI/WSGI
app named `app` in api/*.py files and wraps it automatically - no Mangum or
extra adapter needed for FastAPI specifically, since Vercel's Python builder
natively supports ASGI apps.

This just imports the real app from main.py one directory up.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402