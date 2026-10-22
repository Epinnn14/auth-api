"""Talks to Supabase Auth (the Identity Provider). This file is the only place that knows Supabase exists."""
from __future__ import annotations

import os

from dotenv import load_dotenv
from supabase import Client, ClientOptions, create_client

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")


def new_client() -> Client:
    """A fresh client per call. persist_session=False so one user's session can never leak into another request."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
    return create_client(SUPABASE_URL, SUPABASE_KEY,
                         options=ClientOptions(persist_session=False, auto_refresh_token=False))
