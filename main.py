import logging

from fastapi import FastAPI

import auth_provider

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("auth-api")

app = FastAPI(title="Auth API", version="1.0")

auth_provider.new_client()  # fails fast at startup if the .env values are missing
log.info("Server running and connected to Supabase (%s)", auth_provider.SUPABASE_URL)


@app.get("/health")
def health():
    return {"status": "ok"}
