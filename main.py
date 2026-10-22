import logging

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import auth_provider
from auth_provider import AuthFailed, InvalidToken, SupabaseAuth, get_auth

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("auth-api")

app = FastAPI(title="Auth API", version="1.0")

if auth_provider.SUPABASE_URL:
    auth_provider.new_client()
    log.info("Server running and connected to Supabase (%s)", auth_provider.SUPABASE_URL)


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=200)


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError):
    first = exc.errors()[0]
    field = ".".join(str(p) for p in first["loc"] if p != "body") or "body"
    return error(400, f"{field}: {first['msg']}")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/signup", status_code=201)
def signup(body: Credentials, auth: SupabaseAuth = Depends(get_auth)):
    try:
        return {"user": auth.sign_up(body.email, body.password)}
    except AuthFailed as exc:
        return error(400, str(exc))


@app.post("/auth/login")
def login(body: Credentials, auth: SupabaseAuth = Depends(get_auth)):
    try:
        return auth.sign_in(body.email, body.password)
    except AuthFailed:
        return error(401, "Invalid login credentials")


@app.get("/public/info")
def public_info():
    return {"message": "Welcome stranger! This info is public."}


def bearer_token(authorization: str | None) -> str | None:
    """'Bearer <token>' → '<token>'. Anything else (missing, wrong scheme, empty) → None."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


@app.get("/protected/profile")
def profile(request: Request, auth: SupabaseAuth = Depends(get_auth)):
    token = bearer_token(request.headers.get("Authorization"))
    if not token:
        return error(401, "Access token required")
    try:
        user = auth.get_user(token)
    except InvalidToken:
        return error(401, "Invalid or expired token")
    return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}
