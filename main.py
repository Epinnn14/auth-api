import logging
import os
import time
from collections import defaultdict

from fastapi import Depends, FastAPI, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import auth_provider
from auth_provider import AuthFailed, EmailNotConfirmed, InvalidToken, SupabaseAuth, get_auth

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("auth-api")

app = FastAPI(
    title="Auth API",
    version="1.0",
    description="Sign up, log in and log out with Supabase Auth; JWT-protected routes (FlyRank Backend track, A4). "
                "Click **Authorize** and paste an access_token from /auth/login to try the locked routes.",
)

E401 = {401: {"description": "Missing, malformed, invalid or expired token",
              "content": {"application/json": {"example": {"error": "Invalid or expired token"}}}}}

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


@app.get("/health", tags=["meta"], summary="Liveness check")
def health():
    return {"status": "ok"}


@app.post("/auth/signup", status_code=201, tags=["auth"], summary="Create an account (no auth)", responses={400: {"description": "Missing field or Supabase rejected it"}})
def signup(body: Credentials, auth: SupabaseAuth = Depends(get_auth)):
    try:
        return {"user": auth.sign_up(body.email, body.password)}
    except AuthFailed as exc:
        return error(400, str(exc))


# --- brute-force protection: 5 failed logins per email per 15 minutes, then 429 ---
MAX_FAILED_LOGINS = int(os.environ.get("MAX_FAILED_LOGINS", "5"))
LOCKOUT_SECONDS = 15 * 60
_failed: dict[str, list[float]] = defaultdict(list)


def _recent_failures(email: str) -> list[float]:
    now = time.monotonic()
    _failed[email] = [t for t in _failed[email] if now - t < LOCKOUT_SECONDS]
    return _failed[email]


@app.post("/auth/login", tags=["auth"], summary="Log in, returns access + refresh tokens (no auth)",
          responses={401: {"description": "Invalid login credentials"},
                     429: {"description": "Too many failed attempts for this email"}})
def login(body: Credentials, auth: SupabaseAuth = Depends(get_auth)):
    email = body.email.strip().lower()
    if len(_recent_failures(email)) >= MAX_FAILED_LOGINS:
        return JSONResponse(status_code=429, headers={"Retry-After": str(LOCKOUT_SECONDS)},
                            content={"error": "Too many failed login attempts. Try again in 15 minutes."})
    try:
        tokens = auth.sign_in(body.email, body.password)
    except EmailNotConfirmed:
        # not a password guess, so it doesn't count toward the lockout; say exactly what to do
        return error(403, "Email not confirmed. Click the link in the confirmation email, or turn off "
                          "'Confirm email' in Supabase (Authentication > Sign In / Providers > Email) for practice.")
    except AuthFailed:
        _failed[email].append(time.monotonic())
        return error(401, "Invalid login credentials")
    _failed.pop(email, None)
    return tokens


class RefreshBody(BaseModel):
    refresh_token: str = Field(min_length=1)


@app.post("/auth/refresh", tags=["auth"], summary="New access token from a refresh token (no password)",
          responses={401: {"description": "Invalid or expired refresh token"}})
def refresh(body: RefreshBody, auth: SupabaseAuth = Depends(get_auth)):
    try:
        return auth.refresh(body.refresh_token)
    except InvalidToken:
        return error(401, "Invalid or expired refresh token")


@app.get("/public/info", tags=["public"], summary="Public data, no token needed")
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


class Unauthorized(Exception):
    def __init__(self, message: str):
        self.message = message


@app.exception_handler(Unauthorized)
async def unauthorized(_request: Request, exc: Unauthorized):
    return JSONResponse(status_code=401, content={"error": exc.message},
                        headers={"WWW-Authenticate": "Bearer"})


bearer_scheme = HTTPBearer(auto_error=False, bearerFormat="JWT",
                           description="Paste the access_token from POST /auth/login")


def current_user(request: Request,
                 _creds: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
                 auth: SupabaseAuth = Depends(get_auth)) -> dict:
    """The guard. Any route that declares `user = Depends(current_user)` only runs for a verified user.
    The HTTPBearer scheme is what puts the padlock in Swagger; the header is still parsed strictly here."""
    token = bearer_token(request.headers.get("Authorization"))
    if not token:
        raise Unauthorized("Access token required")
    try:
        user = auth.get_user(token)
    except InvalidToken:
        raise Unauthorized("Invalid or expired token")
    request.state.token = token
    return user


@app.get("/protected/profile", tags=["protected"], summary="Your profile (Bearer token)", responses=E401)
def profile(user: dict = Depends(current_user)):
    return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}


@app.get("/protected/dashboard", tags=["protected"], summary="A second protected route, same guard", responses=E401)
def dashboard(user: dict = Depends(current_user)):
    return {"message": f"Hello {user['email']}, this is your private dashboard."}


@app.post("/auth/logout", status_code=204, tags=["auth"], summary="End this session (Bearer token)", responses=E401)
def logout(request: Request, _user: dict = Depends(current_user), auth: SupabaseAuth = Depends(get_auth)):
    auth.sign_out(request.state.token)
    return Response(status_code=204)


ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}


@app.get("/protected/admin", tags=["protected"], summary="Admins only: 401 if unknown, 403 if not an admin",
         responses={**E401, 403: {"description": "Logged in, but not an admin"}})
def admin_area(user: dict = Depends(current_user)):
    is_admin = user.get("role") == "admin" or (user.get("email") or "").lower() in ADMIN_EMAILS
    if not is_admin:
        return error(403, "Forbidden: admin only")
    return {"message": f"Welcome, admin {user['email']}"}
