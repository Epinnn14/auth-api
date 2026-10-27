"""End-to-end check against the RUNNING server and your real Supabase project.

    uvicorn main:app            # terminal 1
    python scripts/smoke_test.py you+test@gmail.com password123     # terminal 2

Prints every step's status code and body. Tokens are masked, so the output is safe to paste into a README.
"""
import sys

import httpx

BASE = "http://localhost:8000"


def show(label: str, r: httpx.Response, expect) -> None:
    expect = expect if isinstance(expect, tuple) else (expect,)
    body = r.text
    for token in TOKENS:
        body = body.replace(token, token[:12] + "…(masked)")
    mark = "OK " if r.status_code in expect else "!! "
    want = " or ".join(map(str, expect))
    print(f"{mark}{label:<44} → {r.status_code} (expected {want})  {body[:160]}")


TOKENS: list[str] = []


def main() -> None:
    email, password = (sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else (None, None)
    if not email:
        sys.exit("usage: python scripts/smoke_test.py <email> <password>")

    with httpx.Client(base_url=BASE, timeout=30) as c:
        creds = {"email": email, "password": password}
        show("POST /auth/signup", c.post("/auth/signup", json=creds), 201)
        show("POST /auth/signup (missing password)", c.post("/auth/signup", json={"email": email}), 400)
        show("POST /auth/login (wrong password)", c.post("/auth/login", json={**creds, "password": "wrong-" + password}), 401)
        login = c.post("/auth/login", json=creds)
        if login.status_code == 200:
            TOKENS.extend(v for k in ("access_token", "refresh_token") if isinstance(v := login.json().get(k), str))
        show("POST /auth/login", login, 200)
        if login.status_code != 200:
            sys.exit("login failed: fix this first (see the message above)")
        token = login.json()["access_token"]
        auth = {"Authorization": f"Bearer {token}"}
        # change one character in the middle of the signature (the last char can hold only padding bits)
        i = len(token) - 10
        tampered = token[:i] + ("A" if token[i] != "A" else "B") + token[i + 1:]
        show("GET /public/info", c.get("/public/info"), 200)
        show("GET /protected/profile (no token)", c.get("/protected/profile"), 401)
        show("GET /protected/profile (Authorization: abc)", c.get("/protected/profile", headers={"Authorization": "abc"}), 401)
        show("GET /protected/profile (tampered token)", c.get("/protected/profile", headers={"Authorization": f"Bearer {tampered}"}), 401)
        show("GET /protected/profile", c.get("/protected/profile", headers=auth), 200)
        show("GET /protected/dashboard", c.get("/protected/dashboard", headers=auth), 200)
        show("GET /protected/admin (403 unless in ADMIN_EMAILS)", c.get("/protected/admin", headers=auth), (403, 200))
        show("POST /auth/logout", c.post("/auth/logout", headers=auth), 204)


if __name__ == "__main__":
    main()
