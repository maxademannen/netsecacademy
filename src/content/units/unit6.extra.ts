import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "password-reset",
    title: "Password Reset Vulnerabilities",
    summary: "Explore how flawed recovery mechanisms like predictable tokens and Host Header injection lead to account takeover.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "Explain what a password-reset token is standing in for, and why it must be as strong as a password.",
          "Given a reset flow (token format, timing behaviour, or link-building logic), identify the specific weakness — predictable token, user-enumeration timing, or host-header poisoning — and explain the fix.",
        ],
      },
      {
        kind: "intuition",
        title: "A reset token is a temporary spare key",
        body: [
          "Analogy: losing your house key and calling a locksmith who leaves a spare key under a specific rock, then texts you which rock. Anyone who can guess or intercept which rock gets in — no lockpicking required.",
          "A password-reset token is that spare key: possessing it is functionally equivalent to knowing the password, for a limited time. Whoever presents the right token at the reset endpoint can set a new password, no questions asked.",
          "Where the analogy breaks: a physical rock is only visible to someone standing nearby; a token sent over the network can be intercepted, leaked via logs, redirected to the wrong address, or guessed remotely at scale — with no proximity needed.",
        ],
      },
      {
        kind: "prereq",
        title: "Entropy and timing, concretely",
        body: [
          "Entropy = how many possible values an attacker would have to try to guess a secret. A token built from a timestamp (e.g. `base64(1718000000)`) has almost no entropy — if the attacker knows roughly when the reset was requested, there are only a few thousand values to try, not billions.",
          "A cryptographically secure PRNG (pseudo-random number generator) produces values that can't be predicted even if you know the algorithm and prior outputs. `random.randint()` in many languages is NOT this; `crypto.randomBytes()` / `secrets.token_hex()` are designed to be.",
          "Timing side-channel: if checking 'does this email exist?' involves a database lookup that only happens for real accounts, a real account's request takes measurably longer (hashing, lookup, email-send) than a fake one that short-circuits immediately. That millisecond difference is enough to enumerate valid accounts at scale.",
        ],
        code: `Timestamp as token (BAD):
token = base64(current_unix_time)   // e.g. "MTcxODAwMDAwMA=="
→ attacker who knows request was ~09:14-09:16 only needs to try
   each second in that 2-minute window: ~120 guesses, not 2^128.`,
        check: {
          type: "mc",
          q: "Why does `base64(timestamp)` make a weak reset token even though base64 output looks random?",
          options: [
            "Base64 is itself an encryption algorithm that attackers can break",
            "Base64 only encodes the value; it doesn't add any randomness, so the underlying timestamp is still just as guessable",
            "Base64-encoded tokens are too long for URLs",
            "Browsers refuse to send base64 strings in query parameters",
          ],
          answer: 1,
          why: [
            "Base64 is an encoding, not encryption — it's trivially reversible by anyone, with no 'breaking' required.",
            "",
            "Length isn't the issue; browsers happily handle long query strings.",
            "Base64 strings are safe for URLs and are sent constantly in real query parameters.",
          ],
          explain: "Encoding just changes representation, not entropy. If the input (a timestamp) is guessable within a small window, the base64 output is exactly as guessable — an attacker just base64-encodes their guesses too.",
          hints: ["Encoding and encryption are not the same thing — which one can anyone reverse instantly?", "Ask: how many distinct underlying values could the timestamp actually take, given a known rough request time?"],
          ref: "Entropy and timing, concretely",
        },
      },
      {
        kind: "explain",
        title: "Host Header Injection in reset links",
        body: [
          "Many applications build the reset link dynamically instead of hardcoding the domain: `resetLink = \"https://\" + request.Host + \"/reset?token=\" + token`. The `Host` header is meant to tell a server which site a shared IP should serve, but nothing stops a client from setting it to anything.",
          "An attacker submits a reset request for the VICTIM's email address, but sets `Host: attacker-controlled.com` on their own outgoing request. The server still identifies the account by the email in the body, generates a real valid token, and builds the link using the attacker's poisoned Host value.",
          "The victim receives a genuine email from the real sending system, clicks what looks like a normal reset link, and their browser sends the valid token straight to the attacker's server, where it's captured in access logs.",
        ],
        code: `POST /password-reset HTTP/1.1
Host: attacker-controlled.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com

→ server builds: https://attacker-controlled.com/reset?token=abc123
→ emailed to victim@example.com from the real system
→ victim clicks → token lands in attacker-controlled.com's logs`,
        tone: "offense",
        check: {
          type: "fill",
          q: "In the Host Header Injection attack, which HTTP header does the attacker set to a domain they control?",
          answers: ["Host"],
          explain: "The server trusts the client-supplied `Host` header to build a security-sensitive URL (the one the secret token is delivered to), instead of using a hardcoded, server-configured domain.",
          hints: ["It's the header that normally tells a server which website the request is for.", "The attack is literally named after this header."],
          ref: "Host Header Injection in reset links",
        },
      },
      {
        kind: "example",
        title: "Worked example: enumerating accounts via response timing",
        body: [
          "Setup: `shop.example/forgot-password` returns the same generic message either way ('If an account exists, a reset email was sent'), so the response TEXT doesn't leak whether the email is registered. But the developer didn't think about timing.",
          "Step 1: for a registered email, the server hashes a lookup key, queries the database, generates a token, writes it to storage, and queues an email — several operations, taking ~180ms.",
          "Step 2: for an unregistered email, the server's code checks 'does this exist?', finds no match, and returns immediately — taking ~15ms.",
          "Step 3 — attacker's method: send the same request for a list of candidate emails, measuring response time for each. Responses taking ~180ms are registered accounts; ~15ms responses are not — even though the displayed message is identical.",
          "Step 4 — why this matters even with a generic message: user enumeration on its own is a valid finding (it fuels targeted phishing and credential-stuffing lists), and here it exists purely because of an implementation detail (how much work happens before the response), not the response text.",
          "Fix: do equivalent work regardless of outcome — e.g. always perform a dummy hash/lookup operation of similar cost for non-existent emails, so timing is constant.",
        ],
        tone: "offense",
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Assuming a generic response message ('if this account exists...') fully prevents enumeration — it stops MESSAGE-based enumeration but not timing-based enumeration, which depends on how much server work happens before the response is sent.",
          "Treating the reset token as less sensitive than a password because it's 'temporary' — for its entire validity window, it IS the password. Short-lived and single-use are mitigations, not reasons to relax entropy or transport requirements.",
          "Fixing Host-header trust by blocklisting a few known bad domains instead of using a hardcoded or allow-listed server-side base URL — blocklists are always incomplete; the fix is to never let client input determine a security-sensitive URL.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "A site's reset email link is built as `\"https://\" + config.PRIMARY_DOMAIN + \"/reset?t=\" + token`, where `PRIMARY_DOMAIN` is a hardcoded string set by the developers, not read from any request header. An attacker tries sending `Host: evil.example` on their reset request, hoping to poison the link.",
        ],
        check: {
          type: "mc",
          q: "Does this attacker's Host-header attack succeed here, and why?",
          options: [
            "Yes — the Host header always overrides hardcoded domains",
            "No — the link is built from a hardcoded server-side constant, not the client-supplied Host header, so attacker-controlled input never reaches the link",
            "Yes — because reset tokens are always vulnerable to Host header attacks",
            "No — but only because HTTPS encrypts the Host header",
          ],
          answer: 1,
          why: [
            "The Host header has no special power to override application logic; it's the code's choice whether to read it at all.",
            "",
            "Reset tokens aren't inherently vulnerable to this — only implementations that read the Host header when building the link are.",
            "HTTPS encrypts the header in transit, but the server still reads whatever value is inside once decrypted; encryption isn't what stops this attack.",
          ],
          explain: "The vulnerability only exists when the application's code chooses to trust `request.Host` to build a security-sensitive URL. A hardcoded, server-controlled base domain removes the attacker's only lever — their Host header is simply never consulted.",
          hints: ["Where does `PRIMARY_DOMAIN` come from — the request, or the server's own configuration?", "The attack requires the server to USE attacker-controlled input somewhere in the link; check whether that happens here."],
          ref: "Host Header Injection in reset links",
        },
      },
      {
        kind: "relevance",
        title: "What this proves — and doesn't",
        body: [
          "Demonstrating that you captured a real reset token via host-header poisoning, or enumerated a handful of test accounts via timing, in an authorised test, proves the specific mechanism is exploitable — strong, concrete evidence.",
          "It does NOT prove every account is enumerable at scale or that mass account takeover occurred, unless you actually demonstrate that within agreed scope and rate limits.",
          "Only test against your own lab accounts or an explicitly authorised target; never send reset requests for real third-party users' emails outside a sanctioned engagement, and never exfiltrate real users' tokens.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "Why is using `base64(timestamp)` as a reset token dangerous?",
        options: [
          "It is too long for most database fields",
          "It can be predicted or brute-forced because the underlying timestamp has very little entropy",
          "Base64 is an encryption method that is easily cracked",
          "It forces the user to remember the timestamp",
        ],
        answer: 1,
        why: [
          "Length isn't the issue here; databases handle such strings fine.",
          "",
          "Base64 is encoding, not encryption — there's nothing to 'crack', it's instantly reversible.",
          "The token is never shown to the user to remember; it's embedded in a link.",
        ],
        explain: "Timestamps are predictable. If an attacker knows approximately when a reset was requested, they can generate tokens for that narrow time range and hijack the account.",
        hints: ["Think about how much 'entropy' or randomness a timestamp provides.", "If I know you requested a reset 5 minutes ago, how many possibilities are there?"],
        ref: "Entropy and timing, concretely",
      },
      {
        type: "fill",
        q: "To perform a Host Header injection to steal a reset token, which header would you modify in the password reset request?",
        answers: ["Host"],
        explain: "By modifying the `Host` header, you trick the server into generating a link pointing to your own domain, capturing the token when the victim clicks it.",
        hints: ["It's the standard HTTP header that specifies the domain name of the server.", "The name is literally in the description of the attack."],
        ref: "Host Header Injection in reset links",
      },
      {
        type: "order",
        q: "Sequence the steps of a Host Header Injection attack against a password reset flow.",
        items: [
          "Attacker sends a reset request for the victim's email with Host: evil.example",
          "Server generates a valid token and builds a link using the poisoned Host value",
          "Victim receives the email and clicks the link pointing to evil.example",
          "Attacker captures the token from evil.example's access logs",
          "Attacker submits the stolen token on the real site to set a new password",
        ],
        explain: "The attack relies on the server trusting the Host header to build the absolute URL sent to the victim — the attacker starts it, the victim's click delivers the token, and the attacker finishes the takeover on the real site.",
        hints: ["The attacker initiates before the victim does anything.", "The capture of the token happens before the final takeover step."],
        ref: "Host Header Injection in reset links",
      },
      {
        type: "mc",
        q: "A reset endpoint always shows 'If an account exists, we sent an email' regardless of whether the email is registered. Is user enumeration still possible?",
        options: [
          "No — the identical message makes enumeration impossible",
          "Yes — if the server does meaningfully more work (DB lookup, token generation, email queueing) for real accounts than for non-existent ones, response timing can still reveal which is which",
          "No — enumeration requires a different error message, full stop",
          "Yes, but only if the site doesn't use HTTPS",
        ],
        answer: 1,
        why: [
          "Message-based enumeration is blocked, but that's not the only channel — timing is independent of the displayed text.",
          "",
          "A different message is one way to enumerate, not the only way.",
          "HTTPS encrypts content, not the elapsed time between request and response; timing attacks work over HTTPS too.",
        ],
        explain: "Enumeration can happen through any observable difference between the 'exists' and 'doesn't exist' code paths — message text is just the most obvious one. Timing is a side channel that a generic message alone doesn't close.",
        hints: ["Reread the worked example on timing-based enumeration.", "Ask what else differs between the two code paths besides the final text shown."],
        ref: "Worked example: enumerating accounts via response timing",
      },
      {
        type: "fill",
        q: "A function that performs equivalent dummy work for non-existent emails, so that real and fake requests take the same amount of time, defends against ______-based enumeration.",
        answers: ["timing", "timing-based", "time"],
        explain: "Matching response times for 'exists' and 'doesn't exist' cases removes the timing side channel, closing off enumeration that a generic message alone doesn't prevent.",
        hints: ["What was being measured by the attacker in the worked example?", "It's not about the message text."],
        ref: "Worked example: enumerating accounts via response timing",
      },
    ],
  },
  {
    id: "oauth-mfa",
    title: "OAuth & MFA Integration Mistakes",
    summary: "Identify common pitfalls in modern authentication flows, from OAuth redirect leaks to MFA logic bypasses.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "Explain what problem OAuth's `redirect_uri` and `state` parameters each solve, and what breaks when they're missing or weakly validated.",
          "Given a described MFA flow, identify where in the request sequence the second factor is actually enforced (or isn't), and name the resulting bypass.",
        ],
      },
      {
        kind: "intuition",
        title: "OAuth is a bouncer handing out wristbands",
        body: [
          "Analogy: at a festival, you show ID once at the gate, and the bouncer gives you a wristband that gets you into every stage without re-checking ID. OAuth's authorization code is that wristband — proof, issued once by a trusted party, that gets handed around between services.",
          "The redirect_uri is 'which exit booth the bouncer hands the wristband through'. If the bouncer doesn't carefully check that the booth is really the one you arrived with, a stranger standing at a different booth can catch the wristband meant for you.",
          "Where the analogy breaks: a physical wristband can't be copied in transit; an authorization code is just a string in a URL, so if it's delivered to the wrong (attacker's) address, it can be reused immediately before the real user ever gets it.",
        ],
      },
      {
        kind: "prereq",
        title: "The OAuth authorization-code dance, concretely",
        body: [
          "1) The app redirects the user to the OAuth provider (e.g. accounts.example-idp.com) with its own identity (`client_id`) and a `redirect_uri` saying where to send the result.",
          "2) The user logs into the provider and approves access. The provider redirects the browser BACK to `redirect_uri`, appending a short-lived `code` (and ideally the `state` value the app sent in step 1).",
          "3) The app's backend exchanges that `code` (plus a secret only the app knows) for an access token, server-to-server — the code itself is single-use and expires quickly, but is still sensitive while valid.",
          "The `redirect_uri` therefore controls WHERE the sensitive code is delivered, and `state` lets the app verify the callback belongs to a flow IT initiated, not one an attacker started.",
        ],
        code: `GET https://accounts.example-idp.com/authorize
    ?client_id=app123
    &redirect_uri=https://app.example/callback
    &state=f93a... (app-generated, unguessable)

... user approves ...

GET https://app.example/callback?code=xyz789&state=f93a...
→ app checks state matches what IT stored for this browser session
→ app exchanges code=xyz789 for an access token (server-to-server)`,
        check: {
          type: "mc",
          q: "What does the `state` parameter let the application verify when the OAuth callback arrives?",
          options: [
            "That the access token is cryptographically valid",
            "That the callback corresponds to an authorization flow this same browser/session actually started",
            "That the user entered the correct password",
            "That the redirect_uri is on an allow-list",
          ],
          answer: 1,
          why: [
            "Token validity is checked separately, typically via signature verification or introspection, not via `state`.",
            "",
            "Password correctness is the identity provider's job during login, not something `state` checks.",
            "Allow-listing `redirect_uri` is a separate server-side control, unrelated to the `state` value.",
          ],
          explain: "`state` is generated and stored by the app before redirecting the user, then compared on callback. A match proves this specific callback is continuing a flow the app itself started for this session — preventing an attacker from injecting their own authorization result into a victim's session.",
          hints: ["Reread the three-step dance — when is `state` created, and when is it checked?", "Think about what CSRF means in this context: forcing someone to complete someone ELSE's flow."],
          ref: "The OAuth authorization-code dance, concretely",
        },
      },
      {
        kind: "explain",
        title: "Weak redirect_uri validation and MFA logic gaps",
        body: [
          "If a server validates `redirect_uri` with a loose check — e.g. 'starts with https://app.example' — an attacker can register or craft `https://app.example.attacker.com/callback` (different host, same prefix string) or abuse an open redirect within the real app, such as `https://app.example/logout?next=https://attacker.com`, to siphon the authorization code to themselves.",
          "Without a verified `state`, an attacker can start an OAuth flow using THEIR OWN account, capture the resulting callback URL, and trick a victim into visiting it — linking the victim's session to the attacker's identity (login CSRF), which can be used to capture data the victim then enters, thinking they're using their own account.",
          "MFA is typically bolted on AFTER primary login: password check succeeds, then a second request verifies a one-time code. If the server sets any session/cookie indicating 'authenticated' before that second check completes, or if other endpoints don't re-verify MFA status, an attacker who compromises only the password can reach authenticated functionality without ever passing the second factor.",
        ],
        tone: "offense",
      },
      {
        kind: "example",
        title: "Worked example: MFA bypass via endpoint ordering",
        body: [
          "Setup: `app.example` login is: POST /login (password) → sets cookie `pending_mfa=true; user=42` → redirects to /mfa → POST /mfa/verify (code) → on success, sets `authenticated=true`.",
          "Step 1: an attacker who has stolen or guessed the victim's password completes POST /login successfully, receiving the `pending_mfa=true; user=42` cookie — this is set BEFORE the code is verified.",
          "Step 2: the attacker notices `/api/profile` only checks for the presence of a `user` cookie value, not whether `authenticated=true` was ever set — a classic case of one endpoint enforcing MFA and another forgetting to.",
          "Step 3: the attacker requests `/api/profile` directly with the `pending_mfa` cookie, skipping /mfa/verify entirely, and receives the victim's profile data — MFA was bypassed not by breaking the one-time code, but by hitting an endpoint that never checked whether it had been verified.",
          "Lesson: MFA must be enforced by checking authentication state on EVERY sensitive endpoint, not just by gating the UI flow that a legitimate user would normally follow.",
        ],
        tone: "offense",
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Validating `redirect_uri` with `startsWith()` or a regex prefix instead of an exact allow-list match — prefix checks are bypassed by appending attacker-controlled subdomains or paths.",
          "Assuming MFA is 'done' once the login page requires it — if even one API endpoint trusts a pre-MFA cookie, the whole protection can be walked around.",
          "Treating `state` as optional because 'it's just CSRF protection' — login CSRF via a missing `state` can have account-takeover-level consequences, not just a nuisance request.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "An app validates `redirect_uri` by checking `redirect_uri.startsWith(\"https://app.example\")`. An attacker registers the domain `app.example.attacker.com` and uses it as their redirect_uri.",
        ],
        check: {
          type: "fill",
          q: "What type of validation should replace the prefix check to stop this bypass? (one short phrase)",
          answers: ["exact allow-list match", "exact match allow-list", "strict allow-list", "exact string match against an allow-list"],
          explain: "`\"https://app.example.attacker.com\".startsWith(\"https://app.example\")` is true, because string prefix checks don't respect domain boundaries. Only comparing the full redirect_uri against an exact, pre-registered allow-list of complete URLs closes this gap.",
          hints: ["Why does the attacker's domain pass a `startsWith` check at all?", "The fix needs to compare the WHOLE value, not just the beginning."],
          ref: "Weak redirect_uri validation and MFA logic gaps",
        },
      },
      {
        kind: "relevance",
        title: "What this proves — and doesn't",
        body: [
          "In an authorised test, demonstrating that you redirected an authorization code to an attacker-controlled domain, or reached authenticated functionality without completing MFA, proves a concrete auth-flow bypass.",
          "It does NOT prove the identity provider itself is compromised, or that every client of that provider shares the same flaw — each integration must be checked independently.",
          "Only test OAuth and MFA flows on accounts and applications you're authorised to test; never attempt login-CSRF or MFA bypass techniques against real third-party users.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "What is the primary purpose of the `state` parameter in an OAuth 2.0 flow?",
        options: [
          "To remember the user's password",
          "To prove the callback belongs to a flow this app/session actually started, preventing login CSRF",
          "To specify the user's permissions (scopes)",
          "To encrypt the authorization code",
        ],
        answer: 1,
        why: [
          "Passwords are never passed through OAuth parameters like `state`.",
          "",
          "Scopes are requested via a separate `scope` parameter, not `state`.",
          "`state` is an opaque value for verification, not an encryption mechanism for the code.",
        ],
        explain: "The `state` parameter links the initial request to the callback, ensuring that the party who started the login flow is the one finishing it — closing the login-CSRF hole that would otherwise let an attacker link a victim's session to the attacker's identity.",
        hints: ["It prevents an attacker from injecting their own authorization result into someone else's session.", "It's a common defense against session-linking attacks."],
        ref: "The OAuth authorization-code dance, concretely",
      },
      {
        type: "match",
        q: "Match the OAuth/MFA flaw to its consequence.",
        pairs: [
          ["Weak redirect_uri validation (prefix match)", "Authorization code delivered to attacker's domain"],
          ["Missing or unverified state parameter", "Login CSRF / account-linking attack"],
          ["Pre-MFA cookie trusted by other endpoints", "MFA bypass without breaking the second factor"],
        ],
        explain: "Each misconfiguration in the auth flow opens a specific vector: loose URI validation leaks the code, missing state enables CSRF-style flow injection, and endpoints trusting a too-early cookie let MFA be walked around entirely.",
        hints: ["Think about where the code or cookie ends up 'sent' or 'trusted' when each check is missing.", "MFA is a multi-step process; what happens if a later step isn't checked everywhere?"],
        ref: "Weak redirect_uri validation and MFA logic gaps",
      },
      {
        type: "fill",
        q: "In the worked example, the attacker bypassed MFA not by breaking the one-time code, but by hitting an endpoint that never checked the ______ flag.",
        answers: ["authenticated", "authenticated=true", "authenticated cookie"],
        explain: "`/api/profile` only checked for the presence of a `user` cookie, not whether `authenticated=true` had been set after MFA verification — the bypass exploited inconsistent enforcement across endpoints, not the MFA code itself.",
        hints: ["Reread the worked example's step 2 — which cookie was checked, and which wasn't?", "It's the flag that's only supposed to be set AFTER /mfa/verify succeeds."],
        ref: "Worked example: MFA bypass via endpoint ordering",
      },
      {
        type: "mc",
        q: "An app validates redirect_uri with `redirect_uri.startsWith(\"https://app.example\")`. Which redirect_uri would pass this check but should be rejected?",
        options: [
          "https://app.example/callback",
          "https://app.example.attacker.com/callback",
          "https://app.example/oauth/finish",
          "A redirect_uri isn't checked by that function at all",
        ],
        answer: 1,
        why: [
          "This is the legitimate, intended URI and should pass.",
          "",
          "This is a different, legitimate path on the real domain and should also pass.",
          "The `startsWith` function does run on every redirect_uri value passed to it.",
        ],
        explain: "`\"https://app.example.attacker.com/callback\".startsWith(\"https://app.example\")` evaluates to true in plain string comparison, because the attacker's domain simply begins with the same characters — prefix checks don't understand domain boundaries.",
        hints: ["Think purely as a string comparison, not as a URL with structure.", "Which option looks like 'app.example' but is actually a completely different, attacker-owned domain?"],
        ref: "Weak redirect_uri validation and MFA logic gaps",
      },
    ],
  },
  {
    id: "mass-assignment",
    title: "Mass Assignment & API Authorization",
    summary: "Learn how improper mapping of user input to objects and lack of granular checks lead to BOLA and BFLA.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "Explain what mass assignment is and why frameworks that auto-bind JSON fields to database models create risk.",
          "Given an API request or endpoint description, distinguish BOLA (object-level) from BFLA (function-level) authorization failures and identify the specific missing check.",
        ],
      },
      {
        kind: "intuition",
        title: "A form with extra blank lines",
        body: [
          "Analogy: imagine filling out a paper form that only has fields for 'Name' and 'Email', but you staple an extra sheet on top that also says 'Account Type: Administrator'. A careless clerk who files whatever's stapled to the form — without checking which fields were actually supposed to be editable — just promoted you.",
          "Mass assignment is that careless clerk, implemented in code: the server takes the whole JSON body a client sent and writes every key straight onto the internal record, instead of only accepting the specific fields the endpoint is supposed to let users change.",
          "Where the analogy breaks: a physical clerk might notice an oddly stapled extra page; a server blindly mapping JSON keys to object properties has no 'does this look suspicious' instinct unless the developer explicitly coded one.",
        ],
      },
      {
        kind: "prereq",
        title: "How auto-binding frameworks work",
        body: [
          "Many web frameworks offer a convenience: give them a JSON body and a model class, and they automatically create or update an object by matching JSON keys to the model's fields — saving the developer from writing `user.name = body.name; user.email = body.email; ...` by hand for every field.",
          "The convenience becomes a vulnerability when the model has fields the API was never meant to expose for editing — like `role`, `isAdmin`, `accountBalance`, or `verified` — and the auto-binder maps them anyway if they're present in the request body.",
          "The fix is an explicit allow-list (or DTO — Data Transfer Object, a separate, deliberately narrow structure containing only the fields actually meant to be user-editable) so the binder physically cannot see or set anything else.",
        ],
        code: `// Vulnerable: binds the WHOLE body to the User model
PATCH /api/user/profile
{ "display_name": "Alice", "role": "admin" }
→ user.update(request.body)   // role gets set too!

// Fixed: only allow-listed fields are copied
const allowed = { display_name: request.body.display_name };
user.update(allowed);          // role is never touched`,
        check: {
          type: "fill",
          q: "The name for the practice of accepting only a pre-approved, narrow set of fields from user input (instead of binding the whole request body) is an allow-______.",
          answers: ["list", "allowlist", "allow-list"],
          explain: "An allow-list (sometimes called a DTO-based approach) defines exactly which fields are permitted to be set by a given request, regardless of what extra fields the client includes.",
          hints: ["It's the opposite of a 'block-list' or 'deny-list' approach.", "The word completes 'allow-___'."],
          ref: "How auto-binding frameworks work",
        },
      },
      {
        kind: "explain",
        title: "BOLA vs BFLA: which granularity failed",
        body: [
          "BOLA (Broken Object Level Authorization, formerly called IDOR): the user IS allowed to use this endpoint/function in general, but the server fails to check whether THIS SPECIFIC resource belongs to them. Example: `GET /api/orders/1057` returns someone else's order just by changing the ID, with no ownership check.",
          "BFLA (Broken Function Level Authorization): the server fails to check whether the user should be allowed to call this FUNCTION/ENDPOINT at all, regardless of whose data it touches. Example: a regular user successfully calls `POST /api/admin/deleteUser`, because the endpoint only checks 'is there a valid session' and never checks 'is this session an admin'.",
          "Both are authorization failures (the user IS authenticated — the server correctly knows who they are) but at different granularities: BOLA is about WHICH record, BFLA is about WHICH action.",
        ],
      },
      {
        kind: "example",
        title: "Worked example: diagnosing BOLA vs BFLA vs mass assignment",
        body: [
          "Scenario: a fitness-tracker API has `GET /api/workouts/{id}`, `PATCH /api/users/{id}/profile`, and `POST /api/admin/resetAllData`.",
          "Finding 1: user A requests `GET /api/workouts/4471` (which belongs to user B) and receives B's private workout data. The server checked that A was logged in, but never checked that workout 4471 belongs to A. → This is BOLA: a specific resource (one workout record) was accessed without an ownership check.",
          "Finding 2: user A sends `PATCH /api/users/A_id/profile` with body `{ \"bio\": \"hi\", \"subscriptionTier\": \"pro\" }`. The endpoint correctly checks A owns the profile A_id (no BOLA here), but blindly writes every field in the body, including `subscriptionTier`, which should only be settable by the billing system. → This is mass assignment: the right resource, but an unintended FIELD got written.",
          "Finding 3: user A (a regular, non-admin user) successfully calls `POST /api/admin/resetAllData`, and it works — the endpoint only checked that A had a valid session, never checked A's role. → This is BFLA: the function itself should have been restricted to admins, regardless of whose data is involved.",
          "Each finding needs a different fix: Finding 1 needs an ownership check (does workout 4471 belong to the requester?); Finding 2 needs a field allow-list; Finding 3 needs a role check before executing the function.",
        ],
        tone: "offense",
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Assuming fixing BOLA (adding ownership checks) also fixes BFLA — ownership checks answer 'whose data is this', not 'should this user be allowed to call this function at all'. They're independent checks.",
          "Relying on the UI to hide an admin button as the only protection for an admin endpoint — if the backend doesn't independently check the role server-side, anyone who learns or guesses the URL can call it directly, bypassing the UI entirely.",
          "Disabling mass-assignment protection 'temporarily' for convenience during development and forgetting to re-enable field allow-listing before shipping to production.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "An API endpoint `PATCH /api/orders/{id}/status` correctly verifies the requester owns order `{id}` before processing the request. However, it accepts the entire request body and writes it to the order record, including a `refundAmount` field that should only ever be set by the payment-processing service.",
        ],
        check: {
          type: "mc",
          q: "What vulnerability class does this specific flaw belong to — given that ownership is already correctly checked?",
          options: [
            "BOLA, because the order ID could be wrong",
            "BFLA, because a function is being called that shouldn't be",
            "Mass assignment, because an unintended field (refundAmount) is being written from user input",
            "This is not a vulnerability since ownership is verified",
          ],
          answer: 2,
          why: [
            "BOLA is specifically about accessing resources you don't own; ownership is already correctly checked here, so that's not the gap.",
            "",
            "",
            "Owning the right resource doesn't make it safe to write arbitrary fields onto it — the field-level check is still missing.",
          ],
          explain: "Ownership (object-level) is fine here — the bug is that an extra field present in the request body gets written even though it shouldn't be user-settable. That's the defining signature of mass assignment: the right resource, the wrong field.",
          hints: ["The question already tells you ownership is correctly checked — so which granularity is left to consider?", "Think about what specifically gets written that shouldn't be: a whole resource, a whole function, or one unexpected field?"],
          ref: "BOLA vs BFLA: which granularity failed",
        },
      },
      {
        kind: "relevance",
        title: "What this proves — and doesn't",
        body: [
          "In an authorised test, demonstrating you read another user's resource (BOLA), called a restricted function (BFLA), or set an unintended field via mass assignment each proves a specific, concrete authorization gap with a clear fix.",
          "It does NOT prove that all endpoints share the same flaw — each endpoint's object-level, function-level, and field-level checks must be verified independently, since fixing one doesn't fix the others.",
          "Only test against your own lab accounts/resources or an explicitly authorised target's test accounts; never access or modify real third-party users' data to 'prove' impact.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "Which of the following is an example of BFLA (Broken Function Level Authorization)?",
        options: [
          "A user viewing another user's private workout by changing the ID in the URL",
          "A regular user successfully calling the `/api/v1/admin/export_all_users` endpoint",
          "An attacker guessing a weak password-reset token",
          "A user changing their own display name via a normal profile update",
        ],
        answer: 1,
        why: [
          "This is BOLA — the correct function, called about the wrong object/resource.",
          "",
          "That's a different vulnerability class covered in the password-reset lesson, unrelated to function-level authorization.",
          "This is the user's own legitimate data via the function they're supposed to use — no authorization failure here.",
        ],
        explain: "BFLA occurs when a user reaches a restricted FUNCTION (like an admin export) because the server failed to check their role for that specific action, regardless of whose data is involved.",
        hints: ["BOLA is about 'objects' (data), BFLA is about 'functions' (actions).", "Which option involves an administrative action rather than a specific record?"],
        ref: "BOLA vs BFLA: which granularity failed",
      },
      {
        type: "fill",
        q: "An attacker sends a request to update their profile and includes `\"isAdmin\": true`, which the server naively writes to the database. This attack is known as ______ assignment.",
        answers: ["mass"],
        explain: "Mass assignment (or overposting) happens when the application blindly maps all input keys to the underlying data model instead of restricting writes to an allow-listed set of fields.",
        hints: ["It refers to assigning many values at once, without filtering which ones are allowed.", "It starts with 'm'."],
        ref: "How auto-binding frameworks work",
      },
      {
        type: "match",
        q: "Match the vulnerability to the check that would have prevented it.",
        pairs: [
          ["BOLA", "Verify the requester owns resource ID 555"],
          ["BFLA", "Verify the requester has the Admin role before running the function"],
          ["Mass Assignment", "Only allow the 'bio' and 'email' fields to be written"],
        ],
        explain: "Prevention requires specific, independent checks: ownership for BOLA, role verification for BFLA, and field allow-lists for mass assignment — none of these substitutes for the others.",
        hints: ["BOLA is about specific instances of data — what would confirm it's YOUR instance?", "Mass assignment is about which fields get written, not who owns the record."],
        ref: "BOLA vs BFLA: which granularity failed",
      },
      {
        type: "mc",
        q: "An endpoint correctly checks a user owns the order they're updating, and also correctly checks the user isn't trying to call an admin-only function. But it still writes every field from the request body to the order, including an internal `discountOverride` field. What's still missing?",
        options: [
          "An object-level (BOLA) check",
          "A function-level (BFLA) check",
          "A field-level allow-list to prevent mass assignment",
          "Nothing — this is fully secure now",
        ],
        answer: 2,
        why: [
          "Ownership is already stated as correctly checked in the scenario.",
          "Function-level access is already stated as correctly checked in the scenario.",
          "",
          "Two of the three granularities are covered, but field-level control over what gets written is still missing — leaving mass assignment open.",
        ],
        explain: "BOLA, BFLA, and mass assignment are three independent checks at three different granularities (resource, function, and field). Fixing two of them does not automatically fix the third.",
        hints: ["Re-examine what's being written to the record versus who's writing it.", "Three separate granularities were taught in this lesson — which one hasn't been addressed yet?"],
        ref: "Worked example: diagnosing BOLA vs BFLA vs mass assignment",
      },
    ],
  },
  {
    id: "logic-flaws",
    title: "Business Logic Flaws",
    summary: "Identify vulnerabilities in application logic that allow users to bypass workflows or manipulate business rules.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "Explain the difference between input validation (is this technically well-formed?) and business logic (does this violate the rules the feature was designed to enforce?).",
          "Given a multi-step workflow or a calculation involving user-controlled values, identify where an attacker could violate an intended business rule even while submitting technically valid input.",
        ],
      },
      {
        kind: "intuition",
        title: "Following the letter of the rule, not the spirit",
        body: [
          "Analogy: a vending machine's sign says 'insert a $1 coin to get a snack'. A clever person discovers that a certain washer from a hardware store is the exact size and weight of a $1 coin and fools the machine's sensor. The machine's INPUT VALIDATION (is this coin-shaped and the right weight?) passed — but the business rule it was meant to enforce ('only paying customers get snacks') was violated.",
          "Business logic flaws work the same way: the application's technical checks (is this a number? is this field required? is this within a type's valid range?) all pass, but the sequence of actions or combination of values breaks a rule the feature was actually designed to enforce.",
          "Where the analogy breaks: a vending machine has one sensor to fool; a real application has many interacting steps (cart, discount, shipping, payment), and logic flaws often emerge from the INTERACTION between features that were each individually tested but never tested together.",
        ],
      },
      {
        kind: "prereq",
        title: "Where logic flaws hide: state and sequence",
        body: [
          "Most web features assume a sequence: Step 1 (add items) → Step 2 (apply discount) → Step 3 (pay) → Step 4 (confirm). The server is supposed to track which step a given order/session has actually reached — its 'state' — and refuse to let a client jump ahead.",
          "A workflow-bypass flaw exists when the server does NOT track that state, and instead trusts the client to visit pages/call endpoints 'in the right order' — meaning nothing stops a client from calling Step 4's endpoint directly, skipping Step 3 entirely.",
          "A race condition (specifically TOCTOU — Time-Of-Check to Time-Of-Use) is a different kind of state problem: the server checks a condition ('is balance ≥ $50?'), but between that CHECK and the later USE (actually deducting $50), the balance can change — e.g. because a second, simultaneous request performed the same check before either deduction happened.",
        ],
        code: `Thread A: check balance ($100) -> OK, balance >= $50
Thread B: check balance ($100) -> OK, balance >= $50   (runs before A deducts)
Thread A: deduct $50 -> balance now $50
Thread B: deduct $50 -> balance now $0
Result: two $50 withdrawals succeeded against a $100 balance that
        should only have allowed one.`,
        check: {
          type: "mc",
          q: "In the TOCTOU diagram, why do both withdrawals succeed even though the account only had enough balance for one?",
          options: [
            "The server used the wrong currency symbol",
            "Both requests checked the balance before either request's deduction had been applied, so each check independently saw the full $100",
            "The database crashed during the second request",
            "HTTPS allowed both requests to be read by each other",
          ],
          answer: 1,
          why: [
            "Currency formatting is irrelevant to the vulnerability.",
            "",
            "Nothing in the scenario involves a crash — both requests complete successfully, which is exactly the problem.",
            "HTTPS encrypts transport; it doesn't let requests see each other's internal state.",
          ],
          explain: "The flaw is in the ORDERING: both requests perform their 'check balance' step before either performs its 'deduct balance' step, so neither sees the other's effect. The fix is to make check-and-deduct a single atomic operation (e.g. a database transaction with locking), not two separate steps that can interleave.",
          hints: ["Look at which operation happens first for BOTH threads, before either thread's second operation runs.", "The bug isn't about the math — it's about timing and ordering of two separate steps."],
          ref: "Where logic flaws hide: state and sequence",
        },
      },
      {
        kind: "example",
        title: "Worked example: negative-quantity discount abuse",
        body: [
          "Setup: `shop.example`'s cart totals items as `total = sum(price * quantity)` for each line item, and then applies a 10% site-wide discount coupon to the total. The quantity field accepts any integer and passes normal input validation (it IS a valid integer).",
          "Step 1: attacker adds a $500 item (quantity 1) and a $5 item (quantity 1) to the cart. Total so far: $505.",
          "Step 2: attacker edits the $5 item's quantity to -100 (a negative number, still a technically valid integer). New line total: $5 * -100 = -$500. Cart total: $500 + (-$500) = $5.",
          "Step 3: attacker applies the 10% discount coupon, intended to shave a modest amount off a real purchase. 10% of $5 = $0.50 off, bringing the total to $4.50 — meanwhile the attacker still receives the $500 item in their order, because the quantity field doesn't correspond to anything physically shipped for a negative value, yet the system doesn't reject it.",
          "Root cause: input validation confirmed quantity was 'a number' but never enforced the BUSINESS RULE that quantity must be a positive integer within a sane range for a real order — the type-check and the business-rule-check are two different, independent things.",
          "Fix: validate quantity > 0 (and within a reasonable per-item maximum) as a distinct business-rule check, separate from and in addition to 'is this a valid integer'.",
        ],
        code: `POST /cart/update
{ "itemId": "sku-005", "quantity": -100 }
→ passes type validation: quantity is an integer ✓
→ fails (should fail) business rule: quantity must be > 0 ✗ (not enforced!)
→ line total: $5 * -100 = -$500`,
        tone: "offense",
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Treating 'input validation passed' as equivalent to 'this request is legitimate' — type, format, and range checks on a SINGLE field say nothing about whether the COMBINATION of fields or the SEQUENCE of requests violates an intended business rule.",
          "Hiding a workflow step only in the UI (e.g. disabling a 'Confirm' button until payment is shown as complete) without the server independently verifying that the previous step actually happened — client-side sequencing is not enforcement.",
          "Assuming a 'check-then-act' pattern is safe because it 'usually' runs fast enough that no second request could interleave — under real concurrent load, race windows that seem negligibly small are exploitable by deliberately firing simultaneous requests.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "A multi-page registration flow is: Step 1 `/register/details` (collect name/email) → Step 2 `/register/payment` (collect card, charge $10 signup fee) → Step 3 `/register/complete` (create the account). The server does not record which step a given registration session has reached; each page is just a separate HTML form that posts to the next URL.",
        ],
        check: {
          type: "fill",
          q: "What is the name for the flaw where an attacker can navigate directly to `/register/complete` and skip the payment step? (two words, hyphen optional)",
          answers: ["workflow bypass", "workflow-bypass", "logic bypass"],
          explain: "Because the server never tracks and verifies which step a session has actually completed, nothing stops a client from calling a later step's endpoint directly — skipping payment entirely while still ending up with a created account.",
          hints: ["The flaw's name describes skipping steps in a multi-step process.", "It was introduced in the prereq card discussing state and sequence."],
          ref: "Where logic flaws hide: state and sequence",
        },
      },
      {
        kind: "relevance",
        title: "What this proves — and doesn't",
        body: [
          "In an authorised test, demonstrating a successful workflow bypass, a discount/quantity manipulation that changes a real charged amount, or a reproducible race condition proves a concrete business-rule violation with measurable impact.",
          "It does NOT prove the flaw is exploitable at the scale needed to cause real financial loss, or that other, similar-looking workflows share the same bug — each must be independently verified.",
          "Only test against sandbox/test accounts and payment methods explicitly provided for testing; never execute logic-flaw techniques (negative quantities, race conditions, workflow skipping) against production systems with real money or real users without explicit authorisation.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "An attacker sets a cart item's quantity to -99, technically a valid integer, to manipulate the total price. What category of flaw are they exploiting?",
        options: [
          "Cross-Site Scripting (XSS)",
          "SQL Injection",
          "A business logic flaw — the server validated the TYPE of the input but not the business RULE that quantity must be positive",
          "Buffer Overflow",
        ],
        answer: 2,
        why: [
          "No script injection or execution is involved here.",
          "No database query manipulation is involved.",
          "",
          "This isn't a memory-safety bug; the server simply never enforced a business rule beyond type-checking.",
        ],
        explain: "The negative quantity passes type validation (it IS a valid integer) but violates the unstated business rule that quantities should be positive — manipulating the price calculation as a result.",
        hints: ["Think about how the price is calculated: price * quantity.", "What happens to that calculation if quantity is negative?"],
        ref: "Worked example: negative-quantity discount abuse",
      },
      {
        type: "order",
        q: "Order the steps of exploiting a workflow bypass in a multi-page registration flow.",
        items: [
          "Attacker starts at Step 1 (account details) to establish a session",
          "Attacker observes or guesses the URL for the final step (e.g. /register/complete)",
          "Attacker skips Step 2 (payment) by navigating directly to the final-step URL",
          "Attacker checks whether the account was created without payment ever being charged",
        ],
        explain: "Workflow bypasses involve starting a flow normally enough to get a valid session, then jumping directly to a later endpoint that the server doesn't verify was reached through the proper sequence.",
        hints: ["You generally need a valid session before you can usefully call a later-step endpoint.", "The final check confirms the bypass actually worked — the account exists without payment."],
        ref: "Where logic flaws hide: state and sequence",
      },
      {
        type: "fill",
        q: "The vulnerability where a condition is checked and then acted upon in two separate, non-atomic steps, allowing state to change in between, is abbreviated as ______.",
        answers: ["TOCTOU"],
        explain: "TOCTOU stands for Time-Of-Check to Time-Of-Use. It's a common source of race conditions, including the double-withdrawal example worked through in this lesson.",
        hints: ["Time-Of-Check To ...", "It's a 6-letter acronym."],
        ref: "Where logic flaws hide: state and sequence",
      },
      {
        type: "mc",
        q: "Why doesn't passing standard input validation (e.g. 'quantity must be an integer') guarantee a request is business-logic-safe?",
        options: [
          "Input validation and business logic enforcement are two independent checks; validation confirms FORMAT, while business rules (like 'must be positive', 'must follow this sequence') need their own separate checks",
          "Input validation is always sufficient and this scenario cannot occur in practice",
          "Business logic only matters for SQL databases",
          "Input validation and business logic are the same thing, just named differently",
        ],
        answer: 0,
        why: [
          "",
          "This is exactly the dangerous assumption the lesson warns against, and the negative-quantity example demonstrates it's very much possible.",
          "Business logic applies regardless of database technology used.",
          "They're explicitly distinct: one confirms shape/type, the other confirms adherence to the feature's intended rules.",
        ],
        explain: "A value can be perfectly well-formed (a valid integer, a valid email, correct length) while still violating a business rule the developer never explicitly coded a check for, like 'quantity must be positive' or 'this step can't be reached before payment'.",
        hints: ["Reread the vending-machine analogy — what passed, and what rule did it still violate?", "Think about the two separate questions: 'is this input the right TYPE' versus 'does this input make business sense'."],
        ref: "Where logic flaws hide: state and sequence",
      },
    ],
  },
];
