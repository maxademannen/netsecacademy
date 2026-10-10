import type { Unit } from "../types";

const unit4: Unit = {
  id: "web-fundamentals",
  index: 4,
  title: "HTTP & Web Fundamentals",
  tagline: "The protocol you'll spend 80% of your bug-bounty career inside.",
  tone: "offense",
  lessons: [
    {
      id: "http-anatomy",
      title: "Anatomy of a request",
      summary: "The request/response model: what the browser sends, what the server answers, and why every byte of the request is attacker-controlled.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can take a raw HTTP request/response pair and point to each part (method, path, headers, cookie, body, status code), say whether the client or the server controls it, and explain why that distinction matters for testing.",
          ],
        },
        {
          kind: "intuition",
          title: "A letter, not a phone call",
          body: [
            "Think of HTTP like exchanging paper letters rather than a phone call. The browser writes a letter (the *request*): 'please GET me /products/42', signs it, and posts it. The server reads the letter, does some work, and mails back a reply letter (the *response*): 'here is the page, status 200 OK'.",
            "Crucially, the server has no memory of previous letters unless the sender includes a reference number in each new letter — HTTP itself is **stateless**: every request is handled as if it's the first one ever sent. That's the problem cookies and sessions exist to solve (next lesson).",
            "Where the analogy breaks: a real letter can't be forged to look like it came from someone else without effort, but an HTTP request can be typed by hand in a tool like Burp Repeater or curl. There is no envelope guaranteeing who really sent it — anything in the letter is just claims, not proof.",
          ],
        },
        {
          kind: "prereq",
          title: "Client, server, and 'stateless'",
          body: [
            "**Client** — the program making the request: usually a browser, but also curl, a mobile app, or an attacker's script. **Server** — the program listening on a port (see Unit 1) that reads the request and decides what to send back.",
            "**Stateless** means the server, by default, treats each request independently — it doesn't remember you clicked 'login' five seconds ago unless something in the new request reminds it (a cookie, a token). Keep this word in mind; it's why cookies exist.",
            "If you haven't done Unit 1's networking lessons yet: a 'connection' here rides on top of a TCP connection to a port (commonly 443 for HTTPS, 80 for HTTP). HTTP is the *language* spoken once that pipe is open.",
          ],
        },
        {
          kind: "explain",
          title: "The parts of a request",
          body: [
            "Every HTTP request has: a **method** (what action: GET, POST, PUT, DELETE...), a **path** (which resource: /api/v2/orders), optional **query string** (?id=42), **headers** (key: value metadata), and an optional **body** (data, often JSON or form-encoded).",
            "Methods carry a meaning the server is *supposed* to enforce but often doesn't: GET should only read data (no side effects) and is cacheable and logged in plaintext (including the query string) by proxies and servers; POST/PUT/DELETE are meant to change data and aren't normally cached or logged the same way.",
            "Because the server rarely double-checks that a GET truly has no side effects, testers routinely try flipping POST → GET or GET → PUT on an endpoint to see if undocumented behaviour appears.",
          ],
          code: `POST /api/v2/orders HTTP/1.1
Host: shop.example
Cookie: session=eyJ1aWQiOjQyfQ...
Content-Type: application/json
Content-Length: 42
X-Forwarded-For: 192.0.2.10

{"item":"book","qty":1,"price":29.00}

<- method: POST   path: /api/v2/orders
<- every header and the body are values the CLIENT chose; the
   server receives them as untrusted input, same as a form field.`,
          check: {
            type: "mc",
            q: "In the request above, which part(s) does the attacker (the client) fully control before the request leaves their machine?",
            options: [
              "Only the body",
              "Only the headers",
              "Method, path, every header, and the body",
              "Nothing — the server assigns these",
            ],
            answer: 2,
            why: [
              "The headers and method are just as editable as the body — there's no part of the request the client can't change before sending it.",
              "The method, path and body are equally editable — headers aren't special.",
              "",
              "The server only sees what the client sent; it didn't assign any of this.",
            ],
            explain: "A request is a single message the client composed end-to-end. Tools like Burp Repeater exist precisely because every line — method, path, headers, cookie, body — can be rewritten before the server ever sees it.",
            hints: [
              "Who built the raw bytes that get sent over the TCP connection?",
              "The server hasn't processed anything yet when the request is 'in flight'.",
            ],
          },
        },
        {
          kind: "explain",
          title: "The parts of a response, and headers worth remembering",
          body: [
            "The response mirrors the request's shape: a **status code** (3-digit number summarising the outcome), **headers**, and an optional **body**. Status code ranges have fixed meanings: 2xx success, 3xx redirect, 4xx client made a bad request (401 = not authenticated, 403 = authenticated but not allowed, 404 = not found), 5xx server-side error.",
            "Headers worth remembering on the request side: **Host** — which virtual site on a shared server should handle this (changing it can reveal cache poisoning or SSRF bugs). **Cookie** — session/tracking/auth data sent back on every request (next lesson). **Authorization** — Basic/Bearer/Digest credentials; Bearer is often a JWT (Unit 6). **X-Forwarded-For / X-Real-IP / X-Original-URL** — hints some servers wrongly trust for access-control decisions, because they assume only a trusted proxy sets them. **Content-Type** — tells the server how to parse the body (application/json vs application/x-www-form-urlencoded vs multipart); switching it sometimes makes two different parsers disagree about the same bytes.",
          ],
          code: `HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error":"admins only"}

-- add a header the server shouldn't trust, resend --

GET /admin HTTP/1.1
Host: shop.example
X-Forwarded-For: 127.0.0.1

HTTP/1.1 200 OK     <- the server trusted a client-supplied header`,
        },
        {
          kind: "example",
          title: "Worked example: reading a login exchange",
          body: [
            "Request: a client POSTs credentials to /login. Response: the server answers 302 (redirect) with a cookie.",
            "Step 1 — identify the method and path: POST /login, so this is meant to change state (create a logged-in session), not just read something.",
            "Step 2 — read Content-Type: application/x-www-form-urlencoded, so the body `u=alice&p=hunter2` is parsed as form fields, not JSON.",
            "Step 3 — read the response status: 302 Found with Location: /dashboard means 'this succeeded, now go here'; a 401 would have meant the credentials were rejected.",
            "Step 4 — read Set-Cookie: session=eyJ1aWQiOjEwMDF9.sig. The server is handing the stateless client a token to prove, on every future request, 'I am the user who just logged in' — this is exactly the problem flagged in the prereq card.",
            "Why each step matters: testers read responses in this order (status -> headers -> body) because the status code tells you whether to even bother reading further, and Set-Cookie headers are where session state is born.",
          ],
          code: `POST /login HTTP/1.1
Host: shop.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

u=alice&p=hunter2

HTTP/1.1 302 Found
Set-Cookie: session=eyJ1aWQiOjEwMDF9.sig; HttpOnly; Path=/
Location: /dashboard`,
          check: {
            type: "fill",
            q: "In the exchange above, what status code tells you the login attempt did NOT fail?",
            answers: ["302", "302 found", "302 Found"],
            explain: "302 Found is a redirect, used here to mean 'success, go to /dashboard'. A failed login would typically return 401 Unauthorized or a 200 with an error message in the body — the status code alone doesn't guarantee which, so always check both.",
            hints: ["Look at the first line of the response.", "It's in the 3xx (redirect) range, not 2xx or 4xx."],
          },
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: assuming GET requests are always safe to repeat endlessly because 'GET is read-only'. The HTTP spec says it *should* be, but a sloppy server can still delete data on a GET — the convention is not a guarantee.",
            "Mistake: assuming a 403 response means the resource doesn't exist. 403 means the server recognised the request but refused it — a 404 is what 'doesn't exist' usually looks like. Confusing these wastes time.",
            "Mistake: assuming a header the client sent (like X-Forwarded-For) must be trustworthy because 'it looks internal-only'. Any header without server-side enforcement (e.g. stripped/overwritten at a trusted proxy) is just a client claim.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice: diagnose this exchange",
          body: [
            "A tester sends `GET /api/profile` with no Authorization header and gets back `401 Unauthorized`. They then add `Authorization: Bearer <stolen-looking-token>` and get `200 OK` with someone else's data.",
            "Work out: did this prove a bug in authentication, or something else? Use the status-code meanings from the explain card above.",
          ],
          check: {
            type: "mc",
            q: "What does the 401 -> 200 transition by itself tell you?",
            options: [
              "Nothing — 401 and 200 are unrelated codes",
              "The server requires *some* bearer token to respond, and the token supplied was accepted as valid for a request",
              "The server is broken and can't be used for anything",
              "The endpoint only works with GET",
            ],
            answer: 1,
            why: [
              "The codes are directly related: 401 means 'you must authenticate', 200 means 'you did, and here's data'.",
              "",
              "A working endpoint with an auth check is normal, not evidence of general brokenness.",
              "Method wasn't varied in this exchange, so nothing about GET specifically was tested.",
            ],
            explain: "This only confirms the endpoint checks authentication (401 without a token). Whether the returned data *should* belong to this caller is a separate question — authorisation, not authentication — covered before IDOR in the 'Access control' lesson.",
            hints: [
              "401 is about identity, not permission.",
              "Does getting data back tell you the data is YOURS, or just that SOME valid-looking credential was accepted?",
            ],
          },
        },
        {
          kind: "relevance",
          title: "What reading a request/response proves — and doesn't",
          body: [
            "Reading and replaying a request (e.g. in Burp Repeater) lets you confirm exactly what the server does with a given set of bytes — that's solid, reproducible evidence for a report.",
            "It does NOT by itself prove a vulnerability: getting a 200 response proves the server accepted the request, not that the data returned is sensitive, that the behaviour is unintended, or that it's within your authorised scope. Always check scope and confirm impact before reporting.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          ref: "The parts of a request",
          q: "An endpoint rejects your request with 403. You add `X-Forwarded-For: 127.0.0.1` and it returns 200. What's the most likely explanation?",
          options: [
            "The server trusts a client-supplied header and now treats you as an internal/trusted caller",
            "Your real IP address changed",
            "The server restarted",
            "It's a coincidence unrelated to the header",
          ],
          answer: 0,
          why: [
            "This is the classic pattern: an app gates access with 'if X-Forwarded-For looks internal, allow it', forgetting that header is just client-supplied text.",
            "Adding a header can't change your network-level source IP.",
            "A restart wouldn't correlate with the exact header you added.",
            "The correlation (change header -> status flips) is too precise to be coincidence; that's why testers isolate one variable at a time.",
          ],
          explain: "Many apps gate sensitive paths behind 'if X-Forwarded-For == 127.0.0.1 or an RFC1918 address, treat as internal'. Unless a trusted reverse proxy strips/overwrites that header, the client can set it to anything.",
          hints: [
            "Which part of the request did you change, and who normally sets that header in a real deployment?",
            "Think about what a reverse proxy is supposed to do with this header before trusting it.",
          ],
        },
        {
          type: "match",
          ref: "The parts of a response, and headers worth remembering",
          q: "Match each header to the risk it most often enables when misused.",
          pairs: [
            ["Host", "Cache poisoning / password-reset link poisoning"],
            ["X-Original-URL", "Access-control bypass via alternate routing path"],
            ["Content-Type", "Parser confusion between JSON/form/XML handling"],
            ["Authorization", "Credential or token manipulation"],
          ],
          explain: "Each of these headers has a well-known failure mode because some framework somewhere trusts it more than it should. Recognising the header tells you which bug family to test for first.",
          hints: [
            "Host controls which virtual site handles the request — think about what gets built FROM its value (like reset links).",
            "X-Original-URL is sometimes used by frameworks to override routing.",
          ],
        },
        {
          type: "fill",
          ref: "The parts of a response, and headers worth remembering",
          q: "What 3-digit HTTP status code means 'the server understood who you are, but you are not allowed to access this resource'?",
          answers: ["403"],
          explain: "403 Forbidden = authenticated (or not required) but not permitted. 401 Unauthorized is the one that actually means 'you haven't proven who you are'.",
          hints: ["It's in the 4xx range.", "It's not the one that means 'log in first'."],
        },
        {
          type: "mc",
          ref: "Worked example: reading a login exchange",
          q: "You replay the login request from the worked example but change the Content-Type header to application/json while leaving the body as `u=alice&p=hunter2` (not valid JSON). What's the most likely result?",
          options: [
            "It will work identically, because the server ignores Content-Type",
            "The server will likely fail to parse the body as JSON and reject or mishandle the request",
            "It will always escalate your privileges",
            "It will delete the user account",
          ],
          answer: 1,
          why: [
            "Content-Type tells the server which parser to use; most frameworks don't ignore it.",
            "",
            "Nothing in this exchange involves privileges.",
            "Nothing about a parse mismatch implies deletion.",
          ],
          explain: "Content-Type tells the server which parser to invoke. Form-encoded text fed into a JSON parser is invalid JSON and will typically be rejected or parsed as an empty/garbage object — this is exactly the kind of mismatch testers exploit on purpose when they suspect two different code paths disagree about the body format.",
          hints: [
            "Re-read the 'Content-Type' explanation card.",
            "Is `u=alice&p=hunter2` valid JSON syntax?",
          ],
        },
        {
          type: "order",
          ref: "What reading a request/response proves — and doesn't",
          q: "Order the steps a tester takes to responsibly confirm a suspicious 200 OK response is actually a bug, not expected behaviour.",
          items: [
            "Note the exact request and response that looked suspicious",
            "Check whether the target/scope authorises this kind of testing",
            "Reproduce the result with a minimal, repeatable request",
            "Determine whether the data/action returned should legitimately be available to this caller",
          ],
          explain: "Observation alone isn't proof. You confirm scope first (don't escalate testing you're not authorised for), then make the finding reproducible, then reason about whether the behaviour is actually wrong before calling it a vulnerability.",
          hints: [
            "Scope should be settled before you do anything further with a finding.",
            "Reproducibility comes before judging impact.",
          ],
        },
      ],
    },
    {
      id: "cookies-sessions",
      title: "Cookies, sessions, same-origin",
      summary: "How a stateless protocol remembers who you are, how that memory is scoped between sites, and how CORS carefully punches holes in that scoping.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can explain how a session cookie keeps a stateless protocol feeling 'logged in', read a Set-Cookie line and say what each attribute protects against, and judge whether a given CORS response header combination is safe or dangerous.",
          ],
        },
        {
          kind: "intuition",
          title: "A wristband at a festival",
          body: [
            "The previous lesson established HTTP is stateless — the server forgets you between requests. A **cookie** is like a wristband a festival gives you at the door: once stamped, you wave it at every stall (every request) instead of showing ID again each time.",
            "A **session** is the stall-keeper's side of the deal: a record, kept on the server, saying 'wristband #4821 belongs to Alice, logged in at 10:02am'. The cookie is just the ticket number; the actual account details live server-side.",
            "Where the analogy breaks: a wristband is physically hard to copy. A cookie is just a string of text — if it leaks (stolen over Wi-Fi, read by malicious JavaScript, guessed because it's predictable), whoever holds that string IS you, as far as the server can tell.",
          ],
        },
        {
          kind: "prereq",
          title: "Origin, and why 'same site' needs a precise definition",
          body: [
            "An **origin** = scheme + host + port, e.g. `https://shop.example:443`. Change any one of those three and you get a *different* origin: `http://shop.example` (different scheme), `shop.example:8080` (different port), and `api.shop.example` (different host, since it's a different subdomain) are all distinct origins from `https://shop.example`.",
            "This matters because the browser's **same-origin policy (SOP)** is the default rule that JavaScript running on one origin cannot read responses from a different origin. Without this rule, any website you visit could silently read your inbox on another tab's site using your logged-in cookies.",
          ],
        },
        {
          kind: "explain",
          title: "Cookie attributes",
          body: [
            "**Secure** — the cookie is only ever sent over HTTPS. Missing it means the cookie can be read by anyone sniffing unencrypted Wi-Fi traffic.",
            "**HttpOnly** — JavaScript (`document.cookie`) cannot read this cookie at all. Missing it means a successful XSS attack (Unit 5) can steal the session outright.",
            "**SameSite** — controls whether the cookie is sent on requests that originate from another site: `Strict` (never cross-site), `Lax` (sent on top-level navigation like clicking a link, not on background requests), `None` (always sent cross-site — requires Secure). Missing or `None` without other protections opens the door to CSRF (a different site tricking your browser into making a request *with* your cookie attached).",
            "**Domain / Path** — scoping. A cookie set with `Domain=.example.com` is sent to every subdomain. If an unused subdomain gets taken over (a 'subdomain takeover'), that attacker-controlled subdomain can read the shared cookie.",
          ],
          code: `Set-Cookie: session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
             ^ reasonable defaults for a session cookie

Set-Cookie: tracking=xyz; Domain=.example.com
             ^ sent to EVERY subdomain of example.com, including
               ones that don't exist yet`,
          check: {
            type: "mc",
            q: "A session cookie is set with no HttpOnly flag. An attacker finds a way to run their own JavaScript in the page (XSS, Unit 5). What can they now do that HttpOnly would have prevented?",
            options: [
              "Nothing — HttpOnly only affects HTTPS",
              "Read the cookie value directly via document.cookie and send it to themselves",
              "Change the Secure flag remotely",
              "Delete the user's account directly",
            ],
            answer: 1,
            why: [
              "HttpOnly is unrelated to the transport (HTTPS); Secure handles that.",
              "",
              "The Secure flag is set by the server and can't be flipped by page JavaScript.",
              "That would require a separate action, not simply reading a cookie.",
            ],
            explain: "HttpOnly's entire purpose is to make a cookie invisible to JavaScript running in the page, so that even if an attacker achieves script execution (XSS), they can't directly exfiltrate the session cookie through document.cookie.",
            hints: ["Re-read what HttpOnly specifically blocks.", "Think about what document.cookie normally returns."],
          },
        },
        {
          kind: "explain",
          title: "CORS: carefully letting an exception through SOP",
          body: [
            "Sometimes site A legitimately needs to call an API on site B from JavaScript (e.g. a dashboard at app.example calling api.example). **CORS (Cross-Origin Resource Sharing)** is the mechanism by which site B's server explicitly tells the browser 'this other origin is allowed to read my response'.",
            "The server does this with the `Access-Control-Allow-Origin` (ACAO) response header, naming which origin(s) may read the response. If the server also wants to allow the request to carry cookies, it must add `Access-Control-Allow-Credentials: true`.",
            "The dangerous misconfiguration: a server that reflects *whatever* Origin header the request sent back into ACAO (instead of checking it against an allow-list), combined with `Access-Control-Allow-Credentials: true`. That combination means literally any website can make the victim's browser fetch data from the API *with the victim's cookies attached*, and read the response — because the browser is told 'yes, this origin is allowed, and yes, send credentials'.",
          ],
          code: `GET /api/me HTTP/1.1
Host: shop.example
Origin: https://attacker.example
Cookie: session=abc

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.example   <- reflected, not checked
Access-Control-Allow-Credentials: true
{"email":"alice@shop.example"}`,
        },
        {
          kind: "example",
          title: "Worked example: is this ACAO safe?",
          body: [
            "You send the request below twice, once with `Origin: https://attacker.example` and once with `Origin: https://partner.example`, and get back the same `Access-Control-Allow-Origin` value both times — exactly whatever you sent as Origin.",
            "Step 1 — is ACAO checked against an allow-list, or does it mirror the request? Since it equals your Origin both times, it's being reflected unconditionally.",
            "Step 2 — is `Access-Control-Allow-Credentials: true` present? If yes, the browser will send cookies with the cross-origin request AND let the calling page read the response.",
            "Step 3 — conclusion: this is the dangerous combination from the explain card. Any site on the internet, including one an attacker controls, can have a logged-in victim's browser fetch `/api/me` and read the result.",
            "Why this matters more than a 'safe' CORS setup: a server that only ever returns `Access-Control-Allow-Origin: https://partner.example` (a fixed, hardcoded value, never reflecting the request) is safe — only that one named origin can read the response, and the server chose it, not the requester.",
          ],
          code: `# test 1
Origin: https://attacker.example
-> Access-Control-Allow-Origin: https://attacker.example

# test 2
Origin: https://partner.example
-> Access-Control-Allow-Origin: https://partner.example

# conclusion: ACAO mirrors Origin verbatim -> reflected, not allow-listed`,
          check: {
            type: "fill",
            q: "Name the second response header (besides Access-Control-Allow-Origin) that must ALSO be present for the reflected-origin CORS bug to let an attacker read a victim's authenticated data.",
            answers: ["access-control-allow-credentials", "access-control-allow-credentials: true", "allow-credentials"],
            explain: "Without Access-Control-Allow-Credentials: true, the browser would still fetch the response if ACAO matched, but it would NOT attach the victim's cookies to the cross-origin request — so the attacker would only see an unauthenticated, logged-out response, which is far less useful.",
            hints: ["It's the header that controls whether cookies are sent along.", "It's a boolean-style header, 'true' or absent."],
          },
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: confusing SOP and CORS. SOP is the browser's default restriction (deny cross-origin reads). CORS is a server opting IN to specific exceptions. CORS does not add security on top of SOP — a misconfigured CORS policy actively removes SOP's protection.",
            "Mistake: assuming `Access-Control-Allow-Origin: *` (wildcard) with credentials is possible. Browsers explicitly forbid combining a wildcard ACAO with Access-Control-Allow-Credentials: true — so seeing `*` alone is usually lower risk (no credentials can ride along) unless the response contains data not tied to a specific user.",
            "Mistake: treating a Secure+HttpOnly+SameSite=Strict cookie as un-stealable. Those flags each block a *specific* attack vector (sniffing, JS read, cross-site sending) — they don't protect against, say, physically compromising the server's session store, or an XSS bug performing actions on the page rather than reading the cookie.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice: classify this response",
          body: [
            "A different endpoint, `/api/public-prices`, returns: `Access-Control-Allow-Origin: *` with no `Access-Control-Allow-Credentials` header, and the response body contains only public product prices with no cookie-dependent personalisation.",
            "Decide whether this is a CORS misconfiguration worth reporting.",
          ],
          check: {
            type: "mc",
            q: "Is `Access-Control-Allow-Origin: *` on this specific endpoint a vulnerability?",
            options: [
              "Yes, wildcards are always a critical bug",
              "No — the data is public and not tied to a logged-in user, and credentials aren't allowed, so there's no sensitive cross-origin read to exploit",
              "Yes, because any CORS header is inherently unsafe",
              "Cannot be determined without seeing the server's source code",
            ],
            answer: 1,
            why: [
              "Severity depends on what the policy exposes, not the mere presence of a wildcard.",
              "",
              "CORS headers are a normal, often-necessary mechanism; the explain card described when they become risky.",
              "The response content and header combination observed are enough to reason about impact here.",
            ],
            explain: "Impact in CORS bugs comes from exposing *sensitive, user-specific* data to arbitrary origins, typically combined with credentials. A wildcard on a genuinely public, non-personalised endpoint with no credentials allowed has no meaningful impact to exploit.",
            hints: [
              "Compare this to the dangerous combination described earlier — what's missing here?",
              "Ask: what would an attacker actually gain by reading this particular response from another origin?",
            ],
          },
        },
        {
          kind: "relevance",
          title: "What this proves in real testing",
          body: [
            "Finding a reflected-ACAO + credentials-true combination on an endpoint returning sensitive, user-specific data is a reportable, often high-severity finding on its own — it's a concrete, reproducible proof-of-concept (build a minimal attacker.example page that fetches the API and show the stolen data).",
            "It does NOT prove anything about endpoints you haven't tested, and it does not justify fetching real other users' data beyond what's needed to demonstrate the flaw. Test with your own authorised test accounts only, within scope.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          ref: "CORS: carefully letting an exception through SOP",
          exhibit:
            "GET /api/me HTTP/1.1\nHost: shop.example\nOrigin: https://attacker.example\nCookie: session=abc\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true\n{\"email\":\"alice@shop.example\"}",
          q: "What is the bug in this exchange?",
          options: [
            "Nothing, this is a normal, safe CORS response",
            "ACAO reflects the request's Origin unconditionally AND credentials are allowed, so any attacker-controlled site can read this authenticated response",
            "The cookie value is malformed",
            "The response body is too large",
          ],
          answer: 1,
          why: [
            "A server-chosen, allow-listed ACAO would be normal; reflecting any origin is not.",
            "",
            "The cookie format isn't the issue here.",
            "Size is irrelevant to the vulnerability.",
          ],
          explain: "Reflecting the Origin header back as ACAO plus allowing credentials is exactly the dangerous combination from this lesson: it lets attacker.example read shop.example's authenticated response using the victim's own cookie.",
          hints: ["Compare the Origin header to the ACAO value — are they the same, and is that normal?", "Check whether credentials are allowed too."],
        },
        {
          type: "fill",
          ref: "Cookie attributes",
          q: "Which single cookie flag specifically prevents page JavaScript from reading the cookie via document.cookie?",
          answers: ["httponly", "http only", "httponly flag"],
          explain: "HttpOnly. It reduces the blast radius of an XSS bug from 'attacker can read and exfiltrate the session cookie' to 'attacker can only act within the page's existing JS context'.",
          hints: ["Not Secure (that's about HTTPS-only transport).", "Not SameSite (that's about cross-site sending)."],
        },
        {
          type: "mc",
          ref: "Origin, and why 'same site' needs a precise definition",
          q: "Which of these is a DIFFERENT origin from `https://shop.example`?",
          options: [
            "https://shop.example/login (different path)",
            "https://shop.example:443 (explicit default port)",
            "http://shop.example (different scheme)",
            "https://shop.example?x=1 (different query string)",
          ],
          answer: 2,
          why: [
            "Path doesn't affect origin — only scheme, host, and port do.",
            "443 is HTTPS's default port, so this is the same origin.",
            "",
            "Query strings don't affect origin either.",
          ],
          explain: "Origin = scheme + host + port only. Path and query string are irrelevant to the same-origin check. http vs https is a scheme change, making it a different origin even though the host is identical.",
          hints: ["Re-read the definition: scheme + host + port.", "Which of the four options changes one of exactly those three things?"],
        },
        {
          type: "match",
          ref: "Cookie attributes",
          q: "Match each cookie attribute to the risk it mainly mitigates when present.",
          pairs: [
            ["Secure", "Sniffing over unencrypted (HTTP) connections"],
            ["HttpOnly", "Theft via malicious page JavaScript (XSS)"],
            ["SameSite=Strict", "Cross-site request forgery (CSRF)"],
            ["Narrow Domain/Path", "Exposure to unrelated or compromised subdomains"],
          ],
          explain: "Each flag defends against a distinct, separate threat; having one does not substitute for the others.",
          hints: ["Secure is about the wire; HttpOnly is about JavaScript; SameSite is about cross-site requests."],
        },
        {
          type: "order",
          ref: "Worked example: is this ACAO safe?",
          q: "Order the steps for deciding whether an observed CORS configuration is exploitable.",
          items: [
            "Send requests with two different, unrelated Origin headers",
            "Check whether Access-Control-Allow-Origin simply mirrors whatever Origin was sent",
            "Check whether Access-Control-Allow-Credentials: true is also present",
            "Check whether the response contains sensitive, user-specific data",
          ],
          explain: "You need all four pieces: reflection proves there's no allow-list, credentials-true proves cookies would be attached, and sensitive per-user data proves there's something worth stealing. Missing any one weakens or removes the impact.",
          hints: ["You can't tell it's 'reflected' from a single request.", "Sensitivity of the data is checked last because it determines impact, not the mechanism."],
        },
      ],
    },
    {
      id: "burp-workflow",
      title: "A Burp Suite workflow",
      summary: "The tool that turns 'I think there's a bug' into a reproducible, exact proof-of-concept — essential before you start hunting access-control flaws.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can describe what each core Burp Suite tab does, set up your browser to proxy through Burp, and choose the right tab (Proxy history, Repeater, Intruder, Collaborator) for a given testing task.",
          ],
        },
        {
          kind: "intuition",
          title: "A tap on the wire, under your control",
          body: [
            "Normally your browser talks straight to the server, and you only ever see the final rendered page — the raw request/response from the earlier lessons is invisible. Burp Suite sits as a **proxy** in between: your browser talks to Burp, Burp talks to the server, and you get to see — and edit — every request and response in transit.",
            "This matters because everything taught so far (methods, headers, cookies, CORS) is only testable if you can actually see and change the raw bytes. A browser's address bar can't set a custom header or resend a tampered request; Burp can.",
          ],
        },
        {
          kind: "prereq",
          title: "What you need before this makes sense",
          body: [
            "You should already be comfortable reading a request/response pair (method, headers, status, body — previous lesson) and know what a cookie/session is, since most Burp workflows revolve around tampering with exactly those pieces.",
            "Burp is a local HTTPS-intercepting proxy: your browser is configured to send its traffic to `127.0.0.1:8080` (Burp's listener), and you install Burp's own certificate authority in the browser so it can decrypt and re-encrypt HTTPS traffic for you to inspect — this is only legitimate because it's YOUR browser and YOUR traffic, in an authorised test.",
          ],
        },
        {
          kind: "explain",
          title: "The tabs you'll live in",
          body: [
            "**Proxy / HTTP history** — a running log of every request your browser made through Burp. You scroll back and right-click any entry to send it elsewhere for further testing.",
            "**Repeater** — takes one request, lets you edit it freely, and resend it as many times as you like, each time showing you the fresh response. This is where most manual tampering (headers, cookies, body fields from the earlier lessons) happens.",
            "**Intruder** — takes one request and a wordlist, and fires many variations of that request automatically, substituting a payload into a chosen position each time. Used for fuzzing parameters, brute-forcing values, or enumerating IDs.",
            "**Collaborator** — gives you a unique, disposable domain name that logs any DNS lookup or HTTP hit made to it. Useful when a vulnerability doesn't show its effect in the direct response (a 'blind' bug) — you plant the Collaborator domain somewhere and wait to see if the server reaches out to it.",
          ],
          code: `# minimal setup
# 1. install Burp, start it (default proxy listener: 127.0.0.1:8080)
# 2. configure the browser's HTTP(S) proxy to 127.0.0.1:8080
# 3. visit http://burp and install Burp's CA certificate in the browser

# the everyday loop
browse the target -> find the request in Proxy history
-> right-click -> "Send to Repeater" -> tamper a field -> Send
-> compare the new response to the original`,
          check: {
            type: "match",
            q: "Match the Burp tool to the task it's built for.",
            pairs: [
              ["Repeater", "Manually tweak one request and resend it repeatedly"],
              ["Intruder", "Automatically try many payloads from a wordlist in one field"],
              ["Collaborator", "Detect blind, out-of-band interactions (no visible response change)"],
              ["Proxy history", "Review and pick from every request already made"],
            ],
            explain: "Picking the wrong tool for a task costs real time: Repeater for one-off manual tests, Intruder when you need to try many values automatically, Collaborator when the bug doesn't show in the direct response, and Proxy history as the starting point for everything.",
            hints: ["Which tool needs a list of many values?", "Which tool is for things you can't see directly in the response?"],
          },
        },
        {
          kind: "explain",
          title: "Match & Replace, and reading the response diff",
          body: [
            "Proxy → Options → Match and Replace lets you define a rule that rewrites part of EVERY outbound request automatically — for example, always adding `X-Forwarded-For: 192.0.2.10`, or always replacing `admin=0` with `admin=1` in request bodies.",
            "After tampering a request in Repeater, the key skill is reading the **response diff**: did the status code change? Did the body length change meaningfully? Did a field that was previously absent now appear? A single extra character in a 10,000-line response is noise; a status code flipping from 403 to 200 is signal.",
          ],
          tone: "offense",
        },
        {
          kind: "example",
          title: "Worked example: confirming a header-trust bug with Repeater",
          body: [
            "You capture `GET /admin` in Proxy history and see it returns 403. Send it to Repeater.",
            "Step 1 — resend unmodified first, to get a clean baseline: 403 Forbidden, body `{\"error\":\"admins only\"}`.",
            "Step 2 — add exactly one header, `X-Forwarded-For: 127.0.0.1`, change nothing else, and resend: 200 OK, body contains an admin dashboard.",
            "Step 3 — isolate: remove the header again and resend, confirming it reverts to 403. This single-variable test proves the header — not cookies, not timing — caused the change.",
            "Why this discipline matters: changing only one thing at a time is what makes the finding reproducible and credible; changing five things at once and getting 200 tells you something changed, but not what.",
          ],
          code: `# baseline
GET /admin HTTP/1.1
Host: shop.example
Cookie: session=abc
-> 403 Forbidden

# +1 header
GET /admin HTTP/1.1
Host: shop.example
Cookie: session=abc
X-Forwarded-For: 127.0.0.1
-> 200 OK

# remove header again
GET /admin HTTP/1.1
Host: shop.example
Cookie: session=abc
-> 403 Forbidden   (confirms the header was the cause)`,
          check: {
            type: "mc",
            q: "Why did the tester remove the X-Forwarded-For header again in step 3, instead of stopping after step 2?",
            options: [
              "To make the request faster",
              "To isolate the cause by confirming behaviour reverts when the single changed variable is removed",
              "Because Burp requires requests to alternate",
              "It wasn't necessary, step 2 was already proof",
            ],
            answer: 1,
            why: [
              "Speed isn't the concern here.",
              "",
              "No such requirement exists.",
              "Step 2 alone shows correlation but not that nothing else changed between baseline and test — the revert closes that gap.",
            ],
            explain: "Changing exactly one variable, observing the effect, then reverting it and confirming the original behaviour returns, is the standard way to prove causation rather than coincidence — the same discipline as a controlled experiment.",
            hints: ["Think about what would make a skeptical reviewer doubt step 2 alone.", "What's the difference between 'correlation' and 'proven cause'?"],
          },
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: tampering several fields at once in Repeater and declaring a bug when the response changes. You won't know which change mattered — always isolate one variable per resend.",
            "Mistake: treating Intruder results as confirmed vulnerabilities just because some requests returned 200 among many 403s. Automated fuzzing produces leads to manually verify, not finished findings — check each promising hit by hand.",
            "Mistake: leaving Match & Replace rules enabled globally after finishing a specific test, then being confused when unrelated requests behave strangely later.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice: plan a Repeater test",
          body: [
            "You suspect `/api/export?format=csv` might behave differently if you request `format=xml` instead, possibly revealing a different code path with weaker checks. Plan how you'd test this safely and conclusively using the tools from this lesson.",
          ],
          check: {
            type: "order",
            q: "Order the correct steps for this test using Repeater.",
            items: [
              "Capture the original /api/export?format=csv request in Proxy history",
              "Send it to Repeater and resend unmodified to record the baseline response",
              "Change only the format value to xml and resend",
              "Compare status code and body against the baseline to judge what changed",
            ],
            explain: "Always establish an unmodified baseline in the same tool before changing anything, so the only difference between the two Repeater tabs is the one variable you intended to test.",
            hints: ["The baseline must be captured before you change anything.", "Comparison is the last step, after both responses exist."],
          },
        },
        {
          kind: "relevance",
          title: "What a Burp-confirmed finding proves — and its limits",
          body: [
            "A Repeater-confirmed, single-variable, reproducible change (like the X-Forwarded-For example) is strong, easy-to-communicate evidence for a report: anyone can replay the exact same two requests and see the same two outcomes.",
            "It does not, by itself, establish severity or whether the behaviour is in-scope — you still need to check the program's rules of engagement, and confirm the impact (what data/actions are actually exposed) before reporting. Never run Intruder-scale fuzzing against a production target without explicit authorisation for that volume of traffic.",
          ],
        },
      ],
      exercises: [
        {
          type: "match",
          ref: "The tabs you'll live in",
          q: "Match the Burp tool to the task.",
          pairs: [
            ["Repeater", "Tweak one request repeatedly"],
            ["Intruder", "Fuzz a field with a wordlist"],
            ["Collaborator", "Catch blind out-of-band callbacks"],
            ["Proxy history", "Review every request the browser made"],
          ],
          explain: "If you reach for the wrong tool, the test takes far longer than it should — these four cover almost every daily workflow task.",
          hints: ["Reread the explain card listing the four tabs."],
        },
        {
          type: "mc",
          ref: "Worked example: confirming a header-trust bug with Repeater",
          q: "You add a header AND change a cookie value in the same Repeater resend, and the response changes from 403 to 200. What can you conclude?",
          options: [
            "The header definitely caused the change",
            "The cookie change definitely caused the change",
            "You cannot tell which of the two changes caused the result — you changed two variables at once",
            "Burp made an error",
          ],
          answer: 2,
          why: [
            "You have no basis to isolate the header as the cause when the cookie also changed.",
            "Same problem in reverse.",
            "",
            "Nothing suggests a tool malfunction.",
          ],
          explain: "This is the mistake the lesson warns against directly: changing more than one variable per request destroys your ability to attribute the result to a specific cause. Redo the test changing only one field at a time.",
          hints: ["Re-read the 'Common mistakes' card.", "How many things changed between the two requests you compared?"],
        },
        {
          type: "fill",
          ref: "The tabs you'll live in",
          q: "Which Burp feature gives you a unique domain that logs any DNS or HTTP interaction made to it, useful for 'blind' vulnerabilities with no visible response change?",
          answers: ["collaborator", "burp collaborator"],
          explain: "Collaborator is designed exactly for vulnerabilities (like blind SSRF or blind SQLi) where success isn't visible in the direct HTTP response, only in a side effect like an out-of-band network callback.",
          hints: ["It's not Repeater or Intruder.", "Think 'out-of-band'."],
        },
        {
          type: "mc",
          ref: "Match & Replace, and reading the response diff",
          q: "Intruder returns 40 responses with status 403 and 2 with status 200 out of 300 payloads tried. What is the correct next step?",
          options: [
            "Immediately report all 300 as confirmed vulnerable",
            "Manually inspect the 2 interesting (200) responses in Repeater to confirm they're genuine and not false positives",
            "Ignore all results since most were 403",
            "Delete the Intruder attack and start over",
          ],
          answer: 1,
          why: [
            "Reporting unverified automated results overstates confidence and risks false positives.",
            "",
            "Discarding promising leads wastes real findings.",
            "There's no reason to discard useful data.",
          ],
          explain: "Intruder is a lead-generation tool; the 200s among many 403s are worth manually verifying in Repeater (isolating variables, as taught) before treating them as confirmed.",
          hints: ["Re-read the mistakes card about Intruder results.", "What distinguishes a 'lead' from a 'confirmed finding' in this lesson?"],
        },
      ],
    },
    {
      id: "idor",
      title: "Access control: IDOR, the beginner's goldmine",
      summary: "Authentication proves who you are; authorisation decides what you're allowed to touch. IDOR is what happens when a server checks the first and forgets the second.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can explain the difference between authentication and authorisation with an example, recognise the IDOR pattern in a pair of requests, and responsibly prove an IDOR using two test accounts.",
          ],
        },
        {
          kind: "intuition",
          title: "A hotel key card vs. which room it opens",
          body: [
            "Checking in at a hotel desk and getting a key card is **authentication** — the front desk confirmed you're a real guest with a real booking. But if your key card also happens to open every OTHER room in the hotel, that's a failure of **authorisation** — the system verified who you are but never checked which room you're actually allowed into.",
            "On the web, logging in (getting a valid session cookie, from the cookies lesson) proves authentication. Whether the server then checks 'does THIS specific resource belong to THIS specific logged-in user' before handing it over is a separate, independent check — and it's the one developers forget.",
          ],
        },
        {
          kind: "prereq",
          title: "Authentication vs. authorisation, precisely",
          body: [
            "**Authentication (AuthN)** — verifying identity: who are you? Login forms, passwords, 2FA, the session cookie from the earlier lesson that says 'this request is from the user who logged in as alice'.",
            "**Authorisation (AuthZ)** — verifying permission: given that you are alice, are you allowed to do THIS specific thing or see THIS specific resource? A server can authenticate you perfectly and still authorise you incorrectly.",
            "Two sub-types of broken authorisation worth naming precisely: **horizontal** escalation is accessing another user's data at the SAME privilege level (alice reading bob's invoice, both ordinary customers) — this is what IDOR usually is. **Vertical** escalation is reaching a HIGHER privilege level (an ordinary customer reaching an admin-only action). IDOR is almost always horizontal.",
            "Status codes from the first lesson map onto this directly: 401 means an authentication failure (you're not logged in at all); 403 means an authorisation failure (you're logged in, but not allowed here) — or, in a buggy app, 200 when it should have been 403.",
          ],
          check: {
            type: "mc",
            q: "alice is logged in. She requests `/api/invoices/9003`, which belongs to bob, and the server returns it with a 200 OK. Which check did the server fail?",
            options: [
              "Authentication — it didn't verify alice's identity",
              "Authorisation — it verified alice's identity but not whether she should see bob's invoice",
              "Both authentication and authorisation failed equally",
              "Neither — a 200 response is always correct",
            ],
            answer: 1,
            why: [
              "Authentication clearly succeeded — the server knows this request is from alice (that's how it has a session at all).",
              "",
              "Authentication worked fine here; only authorisation failed.",
              "200 here means data that isn't alice's own was handed over — that's the bug.",
            ],
            explain: "This is the exact pattern from the intuition card: the server correctly confirmed WHO is asking (alice, via her session) but never checked WHETHER alice should be allowed to see invoice 9003, which belongs to a different user.",
            hints: ["Does the server know alice is alice? That's one question.", "Does the server check if the resource belongs to alice? That's a different question."],
          },
        },
        {
          kind: "explain",
          title: "The IDOR pattern itself",
          body: [
            "**IDOR (Insecure Direct Object Reference)** is what you call it when an application takes an identifier straight from the request (a URL, a body field, a hidden form field) and uses it to fetch a resource WITHOUT checking that the resource belongs to the requesting user.",
            "The fix developers are supposed to apply is adding an ownership condition to the lookup — not just `WHERE id = $1`, but `WHERE id = $1 AND user_id = $session_user`. IDOR is exactly the absence of that second condition.",
            "Where to look: anywhere an ID appears — in a URL path, a query parameter, a JSON body field, or a hidden form field. Classic feature names to test: 'view my invoice', 'edit my profile', 'cancel my booking', 'download my document' — any 'my X' feature is a candidate for 'can I access someone else's X instead'.",
          ],
          code: `GET /api/invoice/4231     200 OK   (belongs to the logged-in user)
GET /api/invoice/4232     200 OK   (belongs to a DIFFERENT user - bug)

# vulnerable lookup
SELECT * FROM invoices WHERE id = $1;

# fixed lookup - adds the missing ownership check
SELECT * FROM invoices WHERE id = $1 AND user_id = $session_user;`,
        },
        {
          kind: "explain",
          title: "IDs aren't only sequential numbers",
          body: [
            "Sequential numeric IDs (4231, 4232...) make IDOR trivial to find — just increment. But switching to random-looking identifiers (UUIDs) does not fix the underlying missing-ownership-check bug; it only raises the bar for an attacker to GUESS a valid other ID.",
            "A UUID can still be discovered rather than guessed: it might appear in another endpoint's response (a list of 'team members', a notification, a search result, a leaked log), in a URL shared elsewhere, or be predictable if it's generated in a non-random way (e.g. derived from a timestamp). The underlying missing authorisation check is the real bug either way.",
          ],
        },
        {
          kind: "example",
          title: "Worked example: confirming an IDOR with two accounts",
          body: [
            "You have two authorised test accounts: alice (uid 1001) and bob (uid 1002).",
            "Step 1 — log in as alice, perform the normal action ('view my invoices'), and capture the exact request: `GET /api/invoices/me` returns alice's own invoices (ids 9001, 9002). This is your authenticated baseline, same discipline as the Burp lesson.",
            "Step 2 — from another endpoint, or by direct knowledge, learn bob's invoice id is 9003 (e.g. from `/api/users/1002` listing his invoices, if accessible, or simply by incrementing).",
            "Step 3 — still logged in as alice (her session cookie, not bob's), request `GET /api/invoices/9003`. The server returns bob's invoice data with a 200 OK.",
            "Step 4 — this is the proof. Using ONLY alice's own session, you obtained bob's data. You did not need bob's password, his session, or any action by bob. That's exactly why it's authorisation, not authentication, that failed — alice's authentication was entirely legitimate.",
            "Why you don't stop at step 3 alone: a single surprising response could be caused by many things (shared test fixtures, a staging quirk). Repeating with a second known-but-different ID (bob's other invoice, 9004) and getting another cross-user hit rules out coincidence — the same single-variable discipline from the Burp lesson, applied here to IDs instead of headers.",
          ],
          code: `# as alice (session=alice's cookie)
GET /api/invoices/me
-> [{"id":9001,...},{"id":9002,...}]   (alice's own)

GET /api/invoices/9003
-> {"id":9003,"user":1002,...}        (bob's - BUG)

GET /api/invoices/9004
-> {"id":9004,"user":1002,...}        (bob's again - confirms pattern)`,
          check: {
            type: "fill",
            q: "In step 4, whose session cookie was used to retrieve bob's invoice?",
            answers: ["alice", "alice's", "alices"],
            explain: "This is the entire point of the proof: alice's own, completely legitimate session was enough to pull bob's data, because the server never checked that invoice 9003 belongs to the requester.",
            hints: ["Who was logged in throughout steps 1-3?"],
          },
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: assuming random-looking IDs (UUIDs) mean 'IDOR is impossible here'. As covered above, it only means IDs are harder to guess blindly — check whether they leak elsewhere before ruling IDOR out.",
            "Mistake: fuzzing a wide range of IDs (e.g. 1 through 10000) against a live target to 'prove' IDOR at scale. This accesses real other users' real private data without need and is both unauthorised and unethical — a single confirmed cross-user access with your own test accounts is sufficient proof.",
            "Mistake: calling every case of 'I can see something I shouldn't' an IDOR. If reaching the data required a higher privilege level (e.g. a regular user reaching an admin panel) rather than another same-level user's resource, that's vertical privilege escalation, a related but distinct bug — precise naming matters in a report.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice: classify and plan a test",
          body: [
            "A booking site has `GET /api/bookings/{id}/receipt`. You're logged in as a regular customer. You want to check whether you can retrieve another customer's receipt. You have two of your own test accounts (A and B) — no access to any real customer's account.",
          ],
          check: {
            type: "order",
            q: "Order the responsible steps to test this, using only your own two accounts.",
            items: [
              "Log in as Account A, create or view a booking, and capture the exact GET /api/bookings/{id}/receipt request",
              "Log in as Account B, create a separate booking, and note its id",
              "While authenticated as Account A, request Account B's booking id",
              "Record whether the response returns B's receipt data (bug) or an authorisation error (expected behaviour)",
            ],
            explain: "This mirrors the alice/bob worked example exactly: establish each account's own baseline first, then cross the boundary using only your own accounts' sessions, and judge the outcome against what SHOULD happen (a 403/404, not the other account's data).",
            hints: ["You need a known resource ID from each account before you can cross-test.", "The cross-test uses one account's session against the other account's resource id."],
          },
        },
        {
          kind: "relevance",
          title: "What confirming an IDOR proves — and its limits",
          body: [
            "A confirmed IDOR using two of your own authorised test accounts is a strong, reproducible, low-risk piece of evidence: it proves the specific endpoint is missing an ownership check, for the specific resource type tested.",
            "It does NOT prove every endpoint on the site has the same flaw — each endpoint needs its own check, since different features are often implemented by different code. It also does not justify accessing real users' data during testing: always use your own test accounts, stay within authorised scope, and stop at the minimum evidence needed to demonstrate the flaw.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          ref: "Authentication vs. authorisation, precisely",
          q: "You're logged in as alice. `GET /api/invoices/me` returns yours. `GET /api/invoices/42` returns a stranger's invoice with a 200 OK. What's the correct name for this bug?",
          options: ["Cross-site scripting (XSS)", "IDOR (missing object-level authorisation)", "CSRF", "SSRF"],
          answer: 1,
          why: [
            "XSS involves injecting script into a page; nothing here involves script execution.",
            "",
            "CSRF is about tricking a victim's browser into making an unwanted request; here, the tester deliberately made the request themselves.",
            "SSRF is about making the SERVER issue a request on your behalf; this is about direct resource access.",
          ],
          explain: "This is the textbook IDOR pattern: the endpoint successfully authenticates alice, but fails to check whether invoice 42 is actually hers before returning it.",
          hints: ["Re-read 'The IDOR pattern itself' card.", "Which check (identity vs. ownership) failed here?"],
        },
        {
          type: "mc",
          ref: "IDs aren't only sequential numbers",
          q: "The IDs in an API are UUIDv4 (e.g. 7e1a9f2c-...) and look completely random. Does this mean IDOR is no longer possible?",
          options: [
            "Yes, UUIDs are mathematically unguessable so IDOR is impossible",
            "No — UUIDs can still leak via other endpoints, meaning the missing ownership check is still exploitable once an ID is discovered",
            "UUIDs prevent all authorisation bugs by design",
            "IDOR only applies to numeric IDs by definition",
          ],
          answer: 1,
          why: [
            "Guessability is only one path to discovery; leakage via other endpoints is another, and UUIDs don't block the UNDERLYING missing check at all.",
            "",
            "UUIDs are just identifiers; they don't add any permission logic by themselves.",
            "IDOR is defined by the missing ownership check, not by the ID's format.",
          ],
          explain: "UUIDs raise the bar for blind guessing but don't fix the real bug, which is the absent ownership check. Any endpoint that leaks a UUID elsewhere (search results, team member lists, notifications) still hands an attacker a working ID to exploit the same flaw.",
          hints: ["Re-read 'IDs aren't only sequential numbers'.", "Does changing the ID format add a permission check anywhere?"],
        },
        {
          type: "fill",
          ref: "Authentication vs. authorisation, precisely",
          q: "An ordinary logged-in customer finds they can call an admin-only endpoint to reset any user's password. Is this horizontal or vertical privilege escalation?",
          answers: ["vertical"],
          explain: "Reaching a HIGHER privilege tier (admin-only functionality) from a lower one is vertical escalation, distinct from IDOR's usual horizontal (same-tier, different-user) pattern.",
          hints: ["Horizontal = same level, different user. Vertical = different level entirely.", "Is 'admin-only' a different privilege tier from 'ordinary customer'?"],
        },
        {
          type: "order",
          ref: "Worked example: confirming an IDOR with two accounts",
          q: "Order the steps to responsibly confirm an IDOR using two of your own authorised test accounts.",
          items: [
            "Log in as Account A and capture the request for A's own resource",
            "Determine a specific resource id belonging to Account B",
            "Replay the request as Account A, substituting B's resource id",
            "Confirm the response returns B's data rather than an authorisation error, and repeat with a second id to rule out coincidence",
          ],
          explain: "This is the same sequence as the alice/bob worked example: baseline first, then the minimal single-variable swap (only the id changes, session stays A's), then confirm — and verify twice rather than once to exclude a fluke.",
          hints: ["The baseline (your own resource) always comes first.", "Only the resource id should change between the baseline and test requests — this is the same discipline as the Burp Repeater lesson."],
        },
        {
          type: "mc",
          ref: "What confirming an IDOR proves — and its limits",
          q: "Having confirmed IDOR on `/api/invoices/{id}` using your two test accounts, which conclusion is justified?",
          options: [
            "Every endpoint on the site has the same bug",
            "Only this endpoint, for this resource type, is confirmed missing an ownership check — other endpoints need separate testing",
            "The entire company's security program is worthless",
            "No further testing is needed anywhere on the site",
          ],
          answer: 1,
          why: [
            "Different endpoints are often implemented by different code paths; a flaw in one doesn't guarantee the same flaw elsewhere.",
            "",
            "One confirmed bug doesn't characterise an entire program.",
            "Confirming one bug doesn't mean other areas are automatically safe.",
          ],
          explain: "Findings should be scoped precisely to what was actually tested and confirmed. Overclaiming ('this proves the whole site is broken') undermines credibility; each endpoint needs its own verification.",
          hints: ["Re-read the final relevance card.", "What exactly did the two-account test verify — one endpoint, or the whole application?"],
        },
      ],
    },
  ],
  lab: {
    id: "lab-web-fundamentals",
    title: "CTF: the invoice portal",
    tone: "offense",
    briefing: [
      "Target: https://shop.example/portal — a customer invoice portal.",
      "You are logged in as alice (uid 1001). The company's CEO is bob (uid 1002).",
      "Use the terminal to send crafted curl requests. Find and submit the flag inside bob's private invoice.",
      "Flag format: FLAG{...}",
    ],
    terminal: {
      host: "hunter@kali",
      commands: {
        "curl -i https://shop.example/portal/":
          "HTTP/1.1 302 Found\nLocation: /portal/login\nSet-Cookie: csrftoken=A1B2; Path=/\n",
        "curl -i https://shop.example/portal/login -d 'u=alice&p=hunter2'":
          "HTTP/1.1 302 Found\nSet-Cookie: session=eyJ1aWQiOjEwMDF9.sig; HttpOnly; Path=/\nLocation: /portal/dashboard",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/dashboard":
          "<html><body>Welcome, alice (uid 1001). <a href='/portal/invoices/me'>My invoices</a></body></html>",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/me":
          "[{\"id\":9001,\"amount\":42.00,\"status\":\"paid\"},{\"id\":9002,\"amount\":19.00,\"status\":\"paid\"}]",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/9001":
          "{\"id\":9001,\"user\":1001,\"amount\":42.00,\"items\":[\"book\"],\"note\":\"\"}",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/9002":
          "{\"id\":9002,\"user\":1001,\"amount\":19.00,\"items\":[\"ebook\"],\"note\":\"\"}",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/9003":
          "{\"id\":9003,\"user\":1002,\"amount\":120000.00,\"items\":[\"consultancy\"],\"note\":\"CEO reimbursement\"}",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/9004":
          "{\"id\":9004,\"user\":1002,\"amount\":0.00,\"items\":[\"private\"],\"note\":\"internal only — FLAG{1d0r_1s_the_f1rst_bug_every_hunter_f1nds}\"}",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/9005":
          "{\"error\":\"not found\"}",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/users/1002":
          "{\"id\":1002,\"name\":\"bob\",\"role\":\"ceo\",\"invoices\":[9003,9004]}",
      },
      hints: [
        "curl -i https://shop.example/portal/login -d 'u=alice&p=hunter2'",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/me",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/users/1002",
        "curl -b 'session=eyJ1aWQiOjEwMDF9.sig' https://shop.example/portal/api/invoices/9004",
      ],
    },
    tasks: [
      {
        q: "What is bob's user id?",
        answers: ["1002"],
        hint: "The briefing says it.",
      },
      {
        q: "List bob's invoice IDs (comma-separated, sorted).",
        answers: ["9003,9004", "9003, 9004"],
        hint: "The /api/users/1002 endpoint tells you.",
      },
      {
        q: "Which API endpoint lets you fetch an invoice by numeric ID with no ownership check? (template: /path/<id>)",
        answers: ["/portal/api/invoices/", "/portal/api/invoices", "/portal/api/invoices/{id}", "/api/invoices/"],
        hint: "The one that returned bob's invoice when you asked for it.",
      },
      {
        q: "What is the flag? Format FLAG{...}",
        answers: ["FLAG{1d0r_1s_the_f1rst_bug_every_hunter_f1nds}", "1d0r_1s_the_f1rst_bug_every_hunter_f1nds"],
        hint: "It's in invoice 9004.",
      },
    ],
  },
  ids: {
    name: "HTTP toolkit",
    description:
      "You can read and tamper every part of a request, understand cookies, sessions and the same-origin policy, evaluate CORS headers, and use Burp Suite's Repeater/Intruder/Collaborator to confirm access-control bugs like IDOR.",
    rules: [],
  },
};

export default unit4;
