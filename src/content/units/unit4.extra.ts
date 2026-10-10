import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "encoding",
    title: "The Art of Encoding",
    summary: "How the same bytes mean different things in different contexts, and why encoding (not encryption) keeps that from breaking.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: ["By the end of this lesson you can identify URL-encoding, HTML-entity encoding and Base64 on sight, explain why each exists, and recognise double-encoding as a filter-bypass technique."],
      },
      {
        kind: "intuition",
        title: "The same symbol, different alphabets",
        body: [
          "A `<` character means nothing special in plain text, but inside HTML it starts a tag. A space is fine in a sentence, but a URL can't contain a literal space without ambiguity. Encoding is how we write a character so it survives being placed into a context with its own special meaning, without being misread as a control character of that context.",
          "Where this breaks down for attackers' benefit: if a security filter only decodes a value ONCE but the receiving parser decodes it TWICE, you can hide a dangerous character inside an extra layer of encoding that slips past the filter, then gets revealed only after the filter has already approved it.",
        ],
      },
      {
        kind: "prereq",
        title: "What the request/response lesson already told you",
        body: [
          "From the earlier HTTP lesson: the path, query string, headers and body are just text the client sends. Encoding schemes are how that text safely represents characters that would otherwise be ambiguous in a URL, HTML page, or binary-to-text transport.",
        ],
      },
      {
        kind: "explain",
        title: "URL encoding and HTML-entity encoding",
        body: [
          "**URL (percent) encoding** replaces a byte with `%` followed by its two-digit hex value — a space becomes `%20`, because a literal space would break a URL's structure.",
          "**HTML-entity encoding** replaces a character with an `&name;` or `&#code;` form so it's displayed literally instead of interpreted as markup — `<` becomes `&lt;`, so `<script>` typed into a comment box is shown as text, not executed as a tag.",
          "**Double encoding** means encoding an already-encoded value again: `%20` encoded a second time becomes `%2520` (the `%` itself is encoded to `%25`). If a filter only decodes once, it sees `%2520` and may not recognise the dangerous `%20` hiding one layer deeper — a classic filter-bypass trick.",
        ],
        code: `URL encoding:   a b  ->  a%20b
HTML encoding:  <div>  ->  &lt;div&gt;
Double URL encoding:  %20  ->  %2520  (decodes once to %20, decodes again to " ")`,
        check: {
          type: "fill",
          q: "What does the URL-encoded sequence %20 represent, once decoded?",
          answers: ["space", "a space", "' '"],
          explain: "%20 is the percent-encoded form of the space character (hex 0x20), used because a literal space is not allowed unescaped in many parts of a URL.",
          hints: ["20 is the hex value of a common whitespace character."],
        },
      },
      {
        kind: "explain",
        title: "Base64: a transport encoding, not encryption",
        body: [
          "Base64 converts arbitrary binary data into a sequence of 64 printable characters (A-Z, a-z, 0-9, +, /), with `=` used as padding at the end. It exists so binary data can travel safely through systems that only expect plain text.",
          "It is commonly seen inside `Authorization: Basic <base64>` headers and inside JWTs (JSON Web Tokens, covered in Unit 6). Crucially, Base64 provides zero confidentiality — anyone can decode it instantly with no key, so it must never be mistaken for encryption.",
        ],
        code: `echo -n 'admin:hunter2' | base64
# -> YWRtaW46aHVudGVyMg==

echo -n 'YWRtaW46aHVudGVyMg==' | base64 -d
# -> admin:hunter2   (no secret needed to reverse it)`,
        check: {
          type: "mc",
          q: "A request contains `Authorization: Basic YWRtaW46aHVudGVyMg==`. What can you conclude?",
          options: [
            "The credentials are securely encrypted and unreadable",
            "The credentials are trivially recoverable by anyone who decodes the Base64 string",
            "This header can't contain a username and password",
            "Base64 requires a secret key to decode",
          ],
          answer: 1,
          why: [
            "Base64 provides no confidentiality at all.",
            "",
            "Basic auth's entire format is base64(username:password).",
            "Base64 decoding requires no key by design.",
          ],
          explain: "Basic authentication literally is base64(username:password) with no encryption layer; it only becomes safe when sent over HTTPS, which hides it from network observers, not from anyone holding the raw string.",
          hints: ["Re-read: is Base64 encryption or encoding?", "What tool did the example use to reverse it, and did it need a password?"],
        },
      },
      {
        kind: "example",
        title: "Worked example: Content-Type and a WAF bypass attempt",
        body: [
          "A login form normally submits as `application/x-www-form-urlencoded`. A Web Application Filter (WAF) in front of the app is configured to block the literal text `' OR 1=1` in form-encoded bodies, but was never configured to inspect JSON bodies the same way.",
          "Step 1 — identify the assumption: the WAF's rule is tied to one Content-Type / encoding, not to the underlying meaning of the data.",
          "Step 2 — the application itself accepts both `application/x-www-form-urlencoded` and `application/json` for the same endpoint (from the HTTP lesson: Content-Type tells the server which parser to use).",
          "Step 3 — resend the same malicious value, but switch Content-Type to `application/json` and re-encode the body as JSON: the WAF's filter (scoped to form-encoded parsing) doesn't recognise the value in its new shape, and the request reaches the application unfiltered.",
          "Why this matters: this is not a new vulnerability by itself — it's a demonstration that a security CONTROL (the WAF rule) was too narrowly scoped to the request's current encoding, while the application's parsing was broader. The underlying bug (if the value is then dangerous) still needs confirming separately.",
        ],
        code: `# blocked by WAF (form-encoded, filter matches)
POST /login
Content-Type: application/x-www-form-urlencoded

user=admin&pass=' OR 1=1

# same payload, different envelope - WAF rule doesn't match this shape
POST /login
Content-Type: application/json

{"user":"admin","pass":"' OR 1=1"}`,
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Mistake: assuming Base64 output is 'encrypted' because it looks unreadable at a glance. It is reversible by anyone with no key — never rely on it for confidentiality.",
          "Mistake: decoding a value once and assuming you've seen its true form. Always check whether decoding again reveals further structure (double encoding).",
          "Mistake: assuming a WAF or filter that blocks a payload in one encoding/content-type has blocked it everywhere. Filters are often scoped to the format they were tested against.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice: decode and reason",
        body: [
          "You intercept a request containing the query parameter `q=%2522test%2522`. Decode it step by step and decide how many layers of URL encoding are present.",
        ],
        check: {
          type: "fill",
          q: "After decoding %2522test%2522 completely, what is the final plain-text value?",
          answers: ['"test"', "\"test\""],
          explain: "%25 decodes to %, so %2522 first becomes %22, which decodes again to a double-quote character — two layers of encoding wrapped around the word test.",
          hints: ["Decode one layer first: %25 -> %.", "After the first decode you'll have another %-sequence; decode that too."],
        },
      },
      {
        kind: "relevance",
        title: "Why this matters in testing",
        body: [
          "Recognising encoding on sight lets you read what a request or filter is actually doing, and lets you deliberately re-encode a payload to test whether a filter's protection is as broad as it claims.",
          "Successfully bypassing a filter's pattern match with an alternate encoding proves the FILTER is narrowly scoped — it does not by itself prove the underlying application is vulnerable to whatever payload got through. That still needs separate confirmation (Unit 5 covers this for injection).",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        ref: "URL encoding and HTML-entity encoding",
        q: "Which encoding is specifically used to safely include special characters inside a URL?",
        options: ["HTML entities", "Base64", "URL encoding (percent encoding)", "UTF-16"],
        answer: 2,
        why: [
          "HTML entities protect against markup injection in rendered HTML, not URL structure.",
          "Base64 is a binary-to-text transport, unrelated to URL syntax specifically.",
          "",
          "UTF-16 is a character encoding, not an escaping mechanism for URLs.",
        ],
        explain: "URL (percent) encoding replaces characters that would otherwise be ambiguous in a URL's structure with %XX hex sequences.",
        hints: ["Think about what happens to a space in a search URL.", "It involves a percent sign."],
      },
      {
        type: "match",
        ref: "URL encoding and HTML-entity encoding",
        q: "Match the value to the encoding context it belongs to.",
        pairs: [
          ["%22", "URL-encoded double quote"],
          ["&quot;", "HTML-encoded double quote"],
          ["YWRtaW4=", "Base64 encoding of 'admin'"],
          ["%2522", "Double URL-encoded double quote"],
        ],
        explain: "Each representation protects the same underlying character in a different context, or in two nested layers of the same context (double encoding).",
        hints: ["&...; is the HTML form.", "A trailing = is a Base64 padding hint.", "%25 at the start of a sequence suggests a re-encoded %."],
      },
      {
        type: "fill",
        ref: "Base64: a transport encoding, not encryption",
        q: "A string like 'dGVzdA==' with trailing '=' padding is most likely encoded using which scheme?",
        answers: ["base64"],
        explain: "Base64 strings commonly end in '=' or '==' padding and use the 64-character alphanumeric-plus-two-symbols set.",
        hints: ["It's a binary-to-text scheme mentioned alongside Authorization: Basic.", "Padding characters are a giveaway."],
      },
      {
        type: "mc",
        ref: "Worked example: Content-Type and a WAF bypass attempt",
        q: "A WAF blocks a payload sent as form-encoded data but not the identical payload sent as JSON. What does this demonstrate?",
        options: [
          "The application has definitely been successfully exploited",
          "The WAF's filtering rule was scoped to one request format and didn't account for another the application also accepts",
          "JSON cannot contain dangerous payloads",
          "The application doesn't accept JSON",
        ],
        answer: 1,
        why: [
          "Bypassing a filter is not the same as confirming the underlying vulnerability is real.",
          "",
          "JSON strings can contain any text, including dangerous payloads.",
          "The example explicitly shows the application accepting JSON.",
        ],
        explain: "This shows a gap in the WAF's coverage, not a confirmed application vulnerability — those are separate claims requiring separate evidence, as stated in the relevance card.",
        hints: ["Re-read the final line of the worked example.", "What exactly was proven: a filter gap, or an exploited bug?"],
      },
    ],
  },
  {
    id: "authn-vs-authz",
    title: "AuthN vs. AuthZ, deeper",
    summary: "Reinforcing the identity-vs-permission distinction from the IDOR lesson, with the comparer mindset used to test it systematically.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: ["By the end of this lesson you can classify a given scenario as a horizontal or vertical privilege-escalation issue, and describe the 'two accounts + Burp Comparer' method for testing authorisation systematically."],
      },
      {
        kind: "intuition",
        title: "Recap: wristband vs. which stalls it opens",
        body: [
          "This builds directly on the IDOR lesson's hotel key-card analogy: authentication is getting a valid key card at all; authorisation is which doors it actually opens. Here we go one level deeper into HOW testers systematically probe 'which doors does this open'.",
        ],
      },
      {
        kind: "prereq",
        title: "What you already know",
        body: [
          "From the access-control lesson: AuthN = who you are, AuthZ = what you're allowed to do; horizontal escalation = same level, different user; vertical escalation = reaching a higher privilege tier. This lesson adds the systematic method for testing both.",
        ],
      },
      {
        kind: "explain",
        title: "The comparer mindset",
        body: [
          "To test authorisation deliberately, you need (at minimum) two accounts at different points in the privilege structure you want to test: 'Attacker' and 'Victim' for horizontal tests, or 'Low-priv' and 'Admin' for vertical tests.",
          "The method: capture a sensitive request performed by the higher-privileged or victim account, then REPLAY that exact same request while swapping in the lower-privileged or attacker account's session token. If the server still performs the action or returns the data, authorisation is broken.",
          "**Burp Comparer** (a Burp Suite feature) highlights byte-level differences between two responses — useful for spotting a small but meaningful difference, like a response that looks identical at a glance but has `\"role\":\"admin\"` swapped to `\"role\":\"user\"`.",
        ],
        check: {
          type: "mc",
          q: "Why does the comparer method require REPLAYING the exact captured request rather than crafting a new one by hand?",
          options: [
            "Because Burp cannot create new requests",
            "To isolate the one variable that matters (the session/identity) and keep everything else identical to the original, legitimate request — the same single-variable discipline from the Burp Repeater lesson",
            "Because servers reject hand-typed requests",
            "It doesn't matter; any similar request works equally well",
          ],
          answer: 1,
          why: [
            "Burp can create requests freely; that's not the constraint.",
            "",
            "Servers don't distinguish requests by how they were typed.",
            "Changing more than the identity risks the same attribution problem covered in the Burp lesson.",
          ],
          explain: "This reuses the exact discipline from the Burp Suite lesson: change only one variable (here, the session/account) and keep the rest of the request identical, so any difference in outcome can be attributed specifically to the identity swap.",
          hints: ["Which earlier lesson taught 'change one variable at a time'?", "What would happen to your conclusion if you changed the path AND the session at once?"],
        },
      },
      {
        kind: "example",
        title: "Worked example: testing for vertical escalation",
        body: [
          "An app has `POST /api/admin/users/{id}/delete`. You have a regular-user account and (in an authorised test environment) an admin account.",
          "Step 1 — log in as admin, perform the delete action against a disposable test user, and capture the exact request in Burp.",
          "Step 2 — send that captured request to Repeater, and swap only the session cookie to the regular user's session, leaving the URL, headers and body otherwise identical.",
          "Step 3 — send it and read the response. If it returns success (e.g. 200, and the target user is actually gone when checked), the endpoint performs admin-only actions without verifying the caller's role — vertical escalation confirmed. If it returns 403, the check is working correctly.",
        ],
        code: `# as admin (baseline)
POST /api/admin/users/55/delete
Cookie: session=admin-session
-> 200 OK

# identical request, only the session swapped
POST /api/admin/users/55/delete
Cookie: session=regularuser-session
-> 200 OK   <- vertical escalation: role was never checked`,
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Mistake: performing this kind of test against a production system without an explicit, authorised admin test account set up for that purpose — never attempt to escalate using a real administrator's credentials or data.",
          "Mistake: labelling every authorisation bug 'IDOR' out of habit. IDOR specifically refers to the object-reference pattern (horizontal, resource-id based); a role-check bypass on an action endpoint, with no object ID involved, is more precisely a vertical privilege-escalation / broken function-level authorisation issue.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice: classify two scenarios",
        body: [
          "Scenario A: alice (regular user) changes `user_id=123` to `user_id=124` in a URL and sees another regular user's private profile. Scenario B: alice (regular user) successfully calls an endpoint meant only for support staff to view any customer's payment history.",
        ],
        check: {
          type: "match",
          q: "Classify each scenario.",
          pairs: [
            ["Scenario A (alice views user 124's profile)", "Horizontal privilege escalation"],
            ["Scenario B (alice reaches support-staff-only endpoint)", "Vertical privilege escalation"],
          ],
          explain: "A stays at the same privilege tier but crosses to a different user's data (horizontal). B reaches functionality meant for a higher-privileged role entirely (vertical).",
          hints: ["Are the two users in A at the same rank, or different ranks?", "Is 'support staff' a different privilege tier from 'regular user'?"],
        },
      },
      {
        kind: "relevance",
        title: "Why this precision matters",
        body: [
          "Correctly distinguishing horizontal from vertical escalation in a report helps the development team fix the right check — a missing ownership filter (horizontal) and a missing role check (vertical) are different code changes.",
          "Confirming one escalation case with two authorised test accounts proves that specific endpoint's check is missing; it doesn't imply every endpoint behind the same login page shares the flaw.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        ref: "The comparer mindset",
        q: "A user changes 'user_id=123' to 'user_id=124' in a URL and sees another regular user's profile. What is this?",
        options: [
          "Vertical privilege escalation",
          "Horizontal privilege escalation",
          "Broken authentication",
          "An encoding issue",
        ],
        answer: 1,
        why: ["Both users share the same privilege tier.", "", "The user authenticated successfully; nothing about login itself failed.", "No encoding is involved in this scenario."],
        explain: "Since both users are at the same privilege level, accessing another's data this way is horizontal privilege escalation — the same pattern as IDOR.",
        hints: ["Are they moving 'up' a rank, or 'sideways' to another same-level user?"],
      },
      {
        type: "order",
        ref: "Worked example: testing for vertical escalation",
        q: "Order the steps to manually test for vertical privilege escalation using the comparer method.",
        items: [
          "Log in as an admin and capture a 'delete user' request",
          "Log in separately as a regular user and obtain their session cookie",
          "Replace only the session cookie in the captured admin request with the regular user's session",
          "Send the modified request and check whether the delete action actually succeeded",
        ],
        explain: "You need the high-privilege action captured first, then the low-privilege identity, then the swap (changing only the identity), then checking the real outcome.",
        hints: ["The high-priv action must exist before you can replay it.", "The swap happens right before the final send, changing only one thing."],
      },
      {
        type: "match",
        ref: "Guided practice: classify two scenarios",
        q: "Match the term to its primary function.",
        pairs: [
          ["Authentication", "Verifying identity"],
          ["Authorisation", "Verifying permission for a specific resource/action"],
          ["Horizontal escalation", "Same privilege tier, different user's data"],
          ["Vertical escalation", "Reaching a higher privilege tier entirely"],
        ],
        explain: "These four terms, used precisely, let you describe exactly what failed in a finding instead of vaguely saying 'access control is broken'.",
        hints: ["AuthN is about identity; AuthZ is about permission.", "Horizontal moves sideways; vertical moves up."],
      },
    ],
  },
  {
    id: "repro-poc",
    title: "Reproducible PoCs",
    summary: "Turning a confirmed finding (like the IDOR and CORS bugs from earlier lessons) into a clean, minimal, professional proof-of-concept.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: ["By the end of this lesson you can strip a captured request down to a minimal reproducible proof-of-concept, redact sensitive values correctly, and export it as a shareable curl command."],
      },
      {
        kind: "intuition",
        title: "A recipe, not a snapshot",
        body: [
          "A screenshot shows that something happened once, on your machine, at one moment. A reproducible PoC is more like a recipe: anyone who follows the exact steps gets the exact same result, on their own machine, at any time. That reliability is what separates a report a developer can act on from one they have to spend an hour trying to reproduce.",
        ],
      },
      {
        kind: "prereq",
        title: "What a PoC packages up",
        body: [
          "A good PoC for a web bug reuses exactly what you've already learned to read: the method, path, relevant headers, and body (from the HTTP anatomy lesson), captured and confirmed through the single-variable discipline from the Burp lesson (e.g. the two-account IDOR proof, or the two-Origin CORS test).",
        ],
      },
      {
        kind: "explain",
        title: "Minimum viable request",
        body: [
          "Strip away headers that aren't part of the exploit's mechanism — `User-Agent`, `Accept-Language`, `Referer`, cache-control headers — unless the bug specifically depends on one of them. Keep only what's needed to reproduce the result: the method, path, the headers/cookie/body that matter, and nothing else.",
          "A minimal PoC also proves the bug isn't an artefact of browser quirks, extensions, or cached state — if a two-line curl command reproduces it, the bug is in the server's logic, not your environment.",
        ],
      },
      {
        kind: "explain",
        title: "Redacting sensitive values",
        body: [
          "Never include your own real session tokens, passwords, or personal data verbatim in a shared report — replace them with clear placeholders like `[REDACTED]` or `YOUR_SESSION_HERE`.",
          "If the structure of a value matters for reproducing the bug (e.g. a token's format), keep the shape but scramble the actual signature/secret portion so the placeholder is still recognisable as 'a token goes here' without being usable by anyone who reads the report.",
        ],
        tone: "defense",
        check: {
          type: "mc",
          q: "You're writing up the IDOR finding from the access-control lesson. What should you do with alice's real session cookie value in the report?",
          options: [
            "Include it in full so the reviewer can test it themselves",
            "Replace it with a clear placeholder like [ALICE_SESSION], keeping the report's steps otherwise exact",
            "Encrypt it with a password before including it",
            "Omit the cookie entirely from the PoC",
          ],
          answer: 1,
          why: [
            "Sharing a live session token is a real security risk and unnecessary.",
            "",
            "Encryption adds complexity without the reviewer having the key, and still unnecessarily shares a live credential's structure.",
            "Omitting it entirely would make the PoC impossible to reproduce, since the cookie is essential to the exploit.",
          ],
          explain: "The goal is reproducibility without exposing live credentials: a labelled placeholder preserves every step a reviewer needs while removing the actual secret.",
          hints: ["Reproducibility and confidentiality are both goals — which choice satisfies both?"],
        },
      },
      {
        kind: "example",
        title: "Worked example: writing the IDOR PoC as curl",
        body: [
          "Starting from the confirmed IDOR finding (alice's session retrieving bob's invoice 9003), build the minimal curl PoC.",
          "Step 1 — identify the essential parts: method (GET), path (/api/invoices/9003), and the one header that matters (Cookie, carrying alice's session). Drop User-Agent, Accept, and other noise headers captured by the browser.",
          "Step 2 — redact the session value per the previous card, while preserving its format so a reviewer understands what goes there.",
          "Step 3 — export as curl, the universal command-line format any reviewer can run without installing Burp.",
        ],
        code: `curl -i https://shop.example/portal/api/invoices/9003 \\
  -H 'Cookie: session=[ALICE_SESSION]'

# Expected (buggy) result: 200 OK with bob's invoice data,
# even though this request used alice's session only.`,
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Mistake: pasting an entire browser-captured request with 15 headers into a report, burying the one or two that actually matter and making the PoC harder to verify, not easier.",
          "Mistake: forgetting to actually test the stripped-down, redacted version before submitting it — a PoC that only works with the extra headers you removed is not actually minimal, and claiming otherwise undermines trust in the report.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice: strip this capture",
        body: [
          "You captured this full browser request for the CORS finding from the earlier lesson. Decide which lines are essential to keep in the PoC.",
        ],
        code: `GET /api/me HTTP/1.1
Host: shop.example
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Accept: */*
Accept-Language: en-US
Origin: https://attacker.example
Cookie: session=[VICTIM_SESSION]
Connection: keep-alive`,
        check: {
          type: "fill",
          q: "Besides the request line (GET /api/me) and Host, name the ONE header that is essential to reproducing this specific CORS finding (not counting the Cookie).",
          answers: ["origin", "origin header"],
          explain: "Origin is what triggers the server's (mis)handling of CORS — it's the variable the earlier lesson's worked example changed to detect reflection. User-Agent, Accept, Accept-Language and Connection are incidental browser noise for this particular bug.",
          hints: ["Which header did the CORS worked example change between its two test requests?"],
        },
      },
      {
        kind: "relevance",
        title: "Why this matters in a real report",
        body: [
          "A minimal, redacted, curl-reproducible PoC is what lets a triager confirm your finding in under a minute instead of a full afternoon — speed and clarity directly affect how seriously a report is taken.",
          "A PoC only proves what it reproduces: a curl command that demonstrates reading one invoice doesn't by itself prove every invoice is exposed, or that write operations are similarly vulnerable — state explicitly what was and wasn't tested.",
        ],
      },
    ],
    exercises: [
      {
        type: "fill",
        ref: "Worked example: writing the IDOR PoC as curl",
        q: "Which command-line tool is the industry-standard way to share a reproducible HTTP request in a bug report?",
        answers: ["curl"],
        explain: "curl is available on nearly every OS and can precisely replicate a crafted HTTP request from a single copy-pasteable command.",
        hints: ["It's a 'client for URLs'."],
      },
      {
        type: "mc",
        ref: "Minimum viable request",
        q: "Why strip unnecessary headers from a PoC rather than pasting the full browser capture?",
        options: [
          "To hide that you used Burp Suite",
          "To isolate exactly which parameters cause the vulnerability, making it faster and clearer for the developer to confirm and fix",
          "To make the request transmit faster over the network",
          "Stripping headers is required by law",
        ],
        answer: 1,
        why: ["Which tool you used isn't a concern.", "", "Network transmission speed is not the reason.", "No such legal requirement exists."],
        explain: "A minimal PoC isolates signal from noise, proving precisely which parts of the request matter — the same principle as changing one variable at a time in Repeater.",
        hints: ["Think about 'signal vs noise' from the Burp lesson's single-variable discipline."],
      },
      {
        type: "mc",
        ref: "Redacting sensitive values",
        q: "What should you do with your own live session cookie before sharing a PoC in a written report?",
        options: [
          "Keep it live so the reviewer can test with your account",
          "Encrypt it with a password only you know",
          "Redact or replace it with a clearly labelled placeholder",
          "Double-URL-encode it",
        ],
        answer: 2,
        why: [
          "Sharing a live, working credential is an unnecessary security risk.",
          "An encrypted value the reviewer can't decrypt is just as useless and still risky to generate.",
          "",
          "Encoding format has nothing to do with protecting the secret.",
        ],
        explain: "A clearly labelled placeholder preserves reproducibility (the reviewer knows a session cookie goes there) while removing the actual live secret.",
        hints: ["Revisit the mc check on this same card."],
      },
    ],
  },
  {
    id: "rest-api-basics",
    title: "REST API Fundamentals",
    summary: "Most modern web apps are a browser front-end calling a JSON API underneath — understanding that API surface is where access-control testing (IDOR, CORS) actually happens.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: ["By the end of this lesson you can map common REST conventions (resource paths, CRUD methods) to the HTTP concepts from earlier lessons, and know where to look for an API's documented or undocumented endpoints."],
      },
      {
        kind: "intuition",
        title: "A filing cabinet with standard drawers",
        body: [
          "REST treats data as named 'resources' (a user, an invoice, an order) each with its own address (a URL path), and reuses the same small set of HTTP methods from the first lesson to act on any of them — rather than inventing a new verb for every action. It's like a filing cabinet where every drawer is opened, filled, or emptied using the same four standard actions, instead of a different mechanism per drawer.",
        ],
      },
      {
        kind: "prereq",
        title: "What you already know that applies directly",
        body: [
          "From the HTTP anatomy lesson: GET reads, and methods like POST/PUT/DELETE are meant to change state. REST APIs lean on exactly this convention, and most JSON bodies you'll see use the Content-Type: application/json header covered there.",
        ],
      },
      {
        kind: "explain",
        title: "REST conventions and JSON",
        body: [
          "A REST API exposes **resources** at predictable paths, e.g. `/users/1`, `/orders/42`, and lets you act on them with the standard methods: **GET** (read), **POST** (create a new one), **PUT** or **PATCH** (update an existing one), **DELETE** (remove it).",
          "Data is typically exchanged as **JSON**: a key-value text format like `{\"id\":42,\"status\":\"paid\"}`. This is exactly the Content-Type: application/json body shape from the HTTP anatomy lesson.",
        ],
        check: {
          type: "match",
          q: "Match the HTTP method to its standard REST action.",
          pairs: [
            ["GET", "Read a resource"],
            ["POST", "Create a new resource"],
            ["PUT/PATCH", "Update an existing resource"],
            ["DELETE", "Remove a resource"],
          ],
          explain: "This is the standard CRUD (Create, Read, Update, Delete) mapping most REST APIs follow by convention — though, as the first lesson warned, the server doesn't always enforce these meanings strictly.",
          hints: ["POST is for brand-new things; PUT/PATCH is for modifying things that already exist."],
        },
      },
      {
        kind: "explain",
        title: "Finding the map: documentation and hidden endpoints",
        body: [
          "APIs are often documented with **OpenAPI/Swagger**, a machine-readable file listing every endpoint, method, and expected parameter. Developers sometimes accidentally leave this file reachable at paths like `/swagger.json`, `/api-docs`, or `/v1/openapi.json`.",
          "When no such file is public, the next place to look is the site's own JavaScript bundles (e.g. `main.js`) — frontend code frequently hardcodes the exact API paths it calls, revealing the API surface even without formal documentation.",
        ],
        tone: "offense",
      },
      {
        kind: "example",
        title: "Worked example: from a Swagger file to a test target",
        body: [
          "You find `https://shop.example/swagger.json` is publicly reachable and it lists: `GET /api/invoices/{id}`, `GET /api/users/{id}`, `POST /api/invoices/{id}/refund`.",
          "Step 1 — recognise `{id}` as a path parameter taking an object identifier — exactly the pattern the access-control lesson taught you to test for ownership checks.",
          "Step 2 — note `POST /api/invoices/{id}/refund` as a state-changing action gated by an id, worth testing for the vertical/horizontal distinction from the AuthN/AuthZ lesson: can a regular user refund someone ELSE's invoice (horizontal), or refund at all if refunds should be staff-only (vertical)?",
          "Step 3 — this documentation didn't PROVE any bug exists — it only told you where to concentrate the testing techniques from earlier lessons (two-account IDOR tests, single-variable Repeater tampering).",
        ],
        code: `// swagger.json (excerpt)
{
  "paths": {
    "/api/invoices/{id}": { "get": {...} },
    "/api/users/{id}": { "get": {...} },
    "/api/invoices/{id}/refund": { "post": {...} }
  }
}`,
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Mistake: assuming a Swagger/OpenAPI file finding is itself a vulnerability report. An exposed API map is a reconnaissance aid (sometimes worth flagging as information disclosure, with much lower severity) — it is not the same as a confirmed access-control or injection bug.",
          "Mistake: assuming every endpoint listed actually requires the privilege level its name implies ('admin' in the path name is not proof it's protected — and conversely, a plain-looking path isn't proof it's unprotected either). Test, don't assume, exactly as the earlier lessons describe.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice: plan from an endpoint list",
        body: [
          "A swagger file reveals `POST /api/admin/reports/export`. You only have a regular, non-admin test account.",
        ],
        check: {
          type: "mc",
          q: "What's the correct, responsible next step with only a regular-user account?",
          options: [
            "Assume it's vertical escalation and report it without testing",
            "Attempt the request with your regular-user session, within your authorised scope, to check whether the role check is actually enforced",
            "Ignore it since you don't have an admin account",
            "Request admin credentials from the target company over email first without checking scope",
          ],
          answer: 1,
          why: [
            "Naming alone doesn't confirm the check is missing — guessing isn't evidence.",
            "",
            "A reachable endpoint is worth checking with the access you legitimately have, as long as it's in scope.",
            "Scope and rules of engagement should guide any such request, not an unprompted email.",
          ],
          explain: "This directly applies the vertical-escalation test method from the AuthN/AuthZ lesson: try the sensitive action with your lower-privileged, authorised account and observe whether the server actually enforces the restriction its path name implies.",
          hints: ["Which earlier lesson's method applies directly to an admin-looking endpoint?", "Does finding the endpoint name alone constitute proof of anything?"],
        },
      },
      {
        kind: "relevance",
        title: "Why this matters in testing",
        body: [
          "Mapping an API's real surface (via docs or JS bundles) tells you WHERE to apply the techniques from this unit (request tampering, CORS checks, IDOR tests) — it multiplies the value of everything already learned by pointing it at the right targets.",
          "Finding an endpoint, or even finding its documentation exposed, proves the endpoint EXISTS — it does not prove it's vulnerable. Each one still needs to be tested individually before you can report a confirmed bug.",
        ],
      },
    ],
    exercises: [
      {
        type: "match",
        ref: "REST conventions and JSON",
        q: "Match the HTTP method to the standard REST action.",
        pairs: [
          ["GET", "Read resource"],
          ["POST", "Create resource"],
          ["PUT", "Update/replace resource"],
          ["DELETE", "Remove resource"],
        ],
        explain: "These are the standard CRUD mappings REST APIs follow by convention.",
        hints: ["POST is for new things.", "PUT is for modifying existing things."],
      },
      {
        type: "mc",
        ref: "Finding the map: documentation and hidden endpoints",
        q: "You find a publicly reachable 'swagger.json' on a target. Why is this useful to a tester, specifically?",
        options: [
          "It contains the admin's password",
          "It is a map of available API endpoints and their expected parameters, telling you where to focus further testing",
          "It automatically exploits the server for you",
          "It contains the server's full source code",
        ],
        answer: 1,
        why: ["It documents the API surface, not credentials.", "", "It's documentation, not an exploit tool.", "It describes the API contract, not the implementation source."],
        explain: "Swagger/OpenAPI files define the entire documented API surface, including endpoints you might not otherwise discover by browsing — exactly the reconnaissance value described in this lesson.",
        hints: ["It's a documentation format — what does documentation typically describe?"],
      },
      {
        type: "fill",
        ref: "Worked example: from a Swagger file to a test target",
        q: "What HTTP status code is the standard response when a request is from an authenticated user but they lack the necessary permission for the action (an authorisation failure)?",
        answers: ["403"],
        explain: "401 means not authenticated at all (from the access-control lesson); 403 means authenticated but not permitted — the status to expect if the refund endpoint's role check IS working correctly.",
        hints: ["It's in the 4xx range.", "It's not the code meaning 'please log in'."],
      },
      {
        type: "mc",
        ref: "Common mistakes",
        q: "A swagger file lists `GET /api/internal/debug`. Does the path name alone confirm this endpoint is dangerous or unprotected?",
        options: [
          "Yes, 'internal' in the name guarantees it's unprotected",
          "No — the name suggests it's worth testing, but protection must be verified, not assumed from naming",
          "No, because internal endpoints can never be reached externally",
          "Yes, because Swagger always only lists working, exploitable endpoints",
        ],
        answer: 1,
        why: [
          "Naming conventions are not enforcement — the lesson explicitly warns against this assumption.",
          "",
          "If it's listed and reachable at all, it's reachable externally by definition in this scenario.",
          "Swagger simply documents endpoints; it says nothing about their actual protection.",
        ],
        explain: "Path names are hints for where to look, not evidence of a security state either way — the lesson's mistakes card warns against assuming protection status from naming alone, in both directions.",
        hints: ["Re-read the second bullet of 'Common mistakes'."],
      },
    ],
  },
];
