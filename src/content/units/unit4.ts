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
      summary: "Methods, headers, cookies, body — all of them are attacker-controlled.",
      cards: [
        {
          title: "The parts of a request",
          body: [
            "Method, path, query string, headers, body. Any one of them can be edited in Burp Suite's Repeater.",
            "Methods matter: GET is cacheable, idempotent and leaks via logs; POST isn't. But a server rarely enforces the method — flipping POST → GET or GET → PUT often reveals undocumented behaviour.",
          ],
          code: `POST /api/v2/orders HTTP/1.1
Host: shop.example
Cookie: session=eyJ1aWQiOjQyfQ...
Content-Type: application/json
Content-Length: 42
X-Forwarded-For: 127.0.0.1

{"item":"book","qty":1,"price":29.00}

↑ every single line is attacker-controlled on the wire. ↑`,
        },
        {
          title: "Headers worth remembering",
          body: [
            "Host — the Virtual host. Change it and watch what happens (cache poisoning, SSRF, password-reset poisoning).",
            "Cookie — session, tracking, auth. Replace, strip, mutate.",
            "Authorization — Basic, Bearer, Digest. Bearer tokens are often JWTs; see Unit 6.",
            "X-Forwarded-For / X-Real-IP / X-Original-URL / X-Rewrite-URL — trusted blindly by far too many apps for ACLs.",
            "Content-Type — switch application/json ↔ application/xml ↔ x-www-form-urlencoded and watch parsers disagree.",
          ],
          tone: "offense",
        },
        {
          title: "A hunter's reflexes",
          body: [
            "Burp Suite's Repeater is where you tamper requests one-by-one.",
            "Burp Suite's Intruder (or ffuf) is where you fuzz a field with a wordlist.",
            "Match & Replace rules let you add attacker headers (X-Forwarded-For: 127.0.0.1) to every request globally — cheap to try, surprisingly effective.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "An endpoint rejects your request with 403. You add `X-Forwarded-For: 127.0.0.1` and it returns 200. What happened?",
          options: [
            "The server trusts a header the client sends and treated you as internal",
            "Your IP changed",
            "The server reset",
            "Nothing — coincidence",
          ],
          answer: 0,
          explain:
            "Classic ACL bypass. Many apps gate /admin behind 'if X-Forwarded-For == 127.0.0.1 or RFC1918'. They forget that header is client-controlled unless scrubbed at the edge.",
        },
        {
          type: "match",
          q: "Match the header to the attack it most often enables.",
          pairs: [
            ["Host", "Password-reset poisoning / cache deception"],
            ["X-Original-URL", "Access-control bypass"],
            ["Content-Type", "Parser confusion / content-type sniffing"],
            ["Authorization", "Token manipulation (e.g. JWT algo=none)"],
          ],
          explain: "Each header has a classic bug family. Keep this table in your head.",
        },
      ],
    },
    {
      id: "cookies-sessions",
      title: "Cookies, sessions, same-origin",
      summary: "How a site remembers who you are, and how an attacker steals that memory.",
      cards: [
        {
          title: "Cookie attributes",
          body: [
            "Secure — only sent over HTTPS. Missing = sniffable on any public Wi-Fi.",
            "HttpOnly — not readable by JavaScript. Missing = XSS can steal it.",
            "SameSite — Strict / Lax / None. Missing or None without Secure = CSRF.",
            "Domain / Path — scoping. Overly broad Domain = subdomain takeover becomes session takeover.",
          ],
          code: `Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax
                   ^good defaults
Set-Cookie: tracking=xyz; Domain=.example.com      ← any subdomain can read.`,
        },
        {
          title: "The same-origin policy, briefly",
          body: [
            "An origin = scheme + host + port. shop.example:443 is different from shop.example:80, and from api.shop.example:443.",
            "SOP stops site A reading responses from site B. Everything about web security is a careful list of exceptions to that rule: CORS, postMessage, cross-origin cookies, iframes.",
          ],
        },
        {
          title: "CORS gone wrong",
          body: [
            "The most dangerous CORS misconfiguration: `Access-Control-Allow-Origin: <reflected origin>` + `Access-Control-Allow-Credentials: true`.",
            "That combo lets any attacker site read any API response with the victim's cookies.",
            "Test by changing the Origin header to `https://attacker.example` and inspecting the ACAO in the response.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "mc",
          exhibit:
            "GET /api/me HTTP/1.1\nHost: shop.example\nOrigin: https://attacker.example\nCookie: session=abc\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true\n{\"email\":\"alice@shop.example\"}",
          q: "What is the bug here?",
          options: [
            "Nothing, this is normal CORS",
            "ACAO reflects any origin AND credentials are allowed — any attacker site can read authenticated responses",
            "The cookie is wrong",
            "The email is leaked",
          ],
          answer: 1,
          explain:
            "Reflecting the origin + allowing credentials is a classic high-severity CORS misconfig. On most programs this is a bounty on its own.",
        },
        {
          type: "fill",
          q: "Which cookie flag prevents JavaScript from reading the cookie?",
          answers: ["httponly", "http only", "httponly flag"],
          explain: "HttpOnly. Reduces the blast radius of an XSS from 'full account takeover' to 'in-page actions'.",
        },
      ],
    },
    {
      id: "burp-workflow",
      title: "A Burp Suite workflow",
      summary: "The tool that turns 'I think there's a bug' into 'here is the exact PoC'.",
      cards: [
        {
          title: "The tabs you'll live in",
          body: [
            "Proxy / HTTP history — every request your browser made. Scroll back, right-click, 'Send to…'.",
            "Repeater — send one request, tweak, resend. 90% of manual testing.",
            "Intruder — one request, many payloads from a wordlist. Fuzzing, brute force, enumeration.",
            "Scanner / Dastardly — automatic active scan. Burp Pro only; good for second-pass coverage.",
            "Collaborator — unique domain that logs any DNS/HTTP hit. Essential for blind SSRF/XSS/SQLi.",
          ],
          code: `# install
sudo apt install burpsuite
# configure Firefox / foxyproxy to localhost:8080
# install Burp's CA in the browser  → http://burp/cert

# the usual flow
browse the app  →  turn Intercept on  →  right-click → 'Send to Repeater'
tamper a parameter, click Send, read the response diff.`,
          tone: "offense",
        },
        {
          title: "Match & Replace is a superpower",
          body: [
            "Proxy → Options → Match and Replace lets you rewrite every outbound request.",
            "Add `X-Forwarded-For: 127.0.0.1` to every request. Set `User-Agent: ' OR 1=1-- -`. Replace `admin=0` with `admin=1`.",
            "Many bugs show up without any targeted testing because the global replacement nudges them.",
          ],
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Match the Burp tool to the task.",
          pairs: [
            ["Repeater", "Tweak one request repeatedly"],
            ["Intruder", "Fuzz a field with a wordlist"],
            ["Collaborator", "Catch blind out-of-band callbacks"],
            ["Proxy history", "Review every request the browser made"],
          ],
          explain: "If you reach for the wrong tool, the test takes 10× longer. These four cover almost every daily task.",
        },
      ],
    },
    {
      id: "idor",
      title: "IDOR: the beginner's goldmine",
      summary: "Change a number, see someone else's stuff.",
      cards: [
        {
          title: "The pattern",
          body: [
            "The app checks whether you're logged in, but not whether you're authorised to touch the specific resource.",
            "/api/invoices/4231 belongs to you. /api/invoices/4232 belongs to a stranger. The server returns both if asked.",
          ],
          code: `# IDOR 101
GET /api/invoice/4231     200 OK   (yours)
GET /api/invoice/4232     200 OK   (someone else's)  ← bug

# often the fix is 'auth check with resource ownership':
#   WHERE id = $1 AND user_id = $session_user`,
          tone: "offense",
        },
        {
          title: "Where to look",
          body: [
            "Anywhere an ID appears in a URL, body, or hidden form field.",
            "Numeric IDs are the obvious case. UUIDs are not immune — they're guessable if sequentially generated, timestamped, or leaked elsewhere.",
            "'Download your invoice', 'edit my profile', 'cancel my booking', 'change my email' are all textbook IDOR candidates.",
          ],
        },
        {
          title: "Proving it responsibly",
          body: [
            "Create TWO test accounts (A and B).",
            "As A, access A's resource — note the request.",
            "Change the ID to B's resource. Access it as A.",
            "That's the PoC. Do NOT fuzz 1..10000 to find real users' data.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You're logged in as alice. `GET /api/invoices/me` returns yours. `GET /api/invoices/42` returns a stranger's. What's the bug?",
          options: ["XSS", "IDOR (missing object-level authorization)", "CSRF", "SSRF"],
          answer: 1,
          explain: "Classic IDOR. The endpoint checks authentication (you're logged in) but not authorization (you can see 42).",
        },
        {
          type: "mc",
          q: "The IDs are UUIDv4 and look random. Is IDOR dead?",
          options: [
            "Yes, UUIDs are unguessable",
            "No — UUIDs often leak via other endpoints (search, admin lists, notifications)",
            "Only on Fridays",
            "Only on Windows",
          ],
          answer: 1,
          explain:
            "UUIDs just raise the discovery bar. Any endpoint that returns 'users with the same company' or 'members in a chat' feeds you the next victim's ID.",
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
      "You can read and tamper every part of a request, understand cookies and SOP, and use Burp Suite for Repeater/Intruder/Collaborator workflows.",
    rules: [],
  },
};

export default unit4;
