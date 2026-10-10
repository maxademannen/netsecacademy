import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "xss-contexts",
    title: "XSS Contexts & DOM Sinks",
    summary: "Why the same injection point needs different payloads depending on where it lands.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "Given a snippet of page template code showing where user input lands, identify the HTML/JS context and choose an appropriate payload or defense.",
        ],
      },
      {
        kind: "prereq",
        title: "Recap: contexts inside a page",
        body: [
          "From the previous lesson: a browser treats `<script>...</script>` content as JS code, and HTML-encoding (`<` → `&lt;`) neutralises tags in plain HTML content.",
          "But user input doesn't always land inside plain HTML body text — it can land inside an HTML ATTRIBUTE value (`<input value='PAYLOAD'>`), or inside a JAVASCRIPT STRING that's part of an inline `<script>` block (`var name = 'PAYLOAD';`). Each of these is a different CONTEXT, parsed by different rules.",
        ],
      },
      {
        kind: "explain",
        title: "Why one defense doesn't fit all contexts",
        body: [
          "HTML-body context: encoding `<` as `&lt;` is enough, because the danger is a new TAG being created.",
          "HTML-attribute context: the danger is breaking OUT of the attribute's quotes, e.g. `<input value='` + input + `'>`. If input contains a `'`, it closes the attribute early, and the rest becomes a new, attacker-controlled attribute or tag. HTML-encoding the quote character itself (`'` → `&#39;`) is what's needed here.",
          "JavaScript-string context: input lands inside `var name = '` + input + `';`. HTML entities like `&lt;` mean nothing to the JS engine — it never decodes HTML entities. The danger here is a literal `'` closing the JS string, so you need JS-specific escaping (e.g. `\\x27` or a JSON-safe encoder), not HTML encoding.",
          "This is why 'we encode our output' isn't a complete answer on its own — the correct ENCODING FUNCTION depends on which of these three contexts the data lands in.",
        ],
        tone: "info",
      },
      {
        kind: "example",
        title: "Worked example: DOM source → sink",
        body: [
          "Source: `location.search` — the query string of the URL, fully attacker-controlled (a visitor can put anything there and send the link to a victim).",
          "Sink: `element.innerHTML = ...` — this specific JavaScript property parses its string argument AS HTML and inserts real elements, including executing any `<script>`-equivalent content inside it (actually `innerHTML` itself won't run a literal `<script>` tag, but WILL run `<img src=x onerror=...>` because that's an element with an attribute, not a script tag).",
          "Putting them together: if a page runs `document.getElementById('greeting').innerHTML = 'Hello, ' + new URLSearchParams(location.search).get('name')`, then visiting `?name=<img src=x onerror=alert(1)>` causes the browser to build a real `<img>` element from that string and execute its `onerror` handler — all without the server ever seeing the payload, since this logic runs entirely in the browser.",
          "The fix: assign to `element.textContent` instead, which always treats its argument as literal text, never as markup to parse.",
        ],
        code: `// Source: location.search
const params = new URLSearchParams(window.location.search);
const name = params.get('name');

// Sink: innerHTML (dangerous — parses the string as HTML)
document.getElementById('greeting').innerHTML = \`Hello, \${name}\`;

// Safe alternative: textContent never parses markup
document.getElementById('greeting').textContent = \`Hello, \${name}\`;`,
        tone: "offense",
        check: {
          type: "mc",
          q: "Why does switching from `innerHTML` to `textContent` fix the DOM XSS above?",
          options: [
            "textContent is faster to execute",
            "textContent always treats its argument as literal text and never parses it as HTML/markup",
            "textContent blocks all URL parameters",
            "textContent only works in Chrome",
          ],
          answer: 1,
          why: [
            "Performance is not the relevant property here.",
            "Correct — textContent inserts the exact characters given as visible text, never interpreting them as tags or attributes.",
            "textContent has no awareness of URL parameters; it simply doesn't parse its input as markup.",
            "textContent is a standard DOM API supported broadly across browsers.",
          ],
          explain: "The vulnerability exists because innerHTML re-parses its string as HTML. textContent never parses — it just displays the literal characters, so an <img onerror=...> payload becomes inert text instead of a real element.",
        },
      },
      {
        kind: "explain",
        title: "CSP: the safety net, not the fix",
        body: [
          "Content Security Policy (CSP) is a response header that tells the browser which sources of script are allowed to run, e.g. `script-src 'self'` only allows scripts loaded from the site's own origin, blocking most inline `<script>` and `onerror=` style payloads outright.",
          "It's valuable defense-in-depth, but not a substitute for fixing the context-aware encoding issue: bypasses exist (an uploadable JSONP endpoint under the same origin, dangling markup injection, DOM clobbering), and not every legacy app can adopt a strict policy without breaking functionality.",
        ],
        tone: "defense",
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Applying HTML-entity encoding to data that lands inside a JavaScript string — it does nothing there, because the JS engine never interprets HTML entities; you need JS-aware escaping instead.",
          "Assuming `innerHTML` and `textContent` are interchangeable performance-wise alternatives — they have fundamentally different parsing behaviour, not just different speed.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "A page does `<div id=\"msg\" onclick=\"show('PAYLOAD')\">`. A visitor's PAYLOAD contains a `'`. What context is this, and what does that quote allow an attacker to do?",
        ],
      },
      {
        kind: "relevance",
        title: "What this proves — and doesn't",
        body: [
          "Finding an unescaped reflection inside a specific context (attribute, JS string, HTML body) tells you exactly which payload shape will confirm execution there — it does not mean every input on the page shares that same context or vulnerability.",
          "When reporting, always show the exact sink (innerHTML, document.write, eval, etc.) your PoC relies on — that's what a developer needs to find and fix the specific line of code.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        ref: "Why one defense doesn't fit all contexts",
        q: "Which encoding is most appropriate when reflecting user input inside a `<script>` block as a JavaScript string value?",
        options: [
          "HTML Entity Encoding (&lt;)",
          "URL Encoding (%3C)",
          "JavaScript-specific string escaping (e.g. \\x27 for a quote)",
          "Base64 Encoding of the whole page",
        ],
        answer: 2,
        why: [
          "HTML entities are decoded by HTML parsers, not JavaScript engines — they have no effect inside a JS string.",
          "URL encoding is meant for data traveling inside a URL, not for literals inside JS source.",
          "Correct — a JS engine never decodes HTML entities; to stop a character like a quote from closing the string early, you need JS-specific escaping.",
          "Base64 would break the page's functionality entirely; it's not an escaping mechanism for inline data.",
        ],
        hints: ["Think about what parser actually reads this content — HTML parser, or JS engine?", "Does a JS engine decode &lt; style entities?"],
        explain: "In a JavaScript context, HTML entities aren't decoded by the JS engine. You need JS-specific escaping to prevent breaking out of the string.",
      },
      {
        type: "fill",
        ref: "Worked example: DOM source → sink",
        q: "Complete a safe, non-destructive DOM XSS PoC that reveals the current origin without touching cookies:",
        answers: ["alert(document.domain)", "alert(window.origin)"],
        hints: ["Use the alert function.", "Access a property of the document or window object that reveals the site's origin."],
        explain: "alert(document.domain) (or alert(window.origin)) proves script execution without reading sensitive data like cookies, which may be protected by HttpOnly anyway.",
      },
      {
        type: "match",
        ref: "Worked example: DOM source → sink",
        q: "Match each item to its role in a client-side XSS data flow.",
        pairs: [
          ["innerHTML", "Dangerous sink — parses its argument as HTML"],
          ["location.hash", "Source — attacker-controlled data from the URL"],
          ["textContent", "Safe alternative — always treats input as literal text"],
          ["script-src", "CSP directive restricting allowed script origins"],
        ],
        hints: ["Which one handles input as raw text, never parsing it?", "Which one is part of the URL, controlled by whoever shares the link?", "Which one actually renders HTML markup?"],
        explain: "Understanding the flow from sources (attacker-controlled data) to sinks (where it's unsafely used) is the core of diagnosing DOM XSS; CSP directives like script-src are the browser-level mitigation layered on top.",
      },
      {
        type: "mc",
        ref: "Why one defense doesn't fit all contexts",
        q: "`<input value='` + input + `'>` — a visitor's input contains a single quote `'`. What's the danger here, specifically?",
        options: [
          "Nothing, single quotes are always safe in HTML",
          "The quote closes the attribute value early, letting the rest of the input become a new attribute or tag the attacker controls",
          "It causes a server crash",
          "It only matters in XML, not HTML",
        ],
        answer: 1,
        why: [
          "Quotes delimit attribute boundaries — they are specifically unsafe when unescaped inside a quoted attribute.",
          "Correct — this is attribute-context breakout: the user's quote ends the attribute early, letting subsequent text be parsed as new markup (e.g. another attribute like onmouseover=).",
          "This is a client-side parsing issue, not a server crash.",
          "This applies directly to HTML attribute parsing, not just XML.",
        ],
        hints: ["What does a quote normally do inside a quoted HTML attribute?", "What happens to the text right after that quote closes?"],
        explain: "In attribute context, breaking out means closing the quoted value early with an unescaped quote, after which the attacker's remaining text is parsed as new markup — e.g. a new event-handler attribute.",
      },
    ],
  },
  {
    id: "command-injection",
    title: "OS Command Injection",
    summary: "Learning how to break out of application logic to execute arbitrary operating system commands.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "Explain why passing user input to a system shell is dangerous, detect command injection even with no visible output, and distinguish it conceptually from SQLi/XSS despite the shared root cause.",
        ],
      },
      {
        kind: "intuition",
        title: "Why this bug exists at all",
        body: [
          "This is the exact same root cause you've now seen twice: untrusted data and executable instructions sharing one channel. Here, the 'interpreter' is the operating system's SHELL — the program (bash, cmd.exe) that reads a line of text and decides which parts are a command name, which parts are arguments, and which special characters mean 'run another command here'.",
          "If a web app builds a shell command by gluing in user input — e.g. `ping -c 4 ` + host — and the shell is handed that whole string to interpret, any shell-special character the user included (not just a plain hostname) is interpreted according to the shell's own rules, not treated as inert text.",
        ],
      },
      {
        kind: "prereq",
        title: "Prerequisite: shell command separators",
        body: [
          "A Unix shell reads `;` as 'run this command, then run the next one regardless of outcome'. `&&` means 'run the next command only if this one SUCCEEDED'. `||` means 'run the next command only if this one FAILED'. `|` pipes one command's output into the next command's input.",
          "Backticks `` `command` `` or `$(command)` mean 'run this command first, and substitute its output here' — useful for an attacker even inside what looks like a single argument.",
        ],
        code: `# Vulnerable server-side code (pseudocode):
system("ping -c 4 " + userInput)

# If userInput is a plain hostname, nothing unusual happens:
ping -c 4 8.8.8.8

# If userInput is "8.8.8.8; cat /etc/passwd":
ping -c 4 8.8.8.8; cat /etc/passwd
              ^ the shell treats this as TWO separate commands`,
        check: {
          type: "mc",
          q: "Which operator runs the second command only if the first one FAILED (returned a non-zero exit code)?",
          options: [";", "&&", "||", "|"],
          answer: 2,
          why: [
            "`;` runs the second command regardless of whether the first succeeded or failed.",
            "`&&` runs the second command only if the first SUCCEEDED — the opposite of what's asked.",
            "Correct — `||` is the shell's logical OR: it runs the right-hand command only when the left-hand one failed.",
            "`|` pipes output from one command into another; it doesn't check success/failure.",
          ],
          explain: "|| is a shell logical-OR: the second command only runs if the first exits with failure (non-zero status) — useful for an attacker as a fallback chain.",
        },
      },
      {
        kind: "explain",
        title: "Blind detection: when there's no output",
        body: [
          "If the application doesn't display the command's output anywhere in the response, that's 'blind' command injection — you can't read results directly, but you can still detect execution through a SIDE EFFECT.",
          "Timing: inject `; sleep 10` and measure whether the response takes roughly 10 seconds longer than a baseline request — a reliable signal because you control the exact delay and can repeat it with different durations to rule out coincidence (e.g. network jitter).",
          "Out-of-band (OOB): inject `; curl http://your-server.example/proof` and watch your own server's access logs for an incoming request — if it arrives, the command executed on the target, even though the target never showed you anything.",
        ],
        tone: "info",
      },
      {
        kind: "example",
        title: "Worked example: confirming with timing",
        body: [
          "Step 1 — baseline: request the vulnerable endpoint normally (e.g. `?host=8.8.8.8`) and note the response time, say ~200ms.",
          "Step 2 — inject a short delay: request `?host=8.8.8.8; sleep 5` and measure again. If it now takes ~5.2 seconds, that's a strong signal.",
          "Step 3 — vary the delay to rule out coincidence: request `?host=8.8.8.8; sleep 10`. If the delay scales to ~10.2 seconds, the correlation between YOUR chosen duration and the observed delay confirms execution — a one-off slow response could be server load, but a delay that tracks your input precisely cannot be coincidence.",
        ],
        code: `# Step 1
GET /ping?host=8.8.8.8        → ~200ms

# Step 2
GET /ping?host=8.8.8.8; sleep 5    → ~5200ms

# Step 3 — vary the duration to rule out coincidence
GET /ping?host=8.8.8.8; sleep 10   → ~10200ms   ← confirmed: delay tracks your input`,
        check: {
          type: "order",
          q: "Order the steps for confirming blind command injection via timing.",
          items: [
            "Measure a baseline response time with normal input",
            "Inject a short sleep (e.g. sleep 5) and measure again",
            "Inject a different sleep duration (e.g. sleep 10) to see if the delay changes to match",
            "Conclude execution is confirmed because the delay consistently tracks your chosen duration",
          ],
          explain: "A single slow response could be coincidence (server load). Varying the duration and seeing the delay track your input precisely is what rules that out.",
        },
      },
      {
        kind: "explain",
        title: "Prevention, and a related flaw: path traversal",
        body: [
          "The real fix is to never build a shell command string from concatenation at all. APIs like Node's `execFile` (or Python's `subprocess.run` with a list of arguments) pass the command and its arguments as SEPARATE values directly to the operating system, bypassing the shell's parsing entirely — there's no string for a `;` or `|` to hide in.",
          "Path traversal is a related-but-distinct flaw: instead of injecting shell syntax, the attacker manipulates a FILE PATH parameter with `../` sequences to escape the intended directory, e.g. `?file=../../etc/passwd`. A common mistake fix is stripping `../` only once, which attackers bypass with `....//` (becomes `../` after one strip).",
        ],
        tone: "defense",
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Assuming no visible output means 'not vulnerable' — this is exactly what blind injection looks like; you must test for side effects (timing, OOB) before concluding there's no bug.",
          "Stripping `../` once and assuming path traversal is fixed — recursive or overlapping patterns like `....//` can defeat a single-pass filter.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "An endpoint `?host=` feeding a `ping` command shows no output at all, ever (success or failure). You send `?host=8.8.8.8; sleep 7` and the response consistently takes ~7 seconds longer. A colleague says 'that could just be server load.' What's your counter-argument, using the same reasoning as the worked example?",
        ],
      },
      {
        kind: "relevance",
        title: "What this proves — and doesn't",
        body: [
          "A confirmed timing or OOB signal proves the application executes attacker-influenced shell commands — a critical-severity finding, since it often leads to full server compromise.",
          "It does NOT by itself prove what data is reachable or that you've achieved any particular access level — further authorised testing (always within scope) is needed to establish actual impact, exactly as with SQLi and XSS.",
        ],
      },
    ],
    exercises: [
      {
        type: "order",
        ref: "Worked example: confirming with timing",
        q: "Order the steps for safely validating a suspected command injection.",
        items: [
          "Identify a parameter passed to a system call",
          "Inject a timing payload like '; sleep 5'",
          "Observe a delay in the response matching roughly 5 seconds",
          "Confirm execution by varying the sleep duration and checking the delay tracks it",
        ],
        hints: ["Start by finding the input.", "Use a command that causes a measurable delay.", "Verify the delay is consistent with your chosen input, not coincidental."],
        explain: "Blind injection is confirmed by observing time delays that correlate precisely with your injected sleep durations — not just a single slow response.",
      },
      {
        type: "mc",
        ref: "Prerequisite: shell command separators",
        q: "Which character sequence can be used to execute a command only if the previous command SUCCEEDED?",
        options: [";", "&&", "||", "|"],
        answer: 1,
        why: [
          "`;` runs the next command regardless of success or failure.",
          "Correct — `&&` is the shell's logical AND: the right-hand command runs only if the left-hand one succeeded (exit code 0).",
          "`||` runs the next command only on failure — the opposite condition.",
          "`|` pipes data between commands; it isn't conditional on success/failure.",
        ],
        hints: ["Think about logical operators.", "&& reads like 'and' — both need to happen."],
        explain: "The && (AND) operator in shells executes the second command only if the first one returns a zero exit code (succeeds).",
      },
      {
        type: "fill",
        ref: "Prevention, and a related flaw: path traversal",
        q: "What sequence is used to move up one directory level in a path traversal attack?",
        answers: ["../", "..\\"],
        hints: ["It uses two dots.", "It includes a directory separator."],
        explain: "The dot-dot-slash sequence (../) is the standard way to reference the parent directory in most file systems, and is the basis of path traversal attacks.",
      },
      {
        type: "mc",
        ref: "Prevention, and a related flaw: path traversal",
        q: "Why does passing arguments as a list (e.g. execFile('ping', ['-c', '4', host])) prevent command injection, unlike string concatenation into a shell command?",
        options: [
          "It's faster to execute",
          "The arguments are passed directly to the operating system without ever being parsed by a shell, so separator characters like ; have no special meaning",
          "It automatically encrypts the input",
          "It only works for the ping command specifically",
        ],
        answer: 1,
        why: [
          "Performance isn't the relevant property here.",
          "Correct — bypassing the shell entirely means there's no shell syntax parser to exploit; `;` or `|` in an argument is just a literal character, not a separator.",
          "This technique has nothing to do with encryption.",
          "This pattern generalises to any command, not just ping.",
        ],
        hints: ["What's the difference between 'the shell parses a string' and 'arguments are passed directly'?"],
        explain: "Argument-array APIs bypass shell parsing entirely — there's no string for shell-special characters to hide in, so injection via separators becomes impossible.",
      },
    ],
  },
  {
    id: "trust-boundaries",
    title: "Trust Boundaries & Defenses",
    summary: "Defining where data can be trusted and how to implement robust injection defenses.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "Identify the trust boundary in a given data flow, and name the correct root-cause defense (not just a mitigation) for SQLi, XSS, and command injection.",
        ],
      },
      {
        kind: "intuition",
        title: "The pattern behind every injection bug in this unit",
        body: [
          "SQLi, XSS, and command injection are three instances of ONE underlying mistake: untrusted data crossing into a context where it's interpreted as CODE instead of staying DATA. The database engine, the browser's HTML/JS parser, and the shell are each just a different 'interpreter' that got confused about where the attacker's data ends and executable instructions begin.",
          "A TRUST BOUNDARY is the conceptual line where data moves from an untrusted source (anything originating in a visitor's browser — URL, form fields, headers, cookies, uploaded files) into a trusted processing zone (your server's logic, your database, your shell). Every injection bug in this unit happens because data crossed that line without being properly separated from code on the other side.",
        ],
      },
      {
        kind: "prereq",
        title: "Recap: validation vs. encoding — not the same tool",
        body: [
          "INPUT VALIDATION checks that data matches an expected FORMAT before you use it — e.g. 'is this a number?', 'is this a valid email shape?'. It rejects or normalises malformed input.",
          "OUTPUT ENCODING changes how data is REPRESENTED for the specific context it's about to be placed into — e.g. turning `<` into `&lt;` before inserting into HTML. It doesn't reject anything; it makes any value safe to place in that context.",
          "These solve different problems: validation alone doesn't stop injection if the data is still valid-looking but dangerous in context (e.g. a company name legitimately containing an apostrophe, like O'Brien, is perfectly valid input but still breaks a naively-concatenated SQL query). Encoding, applied at the point of use, closes that gap.",
        ],
      },
      {
        kind: "explain",
        title: "The root-cause fix for each class",
        body: [
          "SQL injection: PARAMETERISED QUERIES (prepared statements). The query's structure is sent to the database separately from its data values — the database parses the SQL shape first, then substitutes the data values afterward, so a quote inside a data value can never be read as SQL syntax, no matter what it contains.",
          "XSS: CONTEXT-AWARE OUTPUT ENCODING. As covered in the previous lesson, the correct encoding function depends on exactly where in the HTML/JS/attribute structure the data lands.",
          "Command injection: AVOID THE SHELL ENTIRELY using argument-array APIs (e.g. `execFile`), so there's no string for shell metacharacters to be parsed from.",
          "Notice the shared principle across all three: keep the DATA channel and the CODE/STRUCTURE channel separate, enforced by the underlying API — not by trying to filter out 'dangerous-looking' characters yourself, which is fragile and easy to bypass.",
        ],
        code: `// SQL injection fix — parameterised query:
db.execute("SELECT * FROM users WHERE id = ?", [userId]);
// the database treats "?" as a hole for DATA, never as SQL syntax, regardless of userId's content`,
        tone: "defense",
        check: {
          type: "mc",
          q: "Why do parameterised queries prevent SQL injection even if userId contains a quote character?",
          options: [
            "The database automatically deletes quotes from input",
            "The query structure is parsed first and separately from the data; the data is substituted afterward and is never re-interpreted as SQL syntax",
            "Parameterised queries only work with numeric values",
            "They encrypt the input before sending it",
          ],
          answer: 1,
          why: [
            "Nothing is deleted — the full value, quotes and all, is kept intact as data.",
            "Correct — this is exactly the separation that makes injection structurally impossible via this channel: SQL syntax and data are sent and parsed through different channels.",
            "Parameterised queries handle text and other data types just as safely as numbers.",
            "Encryption isn't the mechanism involved; it's about parsing order and channel separation.",
          ],
          explain: "Parameterised queries send the query shape and the data separately. The database parses the SQL structure first; values are substituted afterward purely as data, so a quote inside a value is just a quote — never reinterpreted as code.",
        },
      },
      {
        kind: "example",
        title: "Worked example: spotting the trust boundary in a code snippet",
        body: [
          "Given: `app.post('/comment', (req,res) => { db.run(\"INSERT INTO comments VALUES ('\" + req.body.text + \"')\"); })`. Where is the trust boundary, and where is it being crossed unsafely?",
          "`req.body.text` is data that came directly from the visitor's HTTP request — untrusted by definition, since the server has no control over what a client sends. The trust boundary is crossed the moment that value is glued into the SQL string via `+` concatenation, before the database ever gets to treat it purely as data.",
          "The fix doesn't change WHERE the boundary is (you can't avoid receiving untrusted input) — it changes HOW the data crosses it: via a parameter placeholder (`?` or `$1`) instead of string concatenation, so the database keeps the data on the 'data' side of its own internal boundary.",
        ],
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Relying on client-side JavaScript validation as a security control — it only improves UX for honest users; an attacker can send raw HTTP requests with any tool (curl, Burp Repeater), bypassing the browser and any JS checks entirely.",
          "Trying to 'blocklist' dangerous characters (quotes, `<`, `;`) instead of using the structural fixes above — blocklists are notoriously incomplete, and legitimate data (like O'Brien, or a `<` in a maths discussion) gets wrongly rejected or still slips through in an unanticipated encoding.",
        ],
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "A developer says: 'We're safe from XSS because our login form has JavaScript that rejects any input containing `<script>`.' Explain the two separate reasons this claim is weak, using what you now know about trust boundaries and validation vs. encoding.",
        ],
      },
      {
        kind: "relevance",
        title: "What this proves — and doesn't",
        body: [
          "Recognising the trust boundary in a code snippet or request flow lets you predict, before even testing, which inputs are worth probing for injection — anywhere untrusted data crosses into a database/HTML/shell-interpreting context without a structural separation mechanism.",
          "It does not replace actual testing — a defense might exist elsewhere in the stack (an ORM wrapping queries safely, a templating engine auto-escaping output) that neutralises a theoretical boundary crossing. Confirm behaviourally, as taught earlier in this unit, before reporting.",
        ],
      },
    ],
    exercises: [
      {
        type: "match",
        ref: "The root-cause fix for each class",
        q: "Match each vulnerability class to its structural, root-cause fix.",
        pairs: [
          ["SQL Injection", "Parameterised queries (prepared statements)"],
          ["XSS", "Context-aware output encoding"],
          ["Command Injection", "Argument-array APIs that bypass the shell"],
          ["Client-side validation", "UX improvement only — not a security boundary"],
        ],
        hints: ["How do you stop SQLi structurally?", "What stops the browser from treating data as markup/code?", "Is client-side code trustworthy for enforcement?"],
        explain: "Each injection class has a root-cause fix that separates data from code/structure at the API level, rather than trying to filter dangerous-looking input after the fact.",
      },
      {
        type: "mc",
        ref: "Common mistakes",
        q: "Why is client-side validation (e.g. JavaScript in the browser) insufficient as a security control on its own?",
        options: [
          "It is too slow to process complex logic",
          "It can be bypassed entirely by sending raw HTTP requests with a proxy or a tool like curl, skipping the browser",
          "Browsers do not support regex validation",
          "It only works on mobile devices",
        ],
        answer: 1,
        why: [
          "Performance isn't the issue — client-side checks run fine; the issue is they can be skipped entirely.",
          "Correct — an attacker controls their own HTTP client and can send any request directly, bypassing any JavaScript checks that only run inside an actual browser session.",
          "Regex is fully supported client-side; that's not the limiting factor.",
          "This limitation is universal, not device-specific.",
        ],
        hints: ["Can an attacker control the request without using the real browser form at all?", "Where does the trust boundary actually start — the browser, or the server?"],
        explain: "Attackers can bypass the browser entirely by sending raw HTTP requests using tools like Burp Suite or curl, ignoring any client-side JavaScript checks — enforcement must happen server-side, where the trust boundary actually is.",
      },
      {
        type: "fill",
        ref: "The root-cause fix for each class",
        q: "In a prepared statement, what character is commonly used as a positional placeholder for a data value?",
        answers: ["?", ":name"],
        hints: ["It's a single punctuation mark in many SQL libraries.", "It represents an unknown value at the time the query structure is parsed."],
        explain: "The question mark (?) — or named placeholders like :id — are standard syntax for data parameters in prepared statement APIs, keeping data separate from the parsed query structure.",
      },
      {
        type: "mc",
        ref: "Recap: validation vs. encoding — not the same tool",
        q: "A company name field correctly validates that input is 'a non-empty string under 100 characters' and accepts the legitimate value `O'Brien & Sons`. Why can this still cause a SQL injection if the value is concatenated directly into a query?",
        options: [
          "O'Brien & Sons is too long to be valid input",
          "Format validation doesn't check whether a character (the apostrophe) is dangerous in the SQL context the value will be placed into — that's a job for encoding/parameterisation, not validation",
          "The ampersand character is always rejected by databases",
          "This can never cause an issue because the input passed validation",
        ],
        answer: 1,
        why: [
          "Length isn't the issue — the value is legitimate and well within reasonable limits.",
          "Correct — this is exactly the gap between validation (format correctness) and encoding/parameterisation (context safety) described in this lesson: a value can be perfectly valid and still dangerous if glued into SQL text.",
          "Ampersands are ordinary characters in most SQL text values; they aren't universally rejected.",
          "Passing format validation says nothing about SQL-context safety — that's the whole point of this lesson's distinction.",
        ],
        hints: ["Is 'valid-looking input' the same as 'safe to concatenate into SQL'?", "What's the actual dangerous character here, and why would validation allow it?"],
        explain: "Validation and encoding solve different problems. A legitimately formatted value like O'Brien & Sons can still contain a character (') that's dangerous in a SQL context if parameterised queries or escaping aren't used.",
      },
    ],
  },
];
