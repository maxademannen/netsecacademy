import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "xss-contexts",
    title: "XSS Contexts & DOM Sinks",
    summary: "Mastering how different injection points require specific encoding and understanding DOM-based flows.",
    cards: [
      {
        title: "The Importance of Context",
        body: [
          "XSS isn't one-size-fits-all. A payload that works in an HTML body (`<div>PAYLOAD</div>`) will fail inside an HTML attribute (`<input value='PAYLOAD'>`) or a JavaScript block.",
          "In HTML context, you need `<script>`. In attribute context, you might need to break out with `'` or `\"`. In JS context, you might need to break the string or the script tag itself.",
          "Modern defenses use context-aware encoding. Standard HTML entity encoding (like &lt;) works for body text but may be insufficient or bypassable in other locations."
        ],
        tone: "info"
      },
      {
        title: "DOM Sources and Sinks",
        body: [
          "DOM XSS occurs when a 'Source' (user-controlled input like `location.hash` or `document.referrer`) flows into a dangerous 'Sink' (a function that executes or renders input).",
          "Common dangerous sinks include `eval()`, `setTimeout()`, and `element.innerHTML`. Safer alternatives like `textContent` or `innerText` automatically handle encoding.",
          "A classic safe PoC (Proof of Concept) is `alert(document.domain)`. It proves execution while identifying the exact origin without accessing sensitive cookies."
        ],
        code: "// Source: location.search\nconst params = new URLSearchParams(window.location.search);\nconst name = params.get('name');\n\n// Sink: innerHTML (Dangerous)\ndocument.getElementById('greeting').innerHTML = `Hello, ${name}`;",
        tone: "offense"
      },
      {
        title: "CSP: The Safety Net",
        body: [
          "Content Security Policy (CSP) is a browser-level defense that restricts where scripts can be loaded from and whether inline scripts can run.",
          "A strong CSP (e.g., `script-src 'self'`) can block XSS even if an injection vulnerability exists, by preventing the browser from executing the injected code.",
          "However, CSP is not a replacement for proper encoding; bypasses exist (like JSONP or open redirects) and not all browsers support every directive."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "Which encoding is most appropriate when reflecting user input inside a <script> block variable?",
        options: [
          "HTML Entity Encoding (&lt;)",
          "URL Encoding (%3C)",
          "Unicode/JavaScript Hex Encoding (\\x3C)",
          "Base64 Encoding"
        ],
        answer: 2,
        explain: "In a JavaScript context, HTML entities aren't decoded by the JS engine. You need JS-specific escaping (like Unicode escapes) to prevent breaking out of the string.",
        hints: [
          "Think about what the JS engine actually parses.",
          "HTML entities are for HTML parsers, not JS engines.",
          "Unicode escapes prevent the character from being treated as syntax."
        ]
      },
      {
        type: "fill",
        q: "Complete the safe DOM XSS PoC that shows the current origin:",
        answers: ["alert(document.domain)", "alert(window.origin)"],
        explain: "Using alert(document.domain) is a standard way to prove XSS without accessing cookies, which might be blocked by HttpOnly or trigger noise.",
        hints: [
          "Use the alert function.",
          "Access the domain property of the document object.",
          "Alternatively, use window.origin."
        ]
      },
      {
        type: "match",
        q: "Match each DOM API to its role in client-side data flow.",
        pairs: [
          ["innerHTML", "Dangerous Sink"],
          ["location.hash", "Source"],
          ["textContent", "Safe Alternative"],
          ["script-src", "CSP Directive"]
        ],
        explain: "Understanding the flow from sources to sinks is key to DOM XSS. CSP directives like script-src help mitigate the impact.",
        hints: [
          "Which one handles input as raw text?",
          "Which one is a part of the URL controlled by the user?",
          "Which one executes HTML?"
        ]
      }
    ]
  },
  {
    id: "command-injection",
    title: "OS Command Injection",
    summary: "Learning how to break out of application logic to execute arbitrary operating system commands.",
    cards: [
      {
        title: "Command Separators",
        body: [
          "Command injection happens when an application passes unvalidated user input to a system shell (like bash or cmd.exe).",
          "Attackers use separators to chain their own commands. Common characters include `;`, `&&` (and), `||` (or), `|` (pipe), and newlines (`\\n`).",
          "In Unix-like systems, backticks `` `command` `` or `$(command)` can also be used for inline execution."
        ],
        code: "# Vulnerable PHP code\nsystem(\"ping -c 4 \" . $_GET['host']);\n\n# Payload\n# host=8.8.8.8; cat /etc/passwd",
        tone: "offense"
      },
      {
        title: "Blind Detection",
        body: [
          "If the application doesn't return the command output, it's 'Blind Command Injection'.",
          "Detection relies on side effects: `sleep 10` (Timing) or `curl attacker.com` (Out-of-Band/OOB).",
          "Timing attacks are reliable: if the server takes 10 seconds longer to respond, your `sleep` command likely executed."
        ],
        tone: "info"
      },
      {
        title: "Prevention & Path Traversal",
        body: [
          "Never use string concatenation for commands. Use APIs that accept an array of arguments (e.g., `execFile` in Node.js), which bypasses shell parsing.",
          "Path Traversal (`../`) is a related flaw where attackers access files outside the intended directory. Normalization pitfalls occur when `../` is stripped once but not recursively.",
          "Defense involves 'allow-listing' valid inputs and using built-in path resolution functions that prevent escaping the base directory."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "order",
        q: "Order the steps for safely validating a suspected command injection.",
        items: [
          "Identify a parameter passed to a system call",
          "Inject a timing payload like '; sleep 5'",
          "Observe a 5-second delay in response",
          "Confirm execution by varying the sleep duration"
        ],
        explain: "Blind injection is confirmed by observing time delays that correlate with your injected sleep commands.",
        hints: [
          "Start by finding the input.",
          "Use a command that causes a delay.",
          "Verify that the delay is consistent with your input."
        ]
      },
      {
        type: "mc",
        q: "Which character can be used to execute a command only if the previous command failed?",
        options: [
          ";",
          "&&",
          "||",
          "|"
        ],
        answer: 2,
        explain: "The || (OR) operator in shells executes the second command only if the first one returns a non-zero exit code (fails).",
        hints: [
          "Think about logical operators.",
          "&& is for success.",
          "|| is for failure."
        ]
      },
      {
        type: "fill",
        q: "What sequence is used to move up one directory level in a path traversal attack?",
        answers: ["../", "..\\"],
        explain: "The dot-dot-slash sequence is the standard way to reference the parent directory in most file systems.",
        hints: [
          "It uses two dots.",
          "It includes a directory separator.",
          "It's used to 'climb' the file tree."
        ]
      }
    ]
  },
  {
    id: "trust-boundaries",
    title: "Trust Boundaries & Defenses",
    summary: "Defining where data can be trusted and how to implement robust injection defenses.",
    cards: [
      {
        title: "Defining the Boundary",
        body: [
          "A 'Trust Boundary' is the point where data moves from an untrusted source (like a user's browser) to a trusted zone (the server's internal logic).",
          "Rule #1: All input is evil until proven otherwise. Validation must happen on the server. Client-side checks are for UX, not security.",
          "Once data crosses the boundary, it must be handled according to its destination: SQL queries, HTML rendering, or shell commands."
        ],
        tone: "info"
      },
      {
        title: "Parameterized Queries",
        body: [
          "The primary defense against SQLi is the use of Parameterized Queries (Prepared Statements).",
          "They separate the query structure from the data. The database engine parses the query first, then treats the parameters strictly as data, never as executable code.",
          "This makes it mathematically impossible for an attacker to change the query's logic via a parameter."
        ],
        code: "// Secure: Using placeholders\ndb.execute(\"SELECT * FROM users WHERE id = ?\", [userId]);",
        tone: "defense"
      },
      {
        title: "Output Encoding vs Validation",
        body: [
          "Input Validation ensures data follows a format (e.g., is this an integer?). Output Encoding ensures data is safe for the context it's displayed in.",
          "For XSS, output encoding is the strongest defense. If you encode `<` as `&lt;`, the browser won't execute it as a tag.",
          "When reporting a finding, always use a non-destructive PoC (like `alert()`) and explain the impact on the trust boundary."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "match",
        q: "Match each vulnerability class to its root-cause fix.",
        pairs: [
          ["SQL Injection", "Parameterized Queries"],
          ["XSS", "Contextual Output Encoding"],
          ["Command Injection", "Argument Arrays / No Shell"],
          ["Client-side Validation", "UX Improvement Only"]
        ],
        explain: "Each type of injection has a 'gold standard' defense that addresses the root cause: mixing data with code.",
        hints: [
          "How do you stop SQLi?",
          "What stops the browser from running scripts?",
          "Is client-side code trustworthy?"
        ]
      },
      {
        type: "mc",
        q: "Why is client-side validation (e.g., JavaScript in the browser) insufficient for security?",
        options: [
          "It is too slow to process complex logic",
          "It can be easily bypassed using a proxy or custom client",
          "Browsers do not support regex validation",
          "It only works on mobile devices"
        ],
        answer: 1,
        explain: "Attackers can bypass the browser entirely by sending raw HTTP requests using tools like Burp Suite or cURL, ignoring any JavaScript checks.",
        hints: [
          "Can an attacker control the browser?",
          "Can an attacker send requests without a browser?",
          "Where does the 'trust boundary' start?"
        ]
      },
      {
        type: "fill",
        q: "In a prepared statement, what character is commonly used as a placeholder for data?",
        answers: ["?", ":name"],
        explain: "The question mark (?) or named placeholders (like :id) are standard syntax for data parameters in SQL libraries.",
        hints: [
          "It's a single punctuation mark.",
          "It represents an unknown value at prepare time.",
          "Often used in 'WHERE id = ...'"
        ]
      }
    ]
  }
];
