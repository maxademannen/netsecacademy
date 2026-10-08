import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "encoding",
    title: "The Art of Encoding",
    summary: "Understand how data changes meaning across URL, HTML, and Base64 contexts.",
    cards: [
      {
        title: "Context is Everything",
        body: [
          "Data is interpreted differently depending on where it sits. A less-than sign '<' is a literal character in a text file, but it starts a tag in HTML.",
          "To prevent confusion, we use encoding. In a **URL**, space becomes `%20`. In **HTML**, `<` becomes `&lt;` or `&#60;`.",
          "Attackers often chain encodings (Double Encoding) to bypass security filters that only decode once."
        ],
        code: "URL: search?q=a%20b\nHTML: <div>&lt;script&gt;</div>\nDouble: %2520 (Decodes to %20, then space)",
        tone: "info"
      },
      {
        title: "Base64: Not Encryption",
        body: [
          "Base64 is a binary-to-text encoding scheme. It represents binary data using 64 printable characters (A-Z, a-z, 0-9, +, /).",
          "It is frequently used in **Authorization: Basic** headers and within JWT (JSON Web Tokens).",
          "Crucially, Base64 is not encryption. Anyone can decode it instantly without a key."
        ],
        code: "echo -n 'admin' | base64\n# Output: YWRtaW4=",
        tone: "info"
      },
      {
        title: "Content-Type Confusion",
        body: [
          "Modern apps handle multiple formats. A server might expect `application/x-www-form-urlencoded` (key=val) but also accept `application/json` ({\"key\":\"val\"}).",
          "Sometimes, security rules only apply to one format. By switching the `Content-Type` and re-encoding your payload, you might bypass a Web Application Firewall (WAF)."
        ],
        code: "POST /login\nContent-Type: application/json\n\n{\"user\": \"admin\", \"pass\": \"123\"}",
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "Which encoding is specifically used to safely include characters in a web address (URI)?",
        options: [
          "HTML Entities",
          "Base64",
          "URL Encoding (Percent Encoding)",
          "UTF-16"
        ],
        answer: 2,
        explain: "URL encoding uses a percent sign followed by two hex digits to represent special characters in a URI.",
        hints: [
          "Think about what happens to a space in a Google search URL.",
          "It often involves percent signs (%)."
        ]
      },
      {
        type: "match",
        q: "Match the character/string to its encoded context.",
        pairs: [
          ["%22", "URL Encoded Quote"],
          ["&quot;", "HTML Encoded Quote"],
          ["YWRtaW4=", "Base64 'admin'"],
          ["%2522", "Double URL Encoded"]
        ],
        explain: "Each context requires a different representation to ensure the data isn't misinterpreted as code or structural delimiters.",
        hints: [
          "&...; is usually HTML.",
          "%... is usually URL.",
          "= at the end is a common Base64 padding characteristic."
        ]
      },
      {
        type: "fill",
        q: "If you see a string like 'dGVzdA==', which encoding format is most likely being used?",
        answers: ["base64"],
        explain: "Base64 strings often end with '==' or '=' as padding and use a specific alphanumeric character set.",
        hints: [
          "It's a binary-to-text scheme.",
          "It ends in '=' padding."
        ]
      }
    ]
  },
  {
    id: "authn-vs-authz",
    title: "AuthN vs. AuthZ",
    summary: "Master the distinction between identifying a user and checking their permissions.",
    cards: [
      {
        title: "Who vs. What",
        body: [
          "**Authentication (AuthN)** is verifying who you are. (Login forms, 2FA, Biometrics).",
          "**Authorization (AuthZ)** is verifying what you are allowed to do. (Can you delete this post? Can you view the admin panel?).",
          "Most 'Broken Access Control' bugs are failures of AuthZ, not AuthN."
        ],
        tone: "info"
      },
      {
        title: "Horizontal vs. Vertical Escalation",
        body: [
          "**Horizontal PrivEsc**: Accessing data belonging to another user with the *same* rank (e.g., User A viewing User B's private messages).",
          "**Vertical PrivEsc**: Accessing functions belonging to a *higher* rank (e.g., a regular User accessing the Admin dashboard)."
        ],
        tone: "offense"
      },
      {
        title: "The Comparer Mindset",
        body: [
          "To find AuthZ bugs, you need two accounts: 'Attacker' and 'Victim'.",
          "Capture a sensitive request from the Victim, then replay it while using the Attacker's session token. If the server performs the action, you've found a vulnerability.",
          "**Burp Comparer** helps you spot the tiny differences in successful vs. failed responses."
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "A user changes 'user_id=123' to 'user_id=124' in a URL and sees another user's profile. What is this?",
        options: [
          "Vertical Privilege Escalation",
          "Horizontal Privilege Escalation",
          "Broken Authentication",
          "Injection"
        ],
        answer: 1,
        explain: "Since both users are likely at the same privilege level, accessing another's data is Horizontal Privilege Escalation.",
        hints: [
          "Are they moving 'up' a rank or 'sideways' to another user?",
          "It's a type of Broken Access Control."
        ]
      },
      {
        type: "order",
        q: "Order the steps to manually test for Vertical Privilege Escalation.",
        items: [
          "Log in as an Administrator and capture a 'Delete User' request.",
          "Log in as a regular User and obtain their session cookie.",
          "Replace the Admin cookie with the User cookie in the captured request.",
          "Send the modified request and check if the 'Delete' succeeded."
        ],
        explain: "To test authorization, you try to perform a high-privileged action using a low-privileged identity.",
        hints: [
          "You need the high-priv action first.",
          "Then you need the low-priv identity.",
          "The swap happens before the final send."
        ]
      },
      {
        type: "match",
        q: "Match the term to its primary function.",
        pairs: [
          ["Authentication", "Verifying Identity"],
          ["Authorization", "Verifying Permissions"],
          ["AuthN", "Login/Password"],
          ["AuthZ", "RBAC/ACLs"]
        ],
        explain: "AuthN is about Identity; AuthZ is about Access Rights.",
        hints: [
          "N for Name/Identity.",
          "Z for Zone/Authorization."
        ]
      }
    ]
  },
  {
    id: "repro-poc",
    title: "Reproducible PoCs",
    summary: "Learn to build clean, minimal, and professional Proof-of-Concept requests.",
    cards: [
      {
        title: "Minimum Viable Request",
        body: [
          "When reporting a bug, don't just send a screenshot. Send a reproducible HTTP request.",
          "Strip away unnecessary headers like `User-Agent`, `Accept-Language`, and `Referer` unless they are critical to the exploit.",
          "A clean PoC helps developers fix the bug faster and proves it's not a fluke of your browser cache."
        ],
        tone: "info"
      },
      {
        title: "Redacting PII",
        body: [
          "Never include your real session tokens, passwords, or personal data in a bug report.",
          "Replace them with placeholders like `[REDACTED]` or `YOUR_TOKEN_HERE`.",
          "If the bug requires a specific token structure (like a JWT), provide a sample but scramble the signature."
        ],
        tone: "defense"
      },
      {
        title: "cURL Exports",
        body: [
          "The universal language of PoCs is `cURL`. In Burp Suite, you can right-click a request and 'Copy as curl command'.",
          "This allows anyone with a terminal to reproduce your findings instantly without setting up a proxy."
        ],
        code: "curl -X POST https://api.example.com/v1/delete \\\n  -H 'Authorization: Bearer [TOKEN]' \\\n  -d '{\"id\": 101}'",
        tone: "info"
      }
    ],
    exercises: [
      {
        type: "fill",
        q: "Which command-line tool is the industry standard for sharing reproducible HTTP requests?",
        answers: ["curl"],
        explain: "cURL is available on almost every OS and can perfectly replicate complex HTTP requests.",
        hints: [
          "It starts with a 'c'.",
          "Client for URLs."
        ]
      },
      {
        type: "mc",
        q: "Why is it important to 'strip' unnecessary headers from a PoC?",
        options: [
          "To hide the fact that you are using Burp Suite",
          "To isolate the exact parameters causing the vulnerability",
          "To make the request run faster",
          "To bypass the firewall"
        ],
        answer: 1,
        explain: "A minimal PoC proves exactly which parts of the request are malicious, making it easier to debug.",
        hints: [
          "Think about 'noise' vs 'signal'.",
          "It helps the developer find the root cause."
        ]
      },
      {
        type: "mc",
        q: "What should you do with your session cookie before sharing a PoC with a client?",
        options: [
          "Keep it so they can test it themselves",
          "Encrypt it with a password",
          "Redact or replace it with a placeholder",
          "Double-encode it"
        ],
        answer: 2,
        explain: "Sharing live session cookies is a security risk. Always redact PII.",
        hints: [
          "Security professionals protect their own data too.",
          "Placeholder text is your friend."
        ]
      }
    ]
  },
  {
    id: "rest-api-basics",
    title: "REST API Fundamentals",
    summary: "API security starts with understanding how modern web services communicate.",
    cards: [
      {
        title: "REST & JSON",
        body: [
          "Representational State Transfer (REST) is the architectural style of the modern web.",
          "Resources (like `/users/1`) are manipulated using standard methods: `GET` (read), `POST` (create), `PUT` (update), and `DELETE`.",
          "Most REST APIs exchange data in **JSON** format."
        ],
        tone: "info"
      },
      {
        title: "Finding the Map",
        body: [
          "APIs are often documented using **Swagger** or **OpenAPI**. Developers sometimes accidentally leave these docs public.",
          "Look for `/swagger.json`, `/api-docs`, or `/v1/swagger.ui`.",
          "If no docs exist, look into JavaScript bundles (`main.js`) for hidden API endpoints hardcoded in the frontend code."
        ],
        tone: "offense"
      },
      {
        title: "BOLA & BFLA Preview",
        body: [
          "API security focuses on two major risks:",
          "1. **BOLA (Broken Object Level Authorization)**: Can I access `/api/orders/99` if I am user 100?",
          "2. **BFLA (Broken Function Level Authorization)**: Can I, a guest, call `POST /api/admin/reset-password`?"
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "match",
        q: "Match the HTTP method to the standard API action.",
        pairs: [
          ["GET", "Read Resource"],
          ["POST", "Create Resource"],
          ["PUT", "Update/Replace Resource"],
          ["DELETE", "Remove Resource"]
        ],
        explain: "These are the standard CRUD (Create, Read, Update, Delete) mappings for REST.",
        hints: [
          "POST is for new things.",
          "PUT is for modifying existing things."
        ]
      },
      {
        type: "mc",
        q: "You find a file named 'swagger.json' on a server. Why is this a 'gold mine' for a pentester?",
        options: [
          "It contains the admin's password",
          "It is a map of all available API endpoints and their expected parameters",
          "It automatically exploits the server",
          "It contains the server's source code"
        ],
        answer: 1,
        explain: "Swagger files define the entire API surface, including hidden or undocumented endpoints.",
        hints: [
          "It's a documentation format.",
          "Think about 'attack surface'."
        ]
      },
      {
        type: "fill",
        q: "What is the common HTTP status code returned when an API request is valid but the user lacks the necessary permissions (Authorization failure)?",
        answers: ["403"],
        explain: "401 means Unauthenticated (who are you?), while 403 means Forbidden (you aren't allowed here).",
        hints: [
          "It's in the 4xx range.",
          "It means 'Forbidden'."
        ]
      }
    ]
  }
];
