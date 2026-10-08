import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "tech-fingerprinting",
    title: "Tech Fingerprinting",
    summary: "Identify the underlying technology stack using HTTP headers, favicon hashes, and framework artifacts.",
    cards: [
      {
        title: "Reading the Headers",
        body: [
          "Information gathering starts with HTTP response headers. Servers often leak their identity via 'Server' or 'X-Powered-By' fields.",
          "Look for specific version strings. A 'Server: Apache/2.4.41' is a precise target; a generic 'Server: cloudflare' tells you to look elsewhere for the origin.",
          "Cookies like 'PHPSESSID' or 'JSESSIONID' immediately reveal the language (PHP and Java, respectively) even if other headers are stripped."
        ],
        code: "HTTP/1.1 200 OK\nServer: nginx/1.18.0\nX-Powered-By: Express\nSet-Cookie: connect.sid=s%3A..." ,
        tone: "info"
      },
      {
        title: "Favicon Hashing",
        body: [
          "Frameworks often leave their default favicon.ico behind. While visually distinctive, hunters use MurmurHash3 to automate detection.",
          "Shodan and Censys allow searching by 'http.favicon.hash'. For example, the hash '0' often maps to default Spring Boot icons.",
          "Calculating the hash of a target's favicon lets you find other assets owned by the same organization using the same template."
        ],
        code: "python3 -c 'import mmh3, requests, codecs; \\\nresponse = requests.get(\"https://target/favicon.ico\"); \\\nfavicon = codecs.encode(response.content, \"base64\"); \\\nhash = mmh3.hash(favicon); \\\nprint(hash)'",
        tone: "offense"
      },
      {
        title: "Validation Over Vibes",
        body: [
          "Don't prioritize a target because it 'looks' old. Prioritize based on hard evidence of outdated components.",
          "Tools like Wappalyzer or BuiltWith are good starts, but manual validation of file paths (like /wp-json/ or /actuator/health) confirms the tech stack.",
          "Map the tech to known CVEs immediately. If you see 'Liferay', you check for Java Deserialization; if you see 'Drupal', you check for Drupalgeddon."
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "You see the header 'X-AspNet-Version: 4.0.30319'. What is the most likely backend language?",
        options: ["Java", "Python", "C# / .NET", "Ruby"],
        answer: 2,
        explain: "The 'X-AspNet-Version' header is a dead giveaway for Microsoft's .NET framework, which primarily uses C#.",
        hints: [
          "Think about Microsoft ecosystems.",
          "ASP.NET is the keyword here.",
          "It's the industry standard for Windows-based web servers."
        ]
      },
      {
        type: "match",
        q: "Match the technology to its common fingerprint indicator.",
        pairs: [
          ["PHPSESSID", "PHP"],
          ["JSESSIONID", "Java/JSP"],
          ["X-Drupal-Cache", "Drupal CMS"],
          ["django-sig", "Python/Django"]
        ],
        explain: "Session cookie names and custom X-headers are reliable indicators of the underlying framework.",
        hints: [
          "J usually stands for Java.",
          "Drupal often puts its name directly in headers.",
          "PHP is famous for its specific session ID name."
        ]
      },
      {
        type: "fill",
        q: "To search for a specific framework globally using a favicon, you would calculate the _________ hash of the icon file.",
        answers: ["MurmurHash3", "mmh3", "MurmurHash"],
        explain: "MurmurHash3 is the standard hashing algorithm used by Shodan for indexing favicons.",
        hints: [
          "It's a non-cryptographic hash function.",
          "Commonly abbreviated as mmh3.",
          "It starts with 'M'."
        ]
      }
    ]
  },
  {
    id: "js-recon",
    title: "JavaScript Analysis",
    summary: "Extract hidden endpoints, API keys, and logic from client-side JavaScript bundles.",
    cards: [
      {
        title: "Finding the Source",
        body: [
          "Modern web apps move logic to the client. Start by listing all .js files loaded in the 'Sources' or 'Network' tab.",
          "Look for 'main.js', 'app.js', or chunked files like '2.34abc.js'. These often contain the entire routing map of the application.",
          "Don't ignore third-party scripts; sometimes custom configurations for Sentry or Mixpanel leak internal environment names."
        ],
        code: "grep -roE 'https?://[a-zA-Z0-9./?=_-]+' ./*.js",
        tone: "info"
      },
      {
        title: "Grepping for Gold",
        body: [
          "Automate the search for secrets using regex. You are looking for 'API_KEY', 'SECRET', 'TOKEN', or 'STAGING_URL'.",
          "API routes are often buried in JS variables. A common pattern is defining a base URL and appending paths. Search for strings starting with '/api/v1'.",
          "Feature flags (e.g., 'isAdmin: false') can sometimes be toggled in the console if you understand the JS logic."
        ],
        code: "// Example of a leaked endpoint in JS\nconst API_URL = \"https://api-dev.internal.target.com/v2\";\nconst DEBUG_MODE = true;",
        tone: "offense"
      },
      {
        title: "Advanced Extraction",
        body: [
          "Tools like LinkFinder (Python) or jsluice (Go) parse the Abstract Syntax Tree (AST) of JS files to find endpoints more accurately than regex.",
          "Beautify minified code before manual review. Minified code isn't encrypted; it's just condensed. Use 'UglifyJS' or browser dev tools to make it readable.",
          "Always check for source maps (.js.map). If present, they allow you to reconstruct the original, unminified source code perfectly."
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "order",
        q: "Arrange the steps for analyzing a minified JS bundle for sensitive endpoints.",
        items: [
          "Locate .js bundles in the HTML source",
          "Download the bundles locally",
          "Beautify or de-minify the code",
          "Run regex/LinkFinder to extract paths",
          "Manually validate discovered endpoints"
        ],
        explain: "Start broad (finding the file), prepare the data (de-minify), automate the search, and finally verify manually.",
        hints: [
          "You can't read minified code easily.",
          "Extraction comes after you can read it.",
          "Verification is always the last step."
        ]
      },
      {
        type: "fill",
        q: "If a developer forgets to remove a ______.js.map file, you can reconstruct the original source code.",
        answers: ["source map", "sourcemap"],
        explain: "Source maps map the minified code back to the original source, a huge win for researchers.",
        hints: [
          "It 'maps' the source.",
          "Extension is .map.",
          "Two words or one compound word."
        ]
      },
      {
        type: "mc",
        q: "You find the string 'AIzaSy...' in a JS file. What is this likely to be?",
        options: ["An AWS Access Key", "A Google API Key", "A JWT Token", "A hashed password"],
        answer: 1,
        explain: "Strings starting with 'AIza' are characteristic of Google API keys.",
        hints: [
          "It's a very common prefix.",
          "Think of a search engine giant.",
          "Check the 'AIza' prefix signature."
        ]
      }
    ]
  },
  {
    id: "content-discovery",
    title: "Content Discovery",
    summary: "Discover hidden directories, files, and parameters through fuzzing and systematic inventory.",
    cards: [
      {
        title: "Fuzzing the Paths",
        body: [
          "Content discovery (or 'directory busting') involves brute-forcing URL paths to find unlinked content like /admin, /backup, or /.env.",
          "Tools like 'ffuf' and 'feroxbuster' are the gold standard. Speed is key, but so is using the right wordlist (e.g., Seclists).",
          "Watch for status code changes. A 403 Forbidden is often more interesting than a 200 OK because it proves the resource exists but is protected."
        ],
        code: "ffuf -w discovery.txt -u https://target.com/FUZZ -mc 200,403",
        tone: "offense"
      },
      {
        title: "Parameter Mining",
        body: [
          "Endpoints often accept hidden parameters that aren't used in the UI, such as 'debug=true' or 'admin=1'.",
          "Use 'Arjun' or Burp Suite's 'Param Miner' to discover these. These parameters can lead to IDORs, XSS, or even logic bypasses.",
          "Mining parameters on a 404 page might seem useless, but sometimes the application logic processes parameters before checking if the path exists."
        ],
        code: "arjun -u https://target.com/api/user -m GET",
        tone: "offense"
      },
      {
        title: "Leads vs. Findings",
        body: [
          "A 'lead' is a discovery that requires further investigation (e.g., a found /dev folder). A 'finding' is a verified vulnerability (e.g., directory listing in /dev).",
          "Maintain an organized inventory. Use a spreadsheet or a tool like 'Notes' to track which paths you've fuzzed and with which wordlists.",
          "Check for 'stage', 'dev', and 'docs' subdomains. These often run newer, less secure versions of the code or contain API documentation that leaks endpoints."
        ],
        tone: "info"
      }
    ],
    exercises: [
      {
        type: "match",
        q: "Match the tool to its primary purpose in discovery.",
        pairs: [
          ["ffuf", "Directory/File Fuzzing"],
          ["Arjun", "Parameter Discovery"],
          ["Seclists", "Wordlist Collection"],
          ["feroxbuster", "Recursive Directory Discovery"]
        ],
        explain: "Each tool specializes in a different layer of content discovery.",
        hints: [
          "One is a famous collection of lists.",
          "Arjun is specifically for parameters.",
          "Feroxbuster is known for its speed and recursion."
        ]
      },
      {
        type: "mc",
        q: "While fuzzing, you receive a 403 Forbidden for /config.php. What should you do?",
        options: [
          "Ignore it; it's inaccessible.",
          "Try to bypass the restriction (e.g., using headers or different methods).",
          "Report it immediately as a high-severity bug.",
          "Delete the target from your list."
        ],
        answer: 1,
        explain: "A 403 confirms the file exists. You should now try to bypass the access control via headers like X-Forwarded-For or by trying different HTTP methods.",
        hints: [
          "Existence is the first step to exploitation.",
          "Access denied doesn't mean access impossible.",
          "Think like a bypass artist."
        ]
      },
      {
        type: "order",
        q: "What is the logical order of operations for a discovery workflow?",
        items: [
          "Passive subdomain enumeration",
          "Active directory fuzzing on found hosts",
          "Parameter mining on interesting endpoints",
          "Manual verification of sensitive files",
          "Documenting verified findings"
        ],
        explain: "Start broad (subdomains), narrow down to paths, then to parameters, then verify and document.",
        hints: [
          "Always start with passive recon.",
          "Verification happens before final documentation.",
          "Fuzzing paths comes before fuzzing parameters."
        ]
      }
    ]
  }
];
