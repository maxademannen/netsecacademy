import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "tech-fingerprinting",
    title: "Tech Fingerprinting",
    summary: "Identify the underlying technology stack using HTTP headers, favicon hashes, and framework artifacts.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "By the end of this lesson you can read an HTTP response to infer backend technology, explain how favicon hashing finds related infrastructure, and distinguish a fingerprinting hint from a validated fact.",
        ],
      },
      {
        kind: "intuition",
        title: "Every stack leaves fingerprints",
        body: [
          "Just as a person leaves fingerprints without meaning to, web servers and frameworks leave small, often-default traces of their identity in every response: header names, cookie names, error page styles, default icons.",
          "None of these traces are secrets — they're accidental byproducts of how the software was built. Fingerprinting is simply the discipline of noticing and cataloguing them.",
        ],
      },
      {
        kind: "prereq",
        title: "Recap: what an HTTP response looks like",
        body: [
          "An HTTP response has a status line (e.g. `200 OK`), a set of header lines (`Name: value`), and a body. Headers are metadata about the response, not content — things like which server software handled the request or what cookie to store.",
          "This lesson assumes you can read a basic HTTP response; if headers below look unfamiliar, treat each one as just a labelled fact the server volunteered about itself.",
        ],
      },
      {
        kind: "explain",
        title: "Reading the headers",
        body: [
          "Servers often leak their identity via the `Server` or `X-Powered-By` headers. `Server: nginx/1.18.0` names the web server software and an exact version; `X-Powered-By: Express` names the application framework.",
          "A precise version string (`Apache/2.4.41`) is a specific, checkable target — you can look up exactly which CVEs affect that version. A generic value (`Server: cloudflare`) tells you that Cloudflare is a reverse proxy in front of the real server, so you're seeing the proxy's identity, not the origin server's — you'd need another technique to learn what's actually behind it.",
          "Cookie names are a second, independent clue. `PHPSESSID` is PHP's default session-cookie name; `JSESSIONID` is Java's. Seeing one of these immediately tells you the backend language, even if the `Server`/`X-Powered-By` headers have been deliberately stripped.",
        ],
        code: `HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: Express
Set-Cookie: connect.sid=s%3A...`,
        tone: "info",
        check: {
          type: "mc",
          q: "A response has `Server: cloudflare` and no other identifying headers. What is the most accurate conclusion?",
          options: [
            "The site runs no backend server at all",
            "Cloudflare (a reverse proxy/CDN) is in front of the real origin server, which is hidden from this header — you'd need another method to identify it",
            "The backend is definitely nginx",
            "The site has no security measures",
          ],
          answer: 1,
          why: [
            "Something always serves the content; Cloudflare is a proxy sitting in front of an origin server, not a replacement for one.",
            "",
            "This header tells you about the proxy, not the origin — nginx is a guess with no supporting evidence here.",
            "A CDN/proxy is itself a security-relevant piece of infrastructure, not an indicator of its absence.",
          ],
          explain: "When a CDN or reverse proxy's name appears in the Server header, it means your request passed through that proxy — the header reflects the proxy, not necessarily the real backend server, which is now hidden one layer deeper.",
          ref: "Reading the headers",
        },
      },
      {
        kind: "explain",
        title: "Favicon hashing",
        body: [
          "Frameworks often ship a default `favicon.ico` (the small icon shown in a browser tab) that almost nobody bothers to replace. Because the exact same default icon file appears on every unmodified install of that framework, its hash becomes a unique fingerprint for that framework.",
          "A hash is a fixed-length string computed from file data such that identical files always produce the identical hash, and different files almost never collide. Hunters use a specific algorithm called MurmurHash3 (abbreviated mmh3) because that is the exact algorithm Shodan and Censys use to index favicons, so your computed hash can be searched directly against their databases.",
          "Searching `http.favicon.hash:<value>` on Shodan returns every indexed server with that identical default icon — often revealing other assets run by the same organisation, or every installation worldwide of a particular vulnerable framework version.",
        ],
        code: `python3 -c 'import mmh3, requests, codecs; \\
response = requests.get("https://target/favicon.ico"); \\
favicon = codecs.encode(response.content, "base64"); \\
hash = mmh3.hash(favicon); \\
print(hash)'`,
        tone: "offense",
      },
      {
        kind: "example",
        title: "Worked example: from one banner to a validated finding",
        body: [
          "You request `https://invoices.legacy.target.example/` and see `Server: Apache/2.2.15 (CentOS) PHP/5.4.16`.",
          "Step 1 (fingerprint, not proof): both Apache 2.2.15 and PHP 5.4.16 are long past their end-of-life dates, meaning no security patches have been released for them in years. This is a strong lead, not a confirmed vulnerability.",
          "Step 2 (validate): search a CVE database for vulnerabilities matching that EXACT Apache/PHP version combination, then check if the specific vulnerable code path (e.g. a specific module or function) is actually reachable on this server — version numbers alone don't confirm a vulnerable configuration.",
          "Step 3 (confirm, minimally): if a matching, unauthenticated vulnerability exists and the program's scope allows active testing, perform the smallest possible proof-of-concept request that demonstrates the flaw without causing damage, following the minimum-necessary-impact rule from the earlier scope lesson.",
          "Only after step 3 do you have a validated finding — step 1 alone is just a well-informed guess.",
        ],
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Mistake: treating a version banner as proof of vulnerability. Banners can be outdated, spoofed, or simply wrong — e.g. a company might patch a vulnerability without changing the reported version string.",
          "Mistake: prioritising a target because it 'looks' old rather than because you've confirmed a specific outdated component. Vague impressions lead to wasted time; a concrete version string checked against a CVE database leads to real findings.",
          "Mistake: ignoring manual validation in favour of automated tools like Wappalyzer alone. These tools are a good starting point but can misidentify frameworks; confirming via distinctive file paths (e.g. `/wp-json/` for WordPress, `/actuator/health` for Spring Boot) adds independent evidence.",
        ],
        tone: "defense",
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "You fingerprint a host and see `X-Drupal-Cache: HIT` plus a favicon hash matching Shodan's indexed hash for default Liferay installs on 40 other hosts worldwide.",
        ],
        check: {
          type: "mc",
          q: "What is the most defensible conclusion?",
          options: [
            "The site is definitely running both Drupal and Liferay simultaneously as its only stack, and all 40 other hosts are vulnerable",
            "There's a contradiction worth investigating further (Drupal header vs Liferay-matching favicon) — possibly a proxy, a mixed/legacy stack, or a stale favicon; this needs more evidence before drawing a firm conclusion",
            "The favicon hash is irrelevant since the header already told you it's Drupal",
            "This proves the site is compromised",
          ],
          answer: 1,
          why: [
            "Two independent signals pointing to different frameworks on the same host means more investigation is needed, not an assumption that both run as the primary stack.",
            "",
            "Favicon hashing is an independent data point; a conflicting signal is informative, not irrelevant.",
            "Neither header nor favicon evidence indicates compromise — both are routine technology fingerprints.",
          ],
          explain: "Conflicting fingerprinting signals are common (legacy favicons left over from a migration, proxies in front of a different backend, multi-app deployments) and should prompt further investigation rather than an immediate, overconfident conclusion either way.",
          ref: "Favicon hashing",
        },
      },
      {
        kind: "relevance",
        title: "What this proves — and what it doesn't",
        body: [
          "Tech fingerprinting proves what software is likely serving a response, based on observable, voluntary traces (headers, cookies, default assets). Combined with a CVE database, it tells you which specific vulnerabilities are worth checking.",
          "It does NOT prove a vulnerability is present, patched, or exploitable — software versions can be misreported, backported-patched without a version bump, or protected by other defences (WAFs, custom configuration). Fingerprinting generates a prioritised list of leads; confirming any one of them requires the explicit validation step shown in the worked example.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "You see the header `X-AspNet-Version: 4.0.30319`. What is the most likely backend language, and why?",
        options: [
          "Java — because of the version-number format",
          "C# / .NET — because `X-AspNet-Version` is a Microsoft ASP.NET-specific header",
          "Python — because of the numeric versioning style",
          "Ruby — because ASP.NET is a Ruby framework",
        ],
        answer: 1,
        why: [
          "The version format itself isn't language-specific; the header name is the actual signal, and it's not a Java header.",
          "",
          "Numeric version formats like this aren't unique to Python; the header name is Microsoft-specific regardless.",
          "ASP.NET is Microsoft's web framework, used with C#/.NET, not Ruby.",
        ],
        hints: [
          "The header name itself names the technology — read it literally.",
          "'AspNet' refers to ASP.NET, a Microsoft framework.",
        ],
        explain: "The `X-AspNet-Version` header is specific to Microsoft's ASP.NET framework, which is primarily used with the C# language on the .NET runtime.",
        ref: "Reading the headers",
      },
      {
        type: "match",
        q: "Match the technology to its common fingerprint indicator.",
        pairs: [
          ["PHPSESSID", "PHP"],
          ["JSESSIONID", "Java/JSP"],
          ["X-Drupal-Cache", "Drupal CMS"],
          ["connect.sid", "Express (Node.js)"],
        ],
        hints: [
          "Session cookie names often directly embed the language or framework name.",
          "'Drupal' appears literally in one of the header names.",
        ],
        explain: "Session cookie names and custom X-headers are reliable indicators of the underlying framework because frameworks set sensible defaults that most sites never bother to rename.",
        ref: "Reading the headers",
      },
      {
        type: "fill",
        q: "To search globally for a specific framework using its default icon, you calculate the _________ hash of the favicon file, matching the algorithm Shodan uses.",
        answers: ["murmurhash3", "mmh3", "murmurhash"],
        hints: ["It's a non-cryptographic hash function.", "Commonly abbreviated as mmh3."],
        explain: "MurmurHash3 (mmh3) is the exact hashing algorithm Shodan and Censys use to index favicons, so computing it the same way lets you search their databases for matching hosts.",
        ref: "Favicon hashing",
      },
      {
        type: "mc",
        q: "A teammate sees `Server: Apache/2.2.15` and immediately writes a report claiming 'Critical: Vulnerable Apache Version'. What's missing from their reasoning?",
        options: [
          "Nothing — an old version number is sufficient proof by itself",
          "They haven't checked whether a specific CVE actually applies to this exact version/configuration, nor confirmed the vulnerable code path is reachable — a banner is a lead, not a confirmed finding",
          "Apache version numbers are never accurate, so the report should be discarded entirely",
          "The severity should be Low instead of Critical, but otherwise the report is fine",
        ],
        answer: 1,
        why: [
          "A version string alone is never sufficient proof — this is the exact mistake the lesson warns against.",
          "",
          "Version banners are often accurate; the issue is relying on them alone without further validation, not that they're universally untrustworthy.",
          "The core problem is a missing validation step, not merely a severity miscalibration.",
        ],
        hints: [
          "Revisit the worked example's three steps: fingerprint, validate, confirm.",
          "What step did the teammate skip between 'saw an old version' and 'wrote a Critical report'?",
        ],
        explain: "A version banner is step 1 of 3 (fingerprint → validate against CVEs for that exact version/config → confirm reachability and impact with a minimal PoC). Skipping straight to a severity claim from a banner alone is exactly the mistake called out in this lesson.",
        ref: "Worked example: from one banner to a validated finding",
      },
    ],
  },
  {
    id: "js-recon",
    title: "JavaScript Analysis",
    summary: "Extract hidden endpoints, API keys, and logic from client-side JavaScript bundles.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "By the end of this lesson you can explain why client-side JavaScript often reveals backend structure, extract candidate endpoints and secrets from a bundle, and explain why a source map is a major information leak when present.",
        ],
      },
      {
        kind: "intuition",
        title: "The client has to know the map, even if it isn't shown",
        body: [
          "Modern web apps run a large amount of logic in the browser rather than on the server. For that JavaScript to work, it must contain — in plain text the browser can execute — the addresses of every backend API it calls, and often feature flags and debug settings too.",
          "Unlike server-side code, which stays hidden on the company's infrastructure, client-side JavaScript is downloaded to and runs on YOUR machine. Anything in it, no matter how 'minified' (compressed to be small, not encrypted), can be read by you directly.",
        ],
      },
      {
        kind: "prereq",
        title: "Minified vs encrypted — an important distinction",
        body: [
          "Minification removes whitespace, shortens variable names, and compresses code to reduce file size for faster page loads. It is NOT encryption — no secret key is needed to read it, and tools can reliably reformat ('beautify') it back into readable, indented code.",
          "This matters because developers sometimes mistakenly treat minification as if it hides secrets — it does not. A minified `const API_KEY=\"abc123\"` is just as readable, after beautifying, as an unminified one.",
        ],
      },
      {
        kind: "explain",
        title: "Finding the source and grepping for gold",
        body: [
          "Start by listing every `.js` file a page loads, visible in a browser's Network or Sources panel — typically files like `main.js`, `app.js`, or numbered 'chunk' files (`2.34abc.js`). These frequently contain the application's entire client-side routing map.",
          "Automate the search for likely secrets and endpoints using regular expressions (grep): look for variable names like `API_KEY`, `SECRET`, `TOKEN`, and for URL path strings starting with `/api/v1` or similar, which reveal the backend API surface even if you never saw it mentioned anywhere else.",
          "Also watch for feature flags — boolean variables like `isAdmin: false` or `DEBUG_MODE: true` baked into the shipped code — which can sometimes hint at functionality that isn't normally exposed to regular users.",
        ],
        code: `grep -roE 'https?://[a-zA-Z0-9./?=_-]+' ./*.js

// Example of what you might find inside a bundle:
const API_URL = "https://api-dev.internal.target.com/v2";
const DEBUG_MODE = true;`,
        tone: "offense",
        check: {
          type: "mc",
          q: "Why is finding `API_URL = \"https://api-dev.internal.target.com/v2\"` inside a minified JS bundle useful recon, even though you never visited that URL directly?",
          options: [
            "It isn't useful — minified code can't be trusted",
            "It reveals a backend hostname/endpoint the client-side code calls, which you can now add to your asset inventory and investigate — even though you only found it by reading shipped code, not by browsing",
            "It proves the endpoint is vulnerable",
            "It means the production site is currently broken",
          ],
          answer: 1,
          why: [
            "Minification doesn't make content untrustworthy — it's just compressed formatting, as covered in the prereq.",
            "",
            "Discovering an endpoint says nothing about whether it's vulnerable; that requires separate testing.",
            "A dev-labelled API URL embedded in production code says nothing about the production site's current status.",
          ],
          explain: "Client-side code has to contain the real backend addresses it calls, in plain readable form once de-minified — so reading it is a legitimate way to discover API endpoints you'd otherwise never see just by clicking through the UI.",
          ref: "Finding the source and grepping for gold",
        },
      },
      {
        kind: "explain",
        title: "Advanced extraction",
        body: [
          "Regex-based grepping is fast but imprecise — it can miss endpoints built from concatenated strings, or flag irrelevant matches. Tools like LinkFinder (Python) or jsluice (Go) instead parse the Abstract Syntax Tree (AST — a structured representation of the code's actual syntax, as the JavaScript engine itself understands it) to extract endpoints more accurately.",
          "Before manual review, beautify minified code (reformat it with proper indentation and spacing) using a tool like js-beautify or your browser's built-in dev tools 'pretty-print' feature — remember, this doesn't decrypt anything, it just reformats already-readable data.",
          "Always check for a matching `.js.map` file (a 'source map'). If present, it allows you to reconstruct the exact original, unminified source code — including original variable names and file structure — turning a deliberately obfuscated-looking bundle back into the developer's original codebase.",
        ],
        tone: "offense",
      },
      {
        kind: "example",
        title: "Worked example: a realistic extraction pass",
        body: [
          "You download `app.a1b2c3.js` from a target's production site.",
          "Step 1: you beautify it with js-beautify, turning a single 4,000-character line into readable, indented code.",
          "Step 2: you run a regex for `/api/` path strings and find `fetch(\\`${BASE}/api/v2/internal/export\\`)` — an 'internal' export endpoint never linked anywhere in the visible UI.",
          "Step 3: you check the Network tab for a `.map` request and find `app.a1b2c3.js.map` returns 200 (not 404). You load it and now see the ORIGINAL source file names, like `src/admin/ExportPanel.jsx`, confirming this endpoint is tied to an admin-only export feature.",
          "Conclusion you CAN draw: an `/api/v2/internal/export` endpoint exists and is associated with admin functionality — a concrete, worth-investigating lead.",
          "Conclusion you CANNOT draw yet: that this endpoint is accessible without authentication, or that it leaks data to a non-admin user. That requires an actual authorised request to the endpoint and observing its real response — reading the JS only told you the endpoint exists and roughly what it's for.",
        ],
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Mistake: assuming minified code is 'hidden' or safe to ship secrets in. As covered above, minification is reversible formatting, not protection — production API keys, admin tokens, or internal URLs should never be shipped to the client at all, minified or not.",
          "Mistake: concluding a feature-flag or hidden endpoint found in JS is immediately exploitable. Finding `isAdmin: false` in client code, for example, does not mean you can simply flip it client-side and gain admin access — proper applications re-validate every privilege on the server, independent of what the client sends.",
          "Mistake: forgetting to check for source maps. They're an easy, high-value check that many testers skip, and when present they can hand you the entire original codebase.",
        ],
        tone: "defense",
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "You find the string `AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWy` inside a bundle, and separately find `fetch(\\`${CONFIG.apiBase}/v1/reports/${id}\\`)`.",
        ],
        check: {
          type: "mc",
          q: "Which of these two findings is immediately more actionable as a potential finding, and why?",
          options: [
            "The API endpoint — it reveals the entire backend structure by itself",
            "The `AIza`-prefixed string — this is a recognisable Google API key pattern, so the next concrete step is to verify what it's scoped to access, whereas the endpoint alone is just a lead requiring further testing before anything is confirmed",
            "Neither — both are completely harmless until proven otherwise",
            "Both are equally final, confirmed vulnerabilities right now",
          ],
          answer: 1,
          why: [
            "An endpoint path alone reveals only a URL structure, not confirmed access or data exposure.",
            "",
            "A live, overly-permissive API key is a concrete, checkable artifact — treating it as 'harmless until proven otherwise' ignores a recognisable, actionable pattern.",
            "Neither is a confirmed vulnerability yet — both still require a verification step before being called a finding.",
          ],
          explain: "`AIza`-prefixed strings are a well-known Google API key signature. The next concrete step is checking what that specific key is scoped to allow (a non-destructive check), whereas the fetch URL is just an API path needing its own separate testing before you know anything about its access controls.",
          ref: "Finding the source and grepping for gold",
        },
      },
      {
        kind: "relevance",
        title: "What this proves — and what it doesn't",
        body: [
          "JavaScript analysis proves what endpoints, configuration values, and sometimes secrets a client-side application contains — because the browser must be able to read all of it to function. Combined with source maps, it can fully reconstruct original source code.",
          "It does NOT prove that any discovered endpoint is unauthenticated, vulnerable, or reachable in its full form — server-side validation can and should independently re-check every request, regardless of what the client-side code implies. Treat every JS-derived discovery as a lead requiring its own verification step, exactly like subdomain or header fingerprinting leads.",
        ],
      },
    ],
    exercises: [
      {
        type: "order",
        q: "Arrange the steps for analyzing a minified JS bundle for sensitive endpoints.",
        items: [
          "Locate .js bundles in the HTML source or Network tab",
          "Download the bundles locally",
          "Beautify or de-minify the code",
          "Run regex/LinkFinder to extract paths",
          "Manually validate discovered endpoints",
        ],
        hints: [
          "You can't read minified code usefully before de-minifying it.",
          "Verification always comes after extraction, as the final step.",
        ],
        explain: "Start broad (finding the files), prepare the data (de-minify so it's human-readable), automate the search (regex/LinkFinder), and finally verify manually — never skip straight from a raw find to a conclusion.",
        ref: "Finding the source and grepping for gold",
      },
      {
        type: "fill",
        q: "If a developer forgets to remove a ______.js.map file, you can reconstruct the exact original, unminified source code.",
        answers: ["source map", "sourcemap"],
        hints: ["It 'maps' the minified code back to the source.", "File extension is .map."],
        explain: "Source maps map minified code back to the original source files and variable names — a huge, often-overlooked information leak when accidentally left accessible on production.",
        ref: "Advanced extraction",
      },
      {
        type: "mc",
        q: "You find the string 'AIzaSy...' in a JS file. What is this likely to be, and what should you do next?",
        options: [
          "An AWS Access Key — log into the AWS console with it",
          "A Google API Key — check what it's scoped to access using a minimal, non-destructive request, consistent with the minimum-necessary-impact rule",
          "A JWT Token — decode it and use it to log in as an arbitrary user",
          "A hashed password — attempt to crack it offline",
        ],
        answer: 1,
        why: [
          "AWS keys follow different prefixes (like AKIA), not 'AIza', and the described next action also isn't minimal.",
          "",
          "JWTs have a distinct three-part dot-separated structure, not this prefix, and attempting to impersonate a user goes beyond minimal verification.",
          "Hashed passwords don't look like this recognisable key-prefix pattern, and cracking attempts aren't the appropriate first step for a found secret.",
        ],
        hints: [
          "The 'AIza' prefix is a specific, well-known signature.",
          "Recall the minimum-necessary-impact rule from the scope lesson — what's the smallest valid next step?",
        ],
        explain: "Strings starting with 'AIza' are the characteristic prefix of Google API keys. As with any found credential, the correct next step is a minimal check of what it can access, not immediate heavy use.",
        ref: "Guided practice",
      },
      {
        type: "mc",
        q: "You find `isAdmin: false` hardcoded in a React component's JS bundle. A teammate wants to report 'privilege escalation' by editing this value in browser dev tools and refreshing. What's the flaw in that plan?",
        options: [
          "There is no flaw — editing client-side JS always grants the matching server-side privilege",
          "Editing a client-side variable only changes what the browser displays locally; a properly built server independently re-validates permissions on every request, so this doesn't prove any real escalation unless the server actually grants elevated access",
          "isAdmin flags are never real and can be ignored entirely",
          "This technique only works on Android apps, not web apps",
        ],
        answer: 1,
        why: [
          "This describes exactly the common misconception the lesson warns against — a client-side edit alone proves nothing about server-side authorization.",
          "",
          "Such flags are a real, common pattern in client apps; the issue is what they do (or don't) prove, not their existence.",
          "The underlying principle (client-side state isn't server-side authority) applies to web apps just the same as any app type.",
        ],
        hints: [
          "Think about where the actual security decision must be enforced.",
          "Does the browser ever get to decide what a server allows?",
        ],
        explain: "A well-built server re-checks every permission on its own side, independent of what the client sends or displays. Flipping a client-side flag only changes the local UI; it is not evidence of a real privilege-escalation vulnerability unless an actual elevated-privilege server response is observed as a result.",
        ref: "Common mistakes",
      },
    ],
  },
  {
    id: "content-discovery",
    title: "Content Discovery",
    summary: "Discover hidden directories, files, and parameters through fuzzing and systematic inventory.",
    cards: [
      {
        kind: "objective",
        title: "What you'll be able to do",
        body: [
          "By the end of this lesson you can explain how directory/parameter fuzzing works, interpret status codes returned during fuzzing, and distinguish a 'lead' from a 'finding' when organising discovery results.",
        ],
      },
      {
        kind: "intuition",
        title: "Not everything has a signpost",
        body: [
          "A website's visible navigation menu is like a building's public signage — it only shows you the rooms the owner wants visitors to find. Content discovery is checking every door along the corridor, even the unmarked ones, to see which ones exist and which ones open.",
          "Where the analogy helps: just because a door isn't signposted doesn't mean it's not there, or not important. Where it breaks down: online, you check for 'doors' by systematically guessing names (fuzzing) rather than walking a real corridor — so your results are only as good as the list of names you tried.",
        ],
      },
      {
        kind: "prereq",
        title: "Recap: HTTP status codes used in discovery",
        body: [
          "This lesson assumes a basic read on HTTP status codes: `200 OK` means the resource exists and was returned successfully; `403 Forbidden` means the server recognised the request but refused to serve it (meaning the resource likely exists but is protected); `404 Not Found` means, as far as the server will admit, nothing exists at that path.",
          "The key distinction for discovery: 404 usually means 'nothing here', while 403 usually means 'something is here, but access is blocked' — these carry very different information even though both are failures to retrieve content.",
        ],
      },
      {
        kind: "explain",
        title: "Fuzzing the paths",
        body: [
          "Content discovery ('directory busting') brute-forces URL paths by trying many candidate names from a wordlist and observing which return a non-404 status. It reveals unlinked content like `/admin`, `/backup`, or `/.env` that no page ever links to, so a human browsing normally would never stumble onto it.",
          "Tools like `ffuf` and `feroxbuster` automate this, substituting a `FUZZ` placeholder with each wordlist entry and reporting results; speed matters, but so does using a well-curated wordlist (e.g. SecLists, a well-known collection of such lists) relevant to the target's likely tech stack.",
          "Watch status codes carefully, per the prereq: a `403 Forbidden` is often more interesting than a `200 OK` because it proves a resource exists and someone cared enough to protect it — which can hint at something sensitive behind the restriction.",
        ],
        code: `ffuf -w discovery.txt -u https://target.com/FUZZ -mc 200,403`,
        tone: "offense",
        check: {
          type: "mc",
          q: "While fuzzing, `/config.php` returns 403 and `/old-config.php` returns 404. What's the correct interpretation?",
          options: [
            "Both paths definitely don't exist",
            "`/config.php` likely exists but access is blocked; `/old-config.php` most likely doesn't exist at this path, as far as the server reports",
            "Both paths definitely exist and are both accessible",
            "403 and 404 mean exactly the same thing",
          ],
          answer: 1,
          why: [
            "A 403 specifically indicates the server recognised something there, which contradicts 'definitely doesn't exist'.",
            "",
            "403 explicitly means NOT accessible — the opposite of this option.",
            "They are meaningfully different, as explained in the prereq card.",
          ],
          explain: "403 generally indicates the resource is present but access-restricted; 404 generally indicates nothing was found at that path. These are different signals and should be triaged differently during fuzzing.",
          ref: "Recap: HTTP status codes used in discovery",
        },
      },
      {
        kind: "explain",
        title: "Parameter mining and inventory discipline",
        body: [
          "Endpoints often silently accept parameters never used by the visible UI, like `debug=true` or `admin=1` — these are discovered with dedicated tools like Arjun or Burp Suite's Param Miner, which send many candidate parameter names and watch for the response changing.",
          "Hidden parameters can lead to IDORs, reflected XSS, or logic bypasses, precisely because they weren't designed with the same care as the exposed, user-facing inputs. Interestingly, mining parameters even on a 404 page can be worthwhile, because some application logic processes parameters before checking whether the requested path exists at all.",
          "Maintain a structured inventory of what you've tried (same discipline as the asset inventory from the subdomains lesson): which paths, with which wordlist, against which host, and the result — otherwise you'll duplicate effort or lose track of promising leads across a long engagement.",
        ],
        code: `arjun -u https://target.com/api/user -m GET`,
        tone: "offense",
      },
      {
        kind: "example",
        title: "Worked example: lead vs finding",
        body: [
          "You fuzz `shop.example` and ffuf reports `200` for `/backup/` with a response body showing a raw directory listing: `index of /backup — db_2023.sql.gz, config.old.php`.",
          "Step 1: this is a 'lead' — a discovery requiring further investigation. The fact that a directory listing is enabled (rather than the server returning an index page or a 403) already suggests weak server configuration, but you haven't yet confirmed what the files actually contain or whether accessing them is within scope.",
          "Step 2: checking the in-scope policy confirms `shop.example` is fully in scope and directory listings/config exposure are explicitly callable findings, not excluded.",
          "Step 3: downloading `config.old.php` (a minimal, read-only action directly proving the exposure) and confirming it contains a database connection string turns this into a 'finding' — a verified vulnerability with concrete, minimal evidence, ready to report.",
          "The distinction matters because reporting step 1 alone ('I saw a directory listing') is weaker than reporting step 3 ('I saw a directory listing AND confirmed the exposed file contains live-looking credentials, verified minimally').",
        ],
      },
      {
        kind: "mistakes",
        title: "Common mistakes",
        body: [
          "Mistake: treating every 403 as a dead end and skipping it. A 403 confirms existence; the next reasonable step (within scope and policy) is checking whether an alternate request — different headers, different HTTP method, different casing — can bypass a misconfigured restriction, not simply walking away.",
          "Mistake: calling a raw discovery (a 'lead') a finished finding without verification. 'I fuzzed and found /backup/' is not yet proof of impact until you've confirmed what's actually exposed there and that it's meaningfully sensitive.",
          "Mistake: using an irrelevant or tiny wordlist and assuming thoroughness. Discovery is only as complete as the wordlist used — different tech stacks (PHP, Rails, Node) have different common path conventions, and a mismatched list will miss real content.",
        ],
        tone: "defense",
      },
      {
        kind: "practice",
        title: "Guided practice",
        body: [
          "You fuzz an API and find `GET /api/v1/users/42` returns 200 with your own profile data (you are user 42). You then manually request `GET /api/v1/users/43`.",
        ],
        check: {
          type: "mc",
          q: "It returns another person's full profile data with no error. What should you record, and what shouldn't you claim yet?",
          options: [
            "Record it as a confirmed critical IDOR and immediately request IDs 44 through 1000 to show full scale",
            "Record this single verified request/response pair as strong evidence of an IDOR (you accessed another real user's data without authorisation), but do not iterate further across other real users' IDs — that exceeds minimum necessary impact",
            "Discard it since one data point isn't a complete investigation",
            "Immediately change user 43's data to prove write access too",
          ],
          answer: 1,
          why: [
            "Iterating across many real users' data is exactly what the minimum-necessary-impact rule forbids, even though the underlying bug is likely confirmed.",
            "",
            "One clear, reproducible request/response pair involving real, identifiably different data is sufficient evidence — it shouldn't be discarded.",
            "Modifying another real user's data goes well beyond proof-of-concept and causes real, unauthorised harm.",
          ],
          explain: "A single clean request showing another real user's data is sufficient to prove and report an IDOR. Continuing to enumerate more IDs, or attempting writes, would exceed the minimum-necessary-impact principle covered in the scope lesson — document what you found and stop there.",
          ref: "Worked example: lead vs finding",
        },
      },
      {
        kind: "relevance",
        title: "What this proves — and what it doesn't",
        body: [
          "Content and parameter discovery prove that specific paths or parameters exist and how the server currently responds to them — valuable because unlinked content often has weaker protection than the advertised, well-tested parts of an application.",
          "They do NOT prove, by discovery alone, that any exposed path is a security vulnerability — a directory listing might only reveal harmless public files, and a hidden parameter might be entirely inert. Classify every raw discovery as a 'lead' until a minimal, scope-respecting verification step confirms real, sensitive impact, at which point it becomes a reportable 'finding'.",
        ],
      },
    ],
    exercises: [
      {
        type: "match",
        q: "Match the tool to its primary purpose in discovery.",
        pairs: [
          ["ffuf", "Directory/File Fuzzing"],
          ["Arjun", "Parameter Discovery"],
          ["Seclists", "Wordlist Collection"],
          ["feroxbuster", "Recursive Directory Discovery"],
        ],
        hints: [
          "One is a famous collection of wordlists, not a scanning tool itself.",
          "Arjun's name is specifically associated with parameter mining.",
        ],
        explain: "Each tool specialises in a different layer of content discovery: ffuf/feroxbuster fuzz paths (feroxbuster adds automatic recursion), Arjun mines parameters, and Seclists supplies the wordlists that feed the others.",
        ref: "Fuzzing the paths",
      },
      {
        type: "mc",
        q: "While fuzzing, you receive a 403 Forbidden for /config.php. What is the most reasonable next step, assuming this is in scope?",
        options: [
          "Ignore it; 403 means it's inaccessible and therefore irrelevant",
          "Record it as a lead (the resource exists but is protected) and, if in scope, try minimal bypass techniques such as alternate headers or HTTP methods before concluding anything",
          "Report it immediately as a confirmed high-severity bug with no further checks",
          "Delete the target from your list entirely",
        ],
        answer: 1,
        why: [
          "A 403 confirms existence, which is itself useful information worth recording, not something to discard.",
          "",
          "A 403 alone is not proof of a vulnerability; further, minimal verification is still required before any severity claim.",
          "Removing the target discards a legitimate lead without investigating it.",
        ],
        hints: [
          "Recall the status-code prereq: what does 403 actually tell you, versus 404?",
          "Existence without access is a lead worth a minimal follow-up check, not an endpoint, if in scope.",
        ],
        explain: "A 403 confirms the file exists but is access-restricted. The reasonable next step — if in scope — is a minimal, targeted bypass attempt (e.g. different HTTP methods, header manipulation) before drawing any conclusion about severity.",
        ref: "Recap: HTTP status codes used in discovery",
      },
      {
        type: "order",
        q: "What is the logical order of operations for a discovery workflow across a target?",
        items: [
          "Passive subdomain enumeration",
          "Active directory fuzzing on found hosts",
          "Parameter mining on interesting endpoints",
          "Manual verification of sensitive files/parameters",
          "Documenting verified findings",
        ],
        hints: [
          "Always start with the passive recon covered earlier in this unit.",
          "Verification happens before final documentation, after mining/fuzzing, not before.",
        ],
        explain: "Start broad and least-intrusive (passive subdomain enumeration), narrow down to paths (fuzzing), then parameters, then verify manually, and finally document only confirmed findings.",
        ref: "Parameter mining and inventory discipline",
      },
      {
        type: "fill",
        q: "What term describes a raw discovery (like a found path) that requires further investigation before it can be called a verified vulnerability?",
        answers: ["lead", "a lead"],
        hints: ["It's contrasted directly with 'finding' in this lesson.", "Short, one-word term."],
        explain: "A 'lead' is a discovery requiring further investigation; a 'finding' is a verified vulnerability with minimal, concrete evidence behind it — the worked example walks through turning one into the other.",
        ref: "Worked example: lead vs finding",
      },
    ],
  },
];
