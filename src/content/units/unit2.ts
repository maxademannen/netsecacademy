import type { Unit } from "../types";

const unit2: Unit = {
  id: "recon",
  index: 2,
  title: "Reconnaissance & OSINT",
  tagline: "Find the attack surface before you touch a single endpoint.",
  tone: "offense",
  lessons: [
    {
      id: "passive-vs-active",
      title: "Passive vs active recon",
      summary: "The difference between watching and knocking.",
      cards: [
        {
          title: "Why passive first",
          body: [
            "Passive recon never sends a packet to the target. You read public databases: WHOIS, DNS, certificate transparency logs, GitHub, Google, Shodan, Wayback Machine, LinkedIn.",
            "It's silent, legal almost everywhere, and gives you more surface area than any port scan will.",
            "Only after passive recon is exhausted do serious hunters touch the target directly.",
          ],
          tone: "offense",
        },
        {
          title: "The map you're building",
          body: [
            "By the end of recon you should have: all domains and subdomains, all public IPs, every exposed service and version, the tech stack (framework, language, CDN, auth provider), employee names and emails, and any leaked secrets or code.",
            "Half of all bug-bounty wins are 'found an undocumented asset nobody else looked at'. Recon is where that lives.",
          ],
          code: `your map after good recon

api-staging.target.example   AWS 54.x.x.x    Node + Express 4.17
admin.target.example         Cloudflare      Rails 5.2  (EOL!)
mobile-api.target.example    AWS 3.x.x.x     Spring Boot 2.4
jenkins.ci.target.example    Hetzner         Jenkins 2.303 (CVE-2021-...)
*.dev.target.example         GCP             various

→ pick the oldest / least-loved target first.`,
        },
        {
          title: "The legal line",
          body: [
            "Passive recon on public data: safe.",
            "Active probing of hosts you do not own: only legal if a bug-bounty program (or written permission) covers that exact asset.",
            "'But it was exposed to the internet' is not a legal defence anywhere. Always confirm scope before you scan.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Classify each activity.",
          pairs: [
            ["Reading cert transparency logs", "Passive"],
            ["Running nmap against the target", "Active"],
            ["Searching GitHub for 'target.com password'", "Passive"],
            ["Fuzzing a login form", "Active"],
          ],
          explain: "If a packet never reaches the target, it's passive — and almost always safe.",
        },
        {
          type: "mc",
          q: "Why do seasoned hunters do passive recon before anything else?",
          options: [
            "It is required by law",
            "It is silent, legal, and often finds forgotten assets with the fewest defenders",
            "It is required to install Burp Suite",
            "It automatically earns XP",
          ],
          answer: 1,
          explain:
            "Known assets are already contested. Forgotten subdomains and stale services are where the easier bounties live.",
        },
      ],
    },
    {
      id: "subdomains",
      title: "Subdomain enumeration",
      summary: "The single highest-ROI skill in bug hunting.",
      cards: [
        {
          title: "Why subdomains matter",
          body: [
            "Big companies run hundreds of subdomains: marketing microsites, legacy admin panels, dev/staging/qa environments, acquired-company remnants, S3-backed assets.",
            "Each one is a separate stack with its own security posture — and the forgotten ones rarely got patched.",
          ],
        },
        {
          title: "Three complementary sources",
          body: [
            "1. Certificate transparency logs — every HTTPS cert ever issued is public, including for internal-looking hostnames.",
            "2. DNS brute force — wordlist of common names (api, dev, test, admin, staging) resolved against the target.",
            "3. Third-party datasets — Chaos (ProjectDiscovery), Securitytrails, VirusTotal, DNSDumpster, Shodan.",
          ],
          code: `# cert transparency, no tool needed
curl -s 'https://crt.sh/?q=%25.target.example&output=json' | jq -r '.[].name_value' | sort -u

# brute force
subfinder -d target.example -silent
amass enum -passive -d target.example
assetfinder --subs-only target.example

# resolve + probe
dnsx -silent -l subs.txt -a -resp
httpx -l alive.txt -title -tech-detect -status-code`,
          tone: "offense",
        },
        {
          title: "The right workflow",
          body: [
            "Gather from every source → merge and de-dup → resolve to IPs → probe HTTP(S) → fingerprint tech → screenshot everything (gowitness, aquatone).",
            "You will look at hundreds of homepages in a weekend. Automate the boring parts.",
          ],
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "What is the one public resource that lists every HTTPS certificate ever issued?",
          answers: ["certificate transparency", "cert transparency", "ct logs", "crt.sh"],
          explain:
            "Certificate transparency logs. crt.sh is the usual search interface. CA/B rules require all new certs to be logged.",
        },
        {
          type: "match",
          q: "Match each tool to its primary job.",
          pairs: [
            ["subfinder", "Passive subdomain enumeration"],
            ["dnsx", "Fast DNS resolution"],
            ["httpx", "HTTP probing + tech detection"],
            ["gowitness", "Screenshots of live sites"],
          ],
          explain: "Pipeline, not a monolith. Each tool does one thing and the output of one feeds the next.",
        },
        {
          type: "mc",
          q: "You find `backup.old.target.example` responding with a 2017 Apache banner. What is this called in bug-bounty slang?",
          options: ["A honeypot", "A forgotten asset / low-hanging fruit", "A canary", "A scope violation"],
          answer: 1,
          explain:
            "Classic forgotten asset. Decade-old server with known CVEs, no one owns it internally. Usually critical-severity if you can show impact.",
        },
      ],
    },
    {
      id: "osint",
      title: "OSINT & leak hunting",
      summary: "Code repos, dorking, and the human layer.",
      cards: [
        {
          title: "Google dorking",
          body: [
            "Operators are the real search engine. site:, inurl:, intitle:, filetype:, -site: to exclude.",
            "You are looking for login portals, exposed configs, error pages, directory listings.",
          ],
          code: `site:target.example inurl:admin
site:target.example filetype:env
site:target.example "index of /"
site:target.example "sql syntax" OR "undefined index"
site:pastebin.com "target.example"      # leaked creds / dumps
site:github.com "target.example" password`,
          tone: "offense",
        },
        {
          title: "GitHub / GitLab leaks",
          body: [
            "Developers paste production tokens into test files, forget them in commit history, and push to public repos. Daily.",
            "trufflehog, gitleaks and github-dorks scan a repo's full history for high-entropy strings and known secret shapes (AWS, Stripe, GitHub tokens, Slack webhooks).",
            "Finding a live API key often beats finding a web vulnerability for impact.",
          ],
          code: `trufflehog github --repo https://github.com/target/mobile-sdk --only-verified
gitleaks detect --source=./clone --redact`,
          tone: "offense",
        },
        {
          title: "The human layer",
          body: [
            "LinkedIn tells you which frameworks the engineering team uses, what they're hiring for, which cloud provider.",
            "A job post reading 'experience with Kubernetes, Istio and ArgoCD on AWS EKS' is a free architecture diagram.",
            "Breach dumps (haveibeenpwned, DeHashed) tell you which employees reused a password that is now public.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Which Google operator restricts results to a specific domain?",
          answers: ["site:", "site"],
          explain: "`site:target.example` is the backbone of 90% of dorks.",
        },
        {
          type: "mc",
          q: "You find an AWS access key in a commit from 2021. The repo is still public. First action?",
          options: [
            "Try to log in to the AWS console with it",
            "Use `aws sts get-caller-identity` with the key to verify it is live, then report immediately",
            "Post it on Twitter",
            "Delete it and move on",
          ],
          answer: 1,
          explain:
            "Minimum necessary impact proof: verify validity with a non-destructive call (sts get-caller-identity). Do NOT list buckets, read data, or create resources — any of those turn a finding into unauthorised access.",
        },
      ],
    },
    {
      id: "scope",
      title: "Scope & responsible disclosure",
      summary: "The paperwork that keeps you out of jail.",
      cards: [
        {
          title: "Reading a program policy",
          body: [
            "Three things to find on every program page before you touch anything: in-scope assets, out-of-scope assets, and prohibited actions.",
            "Common out-of-scope: automated scanners, physical attacks, social engineering, DoS/brute-force, third-party services the company doesn't own.",
            "Common prohibited: data exfiltration beyond proof-of-concept, pivoting to other systems, viewing other users' data without consent.",
          ],
        },
        {
          title: "The 'minimum necessary impact' rule",
          body: [
            "You prove the bug exists. You do not use it to its full extent.",
            "SQLi: prove you can read `version()` or a single harmless row. Do NOT dump the users table.",
            "RCE: `whoami` and `hostname`. Do NOT install anything, do NOT persist, do NOT look around.",
            "IDOR: show it works against YOUR OWN second account. Do NOT iterate across other real users.",
          ],
          tone: "defense",
        },
        {
          title: "Safe-harbour clauses",
          body: [
            "Modern programs include a safe-harbour clause: as long as you stay within the policy and act in good faith, the company will not pursue legal action.",
            "No safe harbour clause? Think twice. 'They have a bounty program' is NOT a legal shield in itself.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You find an SQLi on an in-scope endpoint. What is the right proof for the report?",
          options: [
            "A screenshot of `SELECT * FROM users` with 10 000 real emails",
            "A screenshot of `SELECT version()` or `SELECT current_database()` plus the exact payload",
            "A copy of the entire database",
            "Nothing — just a sentence saying 'SQLi exists'",
          ],
          answer: 1,
          explain:
            "Enough to prove impact, nothing more. Dumping real user data is itself a breach and may void the bounty — and your safe harbour.",
        },
        {
          type: "mc",
          q: "A program's policy excludes 'automated scanners'. You run nuclei against the whole scope. Likely outcome?",
          options: [
            "Instant payout",
            "Report rejected, possibly banned from the program",
            "An apology from the company",
            "They offer you a job",
          ],
          answer: 1,
          explain: "Read the rules. Programs ban scanners for a reason — they drown triage.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-recon",
    title: "Lab: map an attack surface",
    tone: "offense",
    briefing: [
      "Target: shop.example, in a simulated recon environment.",
      "Use the tools in the terminal to enumerate subdomains, pull cert transparency, and find any OSINT leaks.",
      "Everything is scripted; nothing leaves your browser.",
    ],
    terminal: {
      host: "hunter@workstation",
      commands: {
        "whois shop.example":
          "Domain Name: SHOP.EXAMPLE\nRegistrar: Example Registrar\nRegistrant Organization: Example Shops Ltd.\nRegistrant Country: UK\nName Server: ns1.cloudflare.com\nName Server: ns2.cloudflare.com\nCreated: 2008-04-12",
        "subfinder -d shop.example -silent":
          "www.shop.example\napi.shop.example\nmobile.shop.example\nadmin.shop.example\nstaging.shop.example\nold-blog.shop.example\ninvoices.legacy.shop.example\ndev-s3-bucket.shop.example",
        "curl -s 'https://crt.sh/?q=%25.shop.example&output=json' | jq -r '.[].name_value' | sort -u":
          "*.shop.example\nadmin.shop.example\napi.shop.example\ndev.internal.shop.example\ndev-s3-bucket.shop.example\ninvoices.legacy.shop.example\nmobile.shop.example\nold-blog.shop.example\nstaging.shop.example\nwww.shop.example",
        "httpx -l subs.txt -title -tech-detect -status-code -silent":
          "https://www.shop.example       [200] [Shop Example | Online store]  [Nginx, Cloudflare, React]\nhttps://api.shop.example       [200] [Shop API v3]                    [Express, Node]\nhttps://mobile.shop.example    [200] [Shop Mobile]                    [Nginx]\nhttps://admin.shop.example     [403] [Access denied]                  [Nginx]\nhttps://staging.shop.example   [200] [Staging — DO NOT INDEX]         [Rails 5.2, Puma]\nhttps://old-blog.shop.example  [200] [Hello world!]                   [WordPress 4.7.5]\nhttps://invoices.legacy.shop.example [500] []                         [Apache 2.2.15, PHP/5.4.16]\nhttps://dev-s3-bucket.shop.example   [200] [AWS S3 ListBucket]        [AmazonS3]",
        "dig +short old-blog.shop.example":
          "203.0.113.44",
        "dig TXT shop.example +short":
          "\"v=spf1 include:_spf.google.com include:mail.staging-corp.net ~all\"\n\"shop-site-verification=k2v9p3\"",
        "github-dork shop.example":
          "https://github.com/example-shops/mobile-sdk/blob/main/test/config.js  -> const API_KEY = \"sk_live_51Hxxxxxxx\" // TODO remove\nhttps://github.com/dev-contractor-01/shop-backup/blob/master/.env  -> DB_PASS=OldSummer2019!\nhttps://gist.github.com/jdoe/abc  -> AWS_SECRET=AKIA...wE+KN",
        "nuclei -u https://old-blog.shop.example -silent":
          "[wordpress-detect]       https://old-blog.shop.example\n[CVE-2017-5487]          https://old-blog.shop.example/wp-json/wp/v2/users  (user enum)\n[wordpress-user-enum]    users: admin, editor, j.doe\n[.git-exposed]           https://old-blog.shop.example/.git/HEAD",
      },
      hints: [
        "whois shop.example",
        "subfinder -d shop.example -silent",
        "curl -s 'https://crt.sh/?q=%25.shop.example&output=json' | jq -r '.[].name_value' | sort -u",
        "httpx -l subs.txt -title -tech-detect -status-code -silent",
        "dig +short old-blog.shop.example",
        "dig TXT shop.example +short",
        "github-dork shop.example",
        "nuclei -u https://old-blog.shop.example -silent",
      ],
    },
    tasks: [
      {
        q: "Which subdomain appears in certificate transparency but NOT in subfinder's passive result (a classic 'internal-looking' host leaked by a cert)?",
        answers: ["dev.internal.shop.example"],
        hint: "Compare the two lists.",
      },
      {
        q: "Which legacy subdomain discloses an interpreter version that is long end-of-life (just the subdomain, e.g. `name.shop.example`)?",
        answers: ["invoices.legacy.shop.example"],
        hint: "Look at httpx's tech-detect output.",
      },
      {
        q: "What CMS and major version is running on old-blog.shop.example?",
        answers: ["wordpress 4.7", "wordpress 4.7.5", "wp 4.7"],
        hint: "nuclei fingerprinted it.",
      },
      {
        q: "From the GitHub dork, what format of secret was leaked in config.js? (type the vendor prefix)",
        answers: ["stripe", "sk_live", "stripe key"],
        hint: "`sk_live_` is a Stripe live secret key.",
      },
      {
        q: "What is the flag? (hint: run the SPF TXT lookup and submit the site-verification token value)",
        answers: ["k2v9p3"],
        hint: "`dig TXT shop.example +short` — look for the site-verification record.",
      },
    ],
  },
  ids: {
    name: "Recon toolkit",
    description:
      "You can enumerate subdomains three ways, pull cert transparency, probe tech stacks, and dork for leaks.",
    rules: [],
  },
};

export default unit2;
