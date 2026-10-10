import type { Unit } from "../types";

const unit2: Unit = {
  id: "recon",
  index: 2,
  title: "Reconnaissance & OSINT",
  tagline: "Find the attack surface before you touch a single endpoint.",
  tone: "offense",
  lessons: [
    {
      id: "dns-fundamentals",
      title: "Domains, subdomains & DNS records",
      summary: "What a domain actually is, how DNS resolves it, and the record types recon depends on.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can explain what a domain and a subdomain are, name the main DNS record types and what each one points to, and read a real `dig`-style DNS answer to say exactly what it proves and what it does not.",
          ],
        },
        {
          kind: "intuition",
          title: "DNS is the internet's phone book",
          body: [
            "Computers route traffic using IP addresses like `203.0.113.10`, not names. Nobody wants to memorise those, so the Domain Name System (DNS) lets you type `shop.example` and get back the IP address to connect to.",
            "Phone book analogy: you look up a person's name and get a phone number. DNS looks up a name (`shop.example`) and gets back a number (an IP address) — or other useful records, as you'll see below.",
            "Where the analogy breaks: a phone book has one entry per person. A single domain name can have many different *types* of DNS records attached to it at once (an address, a mail-server pointer, a text note, etc.), and the answers can change from one query to the next because of caching and load-balancing.",
          ],
        },
        {
          kind: "prereq",
          title: "Domain structure: labels read right to left",
          body: [
            "A domain name is a dot-separated chain of labels, read in order of authority from right to left.",
            "`shop.example` — `example` is the **registered domain** (sometimes called the apex or root domain, the part you buy from a registrar). `shop` is a label in front of it.",
            "`api.shop.example` — this is a **subdomain** of `shop.example`. A subdomain is simply any name with one or more extra labels prepended to a registered domain. Subdomains are free to create — the owner of `shop.example` can create as many as they like (`api.`, `admin.`, `dev.`, `staging.`, even `old.backup.shop.example`) without buying anything new.",
            "This matters for recon: a company's attack surface is not one domain, it is the registered domain plus every subdomain anyone in the organisation has ever pointed at anything.",
          ],
          code: `example.com                 <- registered domain (apex)
shop.example.com            <- subdomain (1 extra label)
api.shop.example.com        <- subdomain (2 extra labels, a "sub-subdomain")
old-backup.dev.example.com  <- still just a subdomain, however many labels`,
        },
        {
          kind: "explain",
          title: "How a DNS lookup actually resolves",
          body: [
            "When your browser needs `shop.example`'s IP, it asks a **resolver** (often run by your ISP or a public one like 1.1.1.1). The resolver doesn't know the answer either, so it walks the hierarchy:",
            "1. Ask a root server: 'who handles .example?' → gets back the address of the registry's nameservers.",
            "2. Ask the registry's nameserver: 'who handles example.?' → gets back the **authoritative nameservers** for `example` (these are the servers the domain owner configured, e.g. `ns1.cloudflare.com`).",
            "3. Ask that authoritative nameserver directly: 'what is the A record for shop.example?' → gets back the actual IP address.",
            "The result is cached for a period of time called the **TTL** (time to live, in seconds) so step 1–3 don't repeat on every single request.",
            "Key term: **authoritative** means 'the actual source of truth configured by the domain owner', as opposed to a resolver or cache that is just repeating an answer it was told.",
          ],
          code: `dig shop.example A

;; QUESTION SECTION:
;shop.example.          IN  A

;; ANSWER SECTION:
shop.example.    300  IN  A   203.0.113.10

;; AUTHORITY SECTION:
shop.example.    86400 IN NS  ns1.cloudflare.com.
shop.example.    86400 IN NS  ns2.cloudflare.com.`,
          check: {
            type: "mc",
            q: "In the `dig` output above, what does `300` mean next to the A record?",
            options: [
              "The HTTP status code of the server",
              "The TTL — how many seconds this answer can be cached before it must be re-checked",
              "The port the server listens on",
              "The number of IP addresses returned",
            ],
            answer: 1,
            why: [
              "Status codes come from HTTP responses, not DNS answers.",
              "",
              "DNS records don't carry port numbers; that's a transport-layer concept, not part of the record.",
              "Only one IP is shown here; the 300 is a time value, in seconds, not a count.",
            ],
            explain: "The number before `IN A` is the TTL in seconds. 300 means the answer is valid for 5 minutes before a resolver should ask again.",
            ref: "How a DNS lookup actually resolves",
          },
        },
        {
          kind: "explain",
          title: "The record types recon runs on",
          body: [
            "A domain can have many different record *types* attached to it simultaneously, each answering a different question:",
            "**A** — maps a name to an IPv4 address (e.g. `shop.example → 203.0.113.10`).",
            "**AAAA** — same idea, but for IPv6 addresses.",
            "**CNAME** — an alias: 'this name is really just another name, go look that one up instead' (e.g. `www.shop.example CNAME shop.example`, or a subdomain pointed at a third-party service like `d123.cloudfront.net`).",
            "**MX** — mail exchange: which mail servers handle email for this domain, each with a priority number (lower = tried first).",
            "**TXT** — free-form text. Used for domain-ownership verification, SPF/DKIM anti-spam policy, and sometimes accidentally for leaked internal notes.",
            "**NS** — which nameservers are authoritative for this domain (who to ask for the real answer).",
            "Recon relevance: CNAMEs pointing at third-party services (S3 buckets, CDN edges, SaaS apps) are one of the most common sources of 'subdomain takeover' bugs, because if the third-party resource is deleted but the CNAME is left behind, an attacker can sometimes claim it.",
          ],
          code: `shop.example.          A      203.0.113.10
www.shop.example.      CNAME  shop.example.
mail.shop.example.     MX 10  mx1.shop.example.
shop.example.          TXT    "v=spf1 include:_spf.google.com ~all"
blog.shop.example.     CNAME  shops-blog.ghost.io.
shop.example.          NS     ns1.cloudflare.com.`,
          check: {
            type: "match",
            q: "Match each DNS record type to what it tells you.",
            pairs: [
              ["A", "An IPv4 address for the name"],
              ["CNAME", "This name is an alias for another name"],
              ["MX", "Which server handles email for the domain"],
              ["TXT", "Free-form text, e.g. ownership verification or SPF"],
            ],
            explain: "A/AAAA point at addresses, CNAME points at another name, MX points at mail servers, TXT carries arbitrary text data.",
            ref: "The record types recon runs on",
          },
        },
        {
          kind: "example",
          title: "Worked example: reading a DNS trail",
          body: [
            "Scenario: you're mapping `shop.example`. You run three lookups.",
            "Step 1 — `dig blog.shop.example CNAME` returns `shops-blog.ghost.io.`. This tells you the blog is NOT hosted by the company directly — it's on Ghost's hosting platform (ghost.io), aliased under the company's domain.",
            "Step 2 — `dig shop.example TXT` returns `\"v=spf1 include:_spf.google.com include:mailgun.org ~all\"`. This tells you the company uses Google Workspace AND Mailgun to send mail on its behalf — two separate mail-sending services, useful for building a picture of their vendor stack.",
            "Step 3 — `dig dev-s3-bucket.shop.example CNAME` returns `dev-s3-bucket.s3.amazonaws.com.` with no response when you browse to it directly, but an S3 'NoSuchBucket' error when you request the CNAME hostname.",
            "Conclusion you CAN draw: the company created an S3 bucket, pointed a subdomain at it, and the underlying bucket no longer exists — a classic subdomain-takeover setup (an attacker could potentially create a bucket with that exact name and serve content under the company's domain).",
            "Conclusion you CANNOT draw yet: that the takeover will succeed. You have only read a DNS record and an error page — you have not verified that AWS will actually let you claim that exact bucket name (someone else may already own it, or the provider may block it). That requires an explicit, in-scope verification step, and even then only a non-destructive proof.",
          ],
          code: `$ dig blog.shop.example CNAME +short
shops-blog.ghost.io.

$ dig shop.example TXT +short
"v=spf1 include:_spf.google.com include:mailgun.org ~all"

$ dig dev-s3-bucket.shop.example CNAME +short
dev-s3-bucket.s3.amazonaws.com.
$ curl -s https://dev-s3-bucket.shop.example
<Error><Code>NoSuchBucket</Code></Error>`,
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: treating a subdomain as a separate 'domain' the company doesn't control. It's still the same company's namespace — `old.dev.shop.example` is just as in-scope (or out-of-scope) as `shop.example`, depending on the bounty policy's wording, not on how many dots are in the name.",
            "Mistake: assuming a CNAME means 'this is hosted by the company'. A CNAME to `*.amazonaws.com` or `*.ghost.io` means the opposite — a third party is actually serving that content.",
            "Mistake: confusing an NS record (who is authoritative for the whole domain) with an A record (the IP of one specific name). Only the domain owner can change NS records at the registrar; anyone who can edit DNS zone settings can add an A or CNAME record for a new subdomain.",
            "Mistake: treating a DNS answer as permanent. TTL-expired caches, round-robin A records, and CDNs mean the same name can resolve differently minutes apart — don't assume the IP you saw once is the only one.",
          ],
          tone: "defense",
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "You query `api-old.shop.example` and get: `A 198.51.100.77`, TTL 300. You then query the same name five minutes later from a different resolver and get `A 198.51.100.201`. Both answers are 'valid' DNS responses.",
          ],
          check: {
            type: "mc",
            q: "What is the most reasonable explanation, and what should you NOT conclude?",
            options: [
              "One of the two resolvers is lying; DNS is broken for this domain",
              "The domain likely uses multiple A records or a load balancer returning different backend IPs — you should not conclude either IP is 'the real' server",
              "The TTL value means the record is invalid after 300 total lookups",
              "The second IP is a decoy meant to trick scanners",
            ],
            answer: 1,
            why: [
              "DNS has no concept of 'lying' here — multiple valid answers for a name is normal, especially behind load balancers.",
              "",
              "TTL is a time duration in seconds, not a lookup counter.",
              "There's no DNS mechanism that serves intentional decoy IPs to scanners; that's not how caching/load-balancing works.",
            ],
            explain: "Many organisations return several A records (round-robin) or change answers behind a load balancer/CDN. Seeing two different IPs across lookups is normal and does not, by itself, tell you which host is primary, which is a backup, or anything about their security posture.",
            ref: "How a DNS lookup actually resolves",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and what it doesn't",
          body: [
            "DNS reconnaissance proves: that a name exists, what it currently resolves to, and often which third-party services are involved (via CNAME/MX/TXT).",
            "DNS reconnaissance does NOT prove: that a service is vulnerable, that an IP is still in active use by the company, that a subdomain takeover will succeed, or that an asset is in-scope for testing. Always cross-check discovered assets against the authorised scope before touching them with anything beyond a DNS query.",
            "In real engagements this lesson's skills feed directly into subdomain enumeration (next lesson) and into spotting subdomain-takeover candidates (a CNAME pointing at a deprovisioned third-party resource).",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "`careers.example.com` is discovered during recon. What is the most accurate description of this name?",
          options: [
            "A completely separate domain unrelated to example.com",
            "A subdomain of the registered domain example.com",
            "The registered (apex) domain",
            "An IP address alias with no relation to example.com",
          ],
          answer: 1,
          why: [
            "It shares the same registered domain, `example.com`, just with an extra label — it is not independent.",
            "",
            "The apex domain here is `example.com` itself; `careers.example.com` has an added label in front of it.",
            "It's a name, not an address, and it is directly related to example.com by being part of its namespace.",
          ],
          hints: [
            "Read the labels right to left — what's the registered domain part?",
            "A subdomain is any name with extra labels prepended to a registered domain.",
          ],
          explain: "`example.com` is the registered domain; `careers` is an extra label in front, making `careers.example.com` a subdomain of it — part of the same organisation's namespace.",
          ref: "Domain structure: labels read right to left",
        },
        {
          type: "fill",
          q: "Which DNS record type would you query to find out which mail servers handle email for a domain?",
          answers: ["mx", "mx record"],
          hints: ["It stands for 'mail exchange'.", "It's a two-letter abbreviation."],
          explain: "MX records list the mail servers responsible for accepting email for a domain, each with a priority value.",
          ref: "The record types recon runs on",
        },
        {
          type: "mc",
          q: "You find `cdn.shop.example` is a CNAME pointing to `d111abcdef.cloudfront.net`. What can you reasonably conclude?",
          options: [
            "shop.example's own servers are compromised",
            "The company is using Amazon CloudFront (a CDN) to serve content under that subdomain",
            "DNS is misconfigured and this is always a vulnerability",
            "The subdomain is definitely vulnerable to takeover",
          ],
          answer: 1,
          why: [
            "A CNAME to a CDN says nothing about compromise — it's routine infrastructure.",
            "",
            "CNAMEs are not inherently a misconfiguration; this is a completely standard way to use a CDN.",
            "Takeover requires the CloudFront distribution to no longer exist/be claimable — you have not verified that here, only observed a normal, active CNAME.",
          ],
          hints: [
            "CloudFront is Amazon's content delivery network product.",
            "A CNAME to a live, functioning third-party service is routine, not a finding by itself.",
          ],
          explain: "CNAME records to well-known cloud providers are extremely common and simply mean a third party hosts/serves that subdomain's traffic. It becomes a takeover candidate only if that third-party resource has since been deleted or deprovisioned — which you'd need to verify separately.",
          ref: "Worked example: reading a DNS trail",
        },
        {
          type: "order",
          q: "Put these steps of a DNS resolution for `shop.example` in the order they happen (simplified).",
          items: [
            "Resolver asks a root server which servers handle .example",
            "Resolver asks the .example registry which nameservers are authoritative for shop.example",
            "Resolver asks the authoritative nameserver for the A record",
            "Resolver caches the answer for the TTL duration and returns it to the browser",
          ],
          hints: [
            "Think top of the hierarchy down: root, then registry, then the domain's own servers.",
            "Caching always happens after the real answer is obtained, not before.",
          ],
          explain: "DNS resolution walks the hierarchy from root → registry/TLD → authoritative nameserver, then caches the result for the TTL.",
          ref: "How a DNS lookup actually resolves",
        },
        {
          type: "mc",
          q: "A teammate says: 'I pinged admin.shop.example and got 203.0.113.9, so that's the company's permanent admin server IP — let's scan it hard.' What's wrong with this reasoning?",
          options: [
            "Nothing — pinging once is sufficient proof of a permanent IP",
            "A single lookup only shows the current answer; it may change (load balancing, TTL expiry, CDN), and it says nothing about whether admin.shop.example is even in scope to test",
            "Ping is not a valid networking protocol",
            "IP addresses cannot be assigned to subdomains",
          ],
          answer: 1,
          why: [
            "One snapshot in time is not proof of permanence; DNS answers can and do change.",
            "",
            "Ping is a legitimate protocol, just not DNS — the issue is the conclusion drawn, not the tool.",
            "Subdomains resolve to IP addresses routinely via A records; that part is normal.",
          ],
          hints: [
            "Think about TTL and load balancing from the DNS lookup lesson content.",
            "Separately — does finding an IP tell you anything about authorisation to scan it?",
          ],
          explain: "A single DNS answer is a snapshot, not a guarantee of permanence — the backend could change behind a load balancer or CDN. Just as importantly, discovering an IP via DNS says nothing about whether that asset is covered by your testing authorisation; scope must be checked separately before any active probing.",
          ref: "Guided practice",
        },
      ],
    },
    {
      id: "passive-vs-active",
      title: "Passive vs active recon",
      summary: "The difference between watching and knocking.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can classify any recon action as passive or active, explain why the distinction matters legally and tactically, and justify why serious hunters do passive recon first.",
          ],
        },
        {
          kind: "intuition",
          title: "Watching the house vs knocking on the door",
          body: [
            "Imagine casing a building before deciding whether to approach it. Reading the mailbox name, looking at public records about the property, and noting the cars in the driveway — none of that involves touching the building. That's passive recon.",
            "Walking up and knocking, testing if a window is unlocked, or trying the door handle — that's interacting directly with the target. That's active recon.",
            "Where the analogy stops: online, 'never touching the target' has a precise technical meaning — passive recon means no packet you send is ever received by a system the target operates. Reading a third-party database about the target (even one the target doesn't control, like a certificate transparency log run by a certificate authority) still counts as passive, because the target's own servers see nothing.",
          ],
        },
        {
          kind: "prereq",
          title: "What counts as 'touching' a target",
          body: [
            "Every action online involves sending data somewhere. The question is: does that data ever reach a system the target owns or operates?",
            "Reading `crt.sh` (a public certificate transparency search engine run by a third party) — your request goes to crt.sh's servers, not the target's. Passive.",
            "Sending an HTTP request directly to `shop.example` — even just loading the homepage in a browser — reaches the target's own server. Active, though extremely low-impact active recon.",
            "This means 'active' is a spectrum from 'load one public page' up to 'brute-force every password'. All of it still counts as active because the target's infrastructure receives and processes your traffic.",
          ],
        },
        {
          kind: "explain",
          title: "Why passive first",
          body: [
            "Passive recon never sends a packet to the target. You read public databases: WHOIS (domain registration records), DNS, certificate transparency logs, GitHub, search engines, Shodan (a search engine for internet-connected devices), and the Wayback Machine (archived snapshots of old web pages).",
            "It's silent (the target's logs show nothing), legal almost everywhere (you're reading public records, not probing systems), and gives you more surface area than any port scan will, because it surfaces assets even if they're currently offline or hidden behind a firewall that would block a scan.",
            "Only after passive recon is exhausted do serious hunters move to active techniques — and only against assets confirmed to be in scope.",
          ],
          tone: "offense",
        },
        {
          kind: "explain",
          title: "The map you're building",
          body: [
            "By the end of recon you should have an **asset inventory**: a structured list of everything that belongs to the target. At minimum it should record, for each asset: the hostname, its current IP, the hosting provider/CDN, and the technology stack (web server, framework, language).",
            "A good asset inventory lets you compare assets objectively instead of guessing. Below, the oldest/least-maintained stack (Jenkins 2.303 with a known CVE) stands out immediately because the inventory is organised and complete — not because any one asset 'looked suspicious'.",
          ],
          code: `your map after good recon

HOSTNAME                      PROVIDER    STACK
api-staging.target.example    AWS         Node + Express 4.17
admin.target.example          Cloudflare  Rails 5.2  (EOL!)
mobile-api.target.example     AWS         Spring Boot 2.4
jenkins.ci.target.example     Hetzner     Jenkins 2.303 (CVE-2021-...)
*.dev.target.example          GCP         various

→ an inventory lets you compare objectively and pick the oldest / least-loved target first.`,
          check: {
            type: "mc",
            q: "Why build a structured inventory table instead of just remembering 'interesting' hosts as you find them?",
            options: [
              "It looks more professional in a report, nothing more",
              "It lets you compare every asset's stack and age objectively, so outdated or neglected systems stand out instead of relying on memory or hunches",
              "Only automated tools can read it, so humans don't need to",
              "It is required by every bug bounty program's rules",
            ],
            answer: 1,
            why: [
              "It's useful for reports too, but that's not the main recon reason to build one.",
              "",
              "Humans read and reason over these tables directly; that's the point.",
              "No bounty program requires a specific inventory format — this is a practical hunting technique, not a rule.",
            ],
            explain: "A structured inventory turns 'this one feels old' into 'this one IS running a 2021-dated, CVE-affected Jenkins version, confirmed against the others' — reasoning from evidence, not vibes.",
            ref: "The map you're building",
          },
        },
        {
          kind: "example",
          title: "Worked example: classifying a recon session",
          body: [
            "You're recon-ing `target.example`. Here's your session log — walk through why each line is passive or active.",
            "1. `whois target.example` — queries the domain registrar's public WHOIS database, a third party. Passive: target's servers see nothing.",
            "2. `curl https://crt.sh/?q=%25.target.example` — queries crt.sh, a third-party certificate transparency search service. Passive.",
            "3. `dig target.example MX` — this asks YOUR configured DNS resolver, which in turn may ask target.example's own authoritative nameservers for the answer. Borderline, but conventionally treated as passive, because it is a standard, expected, read-only protocol query that every internet user performs constantly — not a probe designed to test defences.",
            "4. `curl https://admin.target.example` — sends an HTTP request directly to the target's own web server and will appear in its access logs. Active.",
            "5. `nmap -p- target.example` — sends thousands of packets directly to the target's host to find open ports. Active, and a much higher-intensity/noisier one than #4.",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: thinking 'passive' means 'harmless' and 'active' means 'illegal'. Neither is true — passive recon is safe because it never touches the target, and active recon is legal when it's within an authorised scope. The word describes mechanism, not legality.",
            "Mistake: assuming 'it was exposed to the internet' is a legal defence for probing something out of scope. It is not, anywhere. Scope is defined by written authorisation, not by what is technically reachable.",
            "Mistake: skipping passive recon because active tools feel more 'real'. Passive recon routinely surfaces forgotten assets (old staging servers, acquired-company domains) that active scanning of the known assets would never find, because nobody links to them anymore.",
          ],
          tone: "defense",
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "Classify this action: searching Google for `site:target.example filetype:pdf confidential`.",
          ],
          check: {
            type: "mc",
            q: "Is a Google dork search against a target's indexed pages passive or active?",
            options: [
              "Active — you are directly querying the target",
              "Passive — your request goes to Google's search index, a third party; the target's own servers see nothing",
              "It depends on how many results come back",
              "Neither — search engines are not part of recon",
            ],
            answer: 1,
            why: [
              "Your HTTP request in this case goes to google.com, not to target.example's servers.",
              "",
              "Result count has no bearing on the passive/active classification — that depends only on who receives your request.",
              "Search engines are a core passive recon source, not outside the scope of recon.",
            ],
            explain: "Google dorking queries Google's index of already-crawled pages. The target's servers never receive a request from you during the search itself, so it's passive — exactly like querying crt.sh or WHOIS.",
            ref: "What counts as 'touching' a target",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and what it doesn't",
          body: [
            "Classifying recon correctly tells you what you're legally and tactically safe to do before you have explicit written authorisation: passive recon, yes; active probing, only against confirmed in-scope assets.",
            "It does NOT tell you that a given passive finding is accurate or current — WHOIS records go stale, cached pages in the Wayback Machine may no longer reflect live infrastructure, and a domain seen in an old leak may have changed owners. Passive data earns you leads to verify, not confirmed facts.",
            "The legal line: passive recon on public data is broadly safe. Active probing of a host you do not own is only legal if a bug-bounty program or written permission explicitly covers that exact asset.",
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
          hints: [
            "Ask: does a packet I send ever reach the target's own servers?",
            "Third-party databases (GitHub search, crt.sh) are passive even though they're about the target.",
          ],
          explain: "If a packet never reaches the target, it's passive — and almost always safe. GitHub and crt.sh searches query third parties; nmap and form fuzzing send traffic directly to the target.",
          ref: "What counts as 'touching' a target",
        },
        {
          type: "mc",
          q: "Why do seasoned hunters do passive recon before anything else?",
          options: [
            "It is required by law in every jurisdiction",
            "It is silent, legal, and often finds forgotten assets with the fewest defenders, without any risk of exceeding scope",
            "It is a mandatory prerequisite step to install scanning tools",
            "It automatically earns bounty payouts",
          ],
          answer: 1,
          why: [
            "There's no universal legal requirement to do recon in a specific order; this is a tactical and safety best practice.",
            "",
            "Installing tools has nothing to do with doing recon in a particular order.",
            "No recon activity by itself earns a payout — payouts come from verified, reported findings.",
          ],
          hints: [
            "Think about what passive recon reveals that active scanning of known assets would miss.",
            "Consider risk: can passive recon ever accidentally exceed an authorised scope?",
          ],
          explain: "Known assets are already contested by other hunters. Forgotten subdomains and stale services found passively are where the easier, less-defended bounties live — and passive recon carries essentially no risk of touching an out-of-scope system.",
          ref: "Why passive first",
        },
        {
          type: "fill",
          q: "What do we call the structured list of hostnames, IPs, providers, and tech stacks you build during recon?",
          answers: ["asset inventory", "inventory"],
          hints: ["It's the 'map' described in the lesson.", "Two words, starting with 'asset'."],
          explain: "An asset inventory is the organised record of everything belonging to the target, which lets you compare assets objectively instead of relying on hunches.",
          ref: "The map you're building",
        },
        {
          type: "mc",
          q: "A teammate argues: 'Scanning admin.target.example is fine — I found it was publicly reachable from the internet.' What's the flaw?",
          options: [
            "There is no flaw; public reachability is the same as authorisation",
            "Reachability only describes whether the network allows a connection; authorisation is a separate, explicit legal permission that must cover that exact asset",
            "admin subdomains are always out of scope everywhere",
            "You should only scan domains, never subdomains",
          ],
          answer: 1,
          why: [
            "This is exactly the flawed reasoning the lesson warns against — 'reachable' and 'authorised' are different questions.",
            "",
            "Scope rules vary per program; there's no universal rule that admin subdomains are always excluded.",
            "Subdomains are commonly in scope; the issue here is verifying scope, not avoiding subdomains altogether.",
          ],
          hints: [
            "Separate the technical question (can my packets reach it?) from the legal question (am I allowed to send them?).",
            "Review the legal-line card from this lesson.",
          ],
          explain: "'It was exposed to the internet' is not a legal defence anywhere. Public reachability is a network fact; authorisation is a written agreement that must name or clearly cover that exact asset.",
          ref: "What this proves — and what it doesn't",
        },
      ],
    },
    {
      id: "subdomains",
      title: "Subdomain enumeration",
      summary: "The single highest-ROI skill in bug hunting.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can list the main sources used to enumerate subdomains, explain what each source can and cannot find, and chain them into a basic recon pipeline.",
          ],
        },
        {
          kind: "intuition",
          title: "One company, many front doors",
          body: [
            "Big companies run hundreds of subdomains: marketing microsites, legacy admin panels, dev/staging/qa environments, remnants of acquired companies, S3-backed static assets.",
            "Each one is a separate stack with its own security posture — different code, different update schedule, sometimes a completely different team maintaining it — and the forgotten ones rarely got patched.",
            "Think of it like a company with one famous main office (the main website) and dozens of smaller satellite offices scattered around, some of which the current staff have forgotten even exist. The satellite offices are usually where the unlocked door is.",
          ],
        },
        {
          kind: "prereq",
          title: "Recap: what you're actually looking for",
          body: [
            "From the previous lesson, recall that a subdomain is any name with extra labels in front of a registered domain (`api.shop.example` is a subdomain of `shop.example`), and that DNS A/CNAME records are how a hostname maps to an IP or another hostname.",
            "Subdomain enumeration means discovering as many valid hostnames under a target's domain as possible — using passive sources first, as covered in the previous lesson.",
          ],
        },
        {
          kind: "explain",
          title: "Three complementary sources",
          body: [
            "1. **Certificate transparency logs** — Certificate Authorities are required to publicly log every HTTPS certificate they issue. Since a certificate lists every hostname it's valid for, searching these logs (e.g. via crt.sh) reveals every hostname anyone has ever requested a certificate for — including internal-looking names nobody meant to publicise.",
            "2. **DNS brute force** — take a wordlist of common subdomain names (`api`, `dev`, `test`, `admin`, `staging`...) and try resolving `wordlist-entry.target.example` for each one. If it resolves, the subdomain exists. This finds names that were never put in a certificate (e.g. internal-only HTTP services).",
            "3. **Third-party aggregated datasets** — services like Shodan, VirusTotal, and DNS-history databases that have already scanned/indexed large parts of the internet and will return subdomains they've previously observed, without you sending the target anything at all.",
            "Each source has blind spots: cert transparency misses subdomains that never got an HTTPS certificate; brute force only finds names already in your wordlist; third-party datasets only show what they happened to observe. That's why you use all three and merge the results.",
          ],
          code: `# cert transparency, no tool needed
curl -s 'https://crt.sh/?q=%25.target.example&output=json' | jq -r '.[].name_value' | sort -u

# DNS brute force / passive aggregation tools
subfinder -d target.example -silent
amass enum -passive -d target.example
assetfinder --subs-only target.example

# resolve + probe what you found
dnsx -silent -l subs.txt -a -resp
httpx -l alive.txt -title -tech-detect -status-code`,
          tone: "offense",
          check: {
            type: "mc",
            q: "A subdomain `legacy-portal.target.example` runs an internal tool and has never been issued an HTTPS certificate. Which source is LEAST likely to reveal it?",
            options: [
              "Certificate transparency logs",
              "DNS brute force with a wordlist containing 'legacy-portal'",
              "A third-party dataset that previously scanned and recorded it",
              "All three are equally likely to find it",
            ],
            answer: 0,
            why: [
              "",
              "Brute force would find it, but only if 'legacy-portal' happens to be in your wordlist — not guaranteed, but possible.",
              "A dataset that already observed it by some other means (e.g. a prior scan) could surface it independent of certificates.",
              "The sources have different blind spots — they are not equally likely here.",
            ],
            explain: "Certificate transparency only logs names that appear in an HTTPS certificate. A subdomain that never had a cert issued for it (e.g. an internal HTTP-only tool) simply won't appear there, no matter how thorough the search — it must be found another way.",
            ref: "Three complementary sources",
          },
        },
        {
          kind: "explain",
          title: "The right workflow",
          body: [
            "Gather from every source → merge and de-duplicate the hostname list → resolve each to an IP (drop ones that don't resolve) → probe the live ones over HTTP(S) → fingerprint the technology running → screenshot everything for quick visual triage.",
            "You will look at hundreds of homepages in a weekend of hunting. Automate the mechanical steps (gathering, resolving, probing) so your attention goes to judgement calls (which of these looks neglected and worth digging into).",
          ],
        },
        {
          kind: "example",
          title: "Worked example: merging two sources",
          body: [
            "subfinder (passive dataset) returns: `www`, `api`, `admin`, `staging`.",
            "crt.sh (certificate transparency) returns: `www`, `api`, `admin`, `dev.internal`, `old-backup`.",
            "Step 1: merge the two lists and de-duplicate by hostname: `www, api, admin, staging, dev.internal, old-backup`.",
            "Step 2: notice `dev.internal` and `old-backup` appear ONLY in the cert transparency results — this is exactly the blind-spot pattern from the checkpoint above: someone requested an HTTPS cert for an internal-sounding or old host, which leaked it into a public log even though it was never advertised anywhere else.",
            "Step 3: these two names are now your highest-priority leads, because 'internal-sounding name leaked via a public record' strongly correlates with 'forgotten asset nobody is actively maintaining' — not proof of a vulnerability, but a strong lead worth investigating first.",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: trusting one source and stopping. Every individual tool has blind spots (see the checkpoint above); real coverage comes from merging multiple sources.",
            "Mistake: treating 'found a subdomain' as 'found a vulnerability'. Enumeration only tells you an asset exists and roughly what it runs — it says nothing about whether it's exploitable. That requires further, in-scope investigation.",
            "Mistake: brute-forcing with a tiny or generic wordlist and assuming you found 'everything'. A wordlist only reveals names it contains; an organisation's actual naming convention (e.g. `eu-prod-gw`) might not be in any public wordlist at all.",
          ],
          tone: "defense",
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "You run `httpx` against a resolved list and get back: `old-crm.target.example [200] [CRM Login] [Apache 2.2.15, PHP/5.3]` alongside nine other, clearly modern, actively maintained hosts.",
          ],
          check: {
            type: "fill",
            q: "Based only on what enumeration + probing has shown so far, what is the single most reasonable NEXT step — not a conclusion, a step? (one or two words)",
            answers: ["investigate", "investigate further", "verify", "dig deeper", "check it out"],
            hints: [
              "You have a strong lead (old software version, stands out from the rest), not a confirmed vulnerability yet.",
              "What would a cautious, evidence-driven hunter do before claiming anything is broken?",
            ],
            explain: "An old Apache/PHP version is a strong, evidence-based lead — PHP 5.3 is long past end-of-life — but by itself it's only a lead. The next step is to investigate/verify (e.g. check for known CVEs matching the exact version, test authorised, non-destructive requests) before concluding anything is actually vulnerable.",
            ref: "Worked example: merging two sources",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and what it doesn't",
          body: [
            "Subdomain enumeration proves that a hostname exists and, once probed, what software appears to be running there. Combined across sources, it gives a far more complete picture of an organisation's attack surface than looking at the main website alone.",
            "It does NOT prove that any discovered asset is vulnerable, in scope, or even still actively used by the company — an old banner string can be stale, spoofed by a WAF, or sitting behind protections you haven't tested yet. Enumeration produces leads; confirming a vulnerability always requires a separate, authorised verification step.",
            "Real-world relevance: 'half of bug-bounty wins are found on an undocumented asset nobody else looked at' is a common pattern precisely because thorough, multi-source enumeration is rarer than it should be.",
          ],
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "What is the one public resource that logs every HTTPS certificate ever issued, searchable at sites like crt.sh?",
          answers: ["certificate transparency", "cert transparency", "ct logs", "crt.sh"],
          hints: ["Certificate Authorities are required to publish issued certs here.", "crt.sh is a common search interface for it."],
          explain: "Certificate transparency logs. CA/Browser Forum rules require all newly issued certificates to be publicly logged, so any hostname that ever got an HTTPS cert shows up there.",
          ref: "Three complementary sources",
        },
        {
          type: "match",
          q: "Match each tool to its primary job in the pipeline.",
          pairs: [
            ["subfinder", "Passive subdomain enumeration"],
            ["dnsx", "Fast DNS resolution"],
            ["httpx", "HTTP probing + tech detection"],
            ["gowitness", "Screenshots of live sites"],
          ],
          hints: ["Think of the pipeline order: gather names, resolve, probe, visualise.", "Each tool name hints at its job (dnsx = DNS, httpx = HTTP)."],
          explain: "Pipeline, not a monolith: subfinder gathers names, dnsx confirms which resolve, httpx probes the live HTTP(S) services, and gowitness turns the list into screenshots for fast triage.",
          ref: "The right workflow",
        },
        {
          type: "mc",
          q: "`backup.old.target.example` responds with a 2017-dated Apache banner, and doesn't show up on the company's current marketing site or app. Which conclusion is justified by the evidence so far?",
          options: [
            "It is definitely exploitable right now",
            "It is a lead worth prioritising for further, authorised investigation, because old + unlinked often means unmaintained — but this alone doesn't confirm a vulnerability",
            "It must be a honeypot set up to trap researchers",
            "It is out of scope because it wasn't linked from the main site",
          ],
          answer: 1,
          why: [
            "A banner string alone never confirms exploitability — that needs a specific, verified vulnerability check.",
            "",
            "There's no evidence here suggesting deliberate deception; 'old and forgotten' is a far more common and simpler explanation.",
            "Scope is determined by the program's written policy, not by whether a page happens to be linked from the main site.",
          ],
          hints: [
            "Separate 'strong lead' from 'confirmed finding' — what evidence would you need for the latter?",
            "Check the program's scope wording, not link structure, to judge in/out of scope.",
          ],
          explain: "A stale server with an old banner, not referenced anywhere current, is the classic 'forgotten asset' pattern — a high-value lead precisely because it's unlikely to be maintained or monitored. But a banner is only a leads-generation signal; you still need to verify any specific vulnerability (e.g. a matching CVE) before concluding anything, and you still must confirm it's in scope before testing further.",
          ref: "What this proves — and what it doesn't",
        },
        {
          type: "order",
          q: "Put the subdomain-enumeration pipeline steps in the correct order.",
          items: [
            "Gather hostnames from multiple sources (cert transparency, brute force, datasets)",
            "Merge and de-duplicate the hostname list",
            "Resolve hostnames to IPs, discard ones that don't resolve",
            "Probe live hosts over HTTP(S) and fingerprint technology",
            "Screenshot and triage visually",
          ],
          hints: [
            "You can't resolve a name you haven't gathered yet.",
            "Probing (sending HTTP requests) is active — it should come after you've narrowed to hosts that actually resolve.",
          ],
          explain: "Gather broadly first, consolidate the list, confirm which names are actually live via DNS, then move to the more active/expensive step of HTTP probing, finishing with visual triage.",
          ref: "The right workflow",
        },
      ],
    },
    {
      id: "osint",
      title: "OSINT & leak hunting",
      summary: "Code repos, dorking, and the human layer.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can construct a basic Google dork, explain why source-code history can leak secrets even after a file is 'deleted', and describe the minimum necessary impact rule when you encounter a live credential.",
          ],
        },
        {
          kind: "intuition",
          title: "OSINT: using the internet's own memory against it",
          body: [
            "OSINT stands for Open-Source Intelligence — gathering information from publicly available sources rather than hacking anything. Search engines, code-hosting sites, and professional social networks were all built to be searchable; recon simply searches them with a security lens instead of a casual one.",
            "The core insight: humans make mistakes in public, all the time — committing a password to a 'private' repo that's actually public, leaving a debug page indexed by Google, posting a job listing that accidentally reveals the entire tech stack. OSINT is the discipline of systematically looking for those mistakes.",
          ],
        },
        {
          kind: "prereq",
          title: "What a search operator actually restricts",
          body: [
            "A normal search like `target.example admin` searches the engine's whole index loosely. A search *operator* is special syntax that tells the search engine to restrict or target the search precisely.",
            "`site:target.example` restricts results to pages the engine has indexed from that domain only — it is still searching Google's existing public index, not querying target.example directly (this is passive recon, per the earlier lesson).",
            "`filetype:env` restricts results to a specific file extension, useful for finding files like `.env` that commonly contain configuration secrets and should never be publicly reachable.",
          ],
        },
        {
          kind: "explain",
          title: "Google dorking",
          body: [
            "Combining operators turns a search engine into a targeted recon tool. `site:` and `inurl:`/`intitle:` narrow by location; `filetype:` narrows by file extension; a leading `-` excludes terms.",
            "You are looking for login portals, exposed configuration files, verbose error pages, and directory listings (a server showing you its raw folder contents instead of a webpage, because no index file exists).",
          ],
          code: `site:target.example inurl:admin
site:target.example filetype:env
site:target.example "index of /"
site:target.example "sql syntax" OR "undefined index"
site:pastebin.com "target.example"      # leaked creds / dumps
site:github.com "target.example" password`,
          tone: "offense",
          check: {
            type: "fill",
            q: "Which operator would you use to restrict Google results to pages Google has indexed specifically from target.example?",
            answers: ["site:", "site"],
            hints: ["It's the first operator introduced in the prereq card.", "It takes a domain as its argument."],
            explain: "`site:target.example` restricts results to the domain's indexed pages, and is the backbone of most dorking searches.",
            ref: "What a search operator actually restricts",
          },
        },
        {
          kind: "explain",
          title: "GitHub / GitLab leaks and the human layer",
          body: [
            "Developers paste production tokens into test files, forget them in commit history, and push to public repos — daily, across the industry. Crucially, deleting a secret in a *new* commit does NOT remove it: version control keeps every prior commit, so the secret is still retrievable from the repo's full history unless that history is actually rewritten and force-pushed.",
            "Tools like trufflehog and gitleaks scan a repo's entire history (not just the current files) for high-entropy strings and known secret 'shapes' (AWS keys start with `AKIA`, Stripe live keys start with `sk_live_`, etc.).",
            "Beyond code: LinkedIn job postings reveal which frameworks and cloud providers a team uses ('experience with Kubernetes, Istio and ArgoCD on AWS EKS' is close to a free architecture diagram). Breach-dump lookup services (e.g. Have I Been Pwned) tell you which employee email addresses have appeared in prior breaches, which is a strong signal for likely password reuse — but not proof that any specific account is currently compromised.",
          ],
          code: `trufflehog github --repo https://github.com/target/mobile-sdk --only-verified
gitleaks detect --source=./clone --redact`,
          tone: "offense",
        },
        {
          kind: "example",
          title: "Worked example: from leak to minimum-impact verification",
          body: [
            "You run trufflehog against a public repo and it flags a string matching the AWS access-key pattern in a commit from 2021, in a file that was later deleted.",
            "Step 1: confirm it's really present — check the raw commit diff yourself; automated tools can occasionally flag false positives (e.g. a placeholder that merely looks key-shaped).",
            "Step 2: if confirmed real, the MINIMUM necessary step to prove it's a live, exploitable finding is a single non-destructive, read-only call such as `aws sts get-caller-identity`, which only returns which AWS account/identity the key belongs to — it does not read, modify, or list any customer data.",
            "Step 3: if that call succeeds, you have now proven the key is live and usable, with the smallest possible footprint. You stop there and report — you do NOT list S3 buckets, read secrets, or launch resources, because each of those would exceed 'proving the bug exists' and start constituting unauthorised access to real systems/data.",
            "This is the same minimum-necessary-impact principle used throughout security testing: prove it, then stop.",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: believing a deleted file is gone from a public repo. Git history retains every prior commit by default; 'deleted' just means it's not in the latest snapshot.",
            "Mistake: treating a Have I Been Pwned hit as proof an employee's current password is compromised. It only shows that an email address appeared in a historical breach dataset — the person may have changed that password long ago, or it may have been for an unrelated personal account.",
            "Mistake: using a found credential beyond the minimum needed to prove it's live (e.g. logging into production, browsing data). That turns a legitimate finding into unauthorised access and can void your bounty or create legal exposure.",
          ],
          tone: "defense",
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "You find a public GitHub repo belonging to the target containing `DB_PASSWORD=Summer2019!` in a config file from three years ago. The repo is still public today.",
          ],
          check: {
            type: "mc",
            q: "What is the correct, minimum-impact next step?",
            options: [
              "Use the credential to log into the production database and browse a few tables to 'confirm impact'",
              "Attempt a single, clearly non-destructive check that the credential is live (e.g. an authentication attempt that reveals success/failure without reading data), then stop and report with evidence",
              "Post the credential publicly to warn others",
              "Ignore it since it's three years old and probably unused",
            ],
            answer: 1,
            why: [
              "Browsing real data goes beyond proving the bug exists and constitutes unauthorised access to production data.",
              "",
              "Publishing a live credential harms the organisation further and is never appropriate.",
              "Age alone doesn't prove a credential is inactive — many teams reuse or forget to rotate passwords for years, so it's still worth a minimal, non-destructive check.",
            ],
            explain: "The same minimum-necessary-impact rule applies here as with the AWS key example: do the smallest possible check that proves the credential is live, then report immediately rather than exploring further.",
            ref: "Worked example: from leak to minimum-impact verification",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and what it doesn't",
          body: [
            "OSINT and leak hunting prove that specific information was exposed publicly (a secret in a repo, an indexed admin page, an employee's breached email) and, with a minimal verification step, whether a found credential is still live.",
            "It does NOT prove the full extent of what an attacker could do with that information, how long it has been exposed, or that the organisation is unaware of it — some leaks are already known and being rotated. Reporting promptly with minimal, clearly-documented proof is what turns a leak into a legitimate, responsible finding.",
            "Finding a live API key or credential often provides stronger, clearer proof of impact than a subtle web vulnerability — which is part of why OSINT is a core recon skill, not a side activity.",
          ],
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Which Google operator restricts results to a specific domain's indexed pages?",
          answers: ["site:", "site"],
          hints: ["Covered directly in the prereq and explain cards.", "Takes the form operator:value."],
          explain: "`site:target.example` is the backbone of most dorking searches — it restricts the search to that domain's indexed content.",
          ref: "What a search operator actually restricts",
        },
        {
          type: "mc",
          q: "You find what looks like an AWS access key in a 2021 commit of a still-public repo. What should you do first?",
          options: [
            "Try to log in to the AWS web console with it",
            "Run a single non-destructive verification call like `aws sts get-caller-identity`, then report immediately if it succeeds",
            "Post it on social media to document the finding",
            "Delete your local clone and forget about it",
          ],
          answer: 1,
          why: [
            "The AWS console isn't the way to verify a programmatic access key, and attempting further access beyond minimal verification is unnecessary and risky.",
            "",
            "Publishing a live credential is harmful and is never the correct response.",
            "Walking away discards a legitimate, reportable finding without verifying or reporting it.",
          ],
          hints: [
            "Think 'minimum necessary impact' — the smallest action that proves the key is live.",
            "`sts get-caller-identity` is read-only and reveals no customer data.",
          ],
          explain: "Minimum necessary impact: verify validity with a non-destructive call, then report. Do NOT list buckets, read data, or create resources — any of those turns a legitimate finding into unauthorised access.",
          ref: "Worked example: from leak to minimum-impact verification",
        },
        {
          type: "mc",
          q: "A developer deleted a secrets file from a GitHub repo two days ago in a new commit. The repo is still public. Is the secret still retrievable?",
          options: [
            "No — deleting the file in a new commit removes it everywhere",
            "Yes — unless the history itself was rewritten and force-pushed, the old commit (and the secret in it) is still in the repo's history",
            "Only if the file was over 1MB",
            "Only GitHub employees can retrieve deleted files",
          ],
          answer: 1,
          why: [
            "A normal delete commit only changes the latest snapshot; it does not erase prior history.",
            "",
            "File size has no bearing on whether git history retains a commit.",
            "Anyone with repo access (including the public, if the repo is public) can browse its full commit history — no special access needed.",
          ],
          hints: [
            "Recall how git stores every commit, not just the latest state.",
            "What would actually be required to truly remove a secret from history?",
          ],
          explain: "Git retains full history by default. A later commit deleting a file only changes what's visible in the newest snapshot — the secret remains fully retrievable from the earlier commit unless history is explicitly rewritten and force-pushed (and even then, forks/clones may retain it).",
          ref: "GitHub / GitLab leaks and the human layer",
        },
        {
          type: "fill",
          q: "What three-word phrase describes the rule that you should prove a vulnerability exists but go no further when verifying it?",
          answers: ["minimum necessary impact", "minimum impact", "minimal necessary impact"],
          hints: ["It appears multiple times in this lesson.", "Starts with 'minimum'."],
          explain: "The minimum necessary impact rule: verify a finding with the smallest possible action, then stop and report — never explore further than needed to prove the bug.",
          ref: "Worked example: from leak to minimum-impact verification",
        },
      ],
    },
    {
      id: "scope",
      title: "Scope & responsible disclosure",
      summary: "The paperwork that keeps you out of jail.",
      cards: [
        {
          kind: "objective",
          title: "What you'll be able to do",
          body: [
            "By the end of this lesson you can identify the three things to check on any bug-bounty program page before testing, apply the minimum-necessary-impact rule to a new vulnerability type, and explain what a safe-harbour clause does and does not protect you from.",
          ],
        },
        {
          kind: "intuition",
          title: "Permission is a specific, written thing",
          body: [
            "Imagine a landlord says 'feel free to inspect apartment 4B for safety issues.' That permission does not extend to apartment 4C, the building's electrical room, or the landlord's personal office — even though they're all in the same building and you could physically walk into any of them.",
            "A bug-bounty scope works the same way: permission to test is specific to the assets, actions, and limits written in the policy. 'I found it on the same company's infrastructure' is not the same as 'I was told I could test it'.",
          ],
        },
        {
          kind: "prereq",
          title: "Recap: recon findings are leads, not permission",
          body: [
            "From earlier lessons: recon (passive or active) can surface an asset — a subdomain, a leaked credential, an old server — but discovering something does not grant permission to test it. Scope is a separate, written question you must check explicitly for every asset.",
          ],
        },
        {
          kind: "explain",
          title: "Reading a program policy",
          body: [
            "Three things to find on every program page before you touch anything: **in-scope assets** (exactly which domains/apps/IP ranges you're allowed to test), **out-of-scope assets** (explicitly excluded, even if they belong to the same company), and **prohibited actions** (things you must never do, regardless of scope).",
            "Common out-of-scope items: automated scanners run against the whole program without throttling, physical attacks, social engineering of employees, denial-of-service/brute-force testing, and third-party services the company uses but doesn't own (e.g. their payment processor's own infrastructure).",
            "Common prohibited actions: data exfiltration beyond a minimal proof-of-concept, pivoting from one compromised system to attack others, and viewing other real users' data without their consent.",
          ],
        },
        {
          kind: "explain",
          title: "The minimum necessary impact rule, generalised",
          body: [
            "You prove the bug exists. You do not use it to its full extent. This is the same principle from the OSINT lesson, applied across every vulnerability class:",
            "SQL injection: prove you can read `version()` or a single harmless, non-sensitive value. Do NOT dump the users table.",
            "Remote code execution: run something read-only and identifying like `whoami` or `hostname`. Do NOT install anything, persist access, or browse the filesystem.",
            "Insecure direct object reference (IDOR — accessing another user's data by guessing/changing an ID): demonstrate it works against your OWN second test account. Do NOT iterate across IDs belonging to other real users.",
            "The underlying reason is the same in every case: anything beyond minimal proof stops being 'testing for a bug' and starts being unauthorised access to real systems or real people's data — which is both an ethical and a legal problem, independent of whether you found a genuine vulnerability.",
          ],
          tone: "defense",
          check: {
            type: "mc",
            q: "You find an IDOR letting you view other users' order histories by changing an ID in the URL. What is the correct proof-of-concept?",
            options: [
              "Enumerate and record 50 other users' order histories as evidence of scale",
              "Demonstrate the flaw using two accounts you control, showing account A can view account B's data when both are yours",
              "Post a sample of real users' data in your report for context",
              "Fix the bug yourself by patching the client-side code",
            ],
            answer: 1,
            why: [
              "Enumerating real users' data at scale is exactly the kind of impact-maximising action the minimum-necessary-impact rule forbids.",
              "",
              "Including real user data in a report is itself a privacy violation, even if well-intentioned.",
              "Testers report bugs; patching the live application is not your role and would itself be an unauthorised change.",
            ],
            explain: "Using two accounts you own and control to demonstrate the access-control failure proves the vulnerability conclusively without touching any real user's actual data — exactly the minimum needed.",
            ref: "The minimum necessary impact rule, generalised",
          },
        },
        {
          kind: "explain",
          title: "Safe-harbour clauses",
          body: [
            "Modern bug-bounty programs include a safe-harbour clause: a written promise that as long as you stay within the policy's scope and rules and act in good faith, the company will not pursue legal action against you for your testing.",
            "A safe-harbour clause protects you only for actions that comply with the stated policy — it does not retroactively protect actions taken outside the scope or against the prohibited-actions list.",
            "No safe-harbour clause published? Think twice. 'They run a bounty program' by itself is not a legal shield — the safe-harbour language specifically is what provides that protection.",
          ],
        },
        {
          kind: "example",
          title: "Worked example: checking scope before acting on a recon lead",
          body: [
            "During recon (earlier lessons) you found `partner-portal.target.example`, a subdomain hosted by a third-party SaaS vendor the company uses, revealed via a CNAME record.",
            "Step 1: check the program's in-scope list. It says: 'In scope: *.target.example web applications owned and operated by Target Inc.'",
            "Step 2: check the out-of-scope list. It explicitly says: 'Out of scope: third-party vendor platforms, even if reachable via a target.example subdomain.'",
            "Step 3: conclude correctly — even though `partner-portal.target.example` is technically a subdomain of the in-scope domain, the policy excludes it because it's operated by a third party, not Target Inc. itself. Testing it further would violate scope despite matching the domain pattern.",
            "This shows why reading the full policy text matters more than pattern-matching on the domain name alone.",
          ],
        },
        {
          kind: "mistakes",
          title: "Common mistakes",
          body: [
            "Mistake: assuming every subdomain under an in-scope apex domain is automatically in scope. As shown above, policies can carve out specific exclusions (e.g. third-party-hosted subdomains) that override the general pattern.",
            "Mistake: running broad automated scanners against an entire program when the policy excludes 'automated scanning' — this is one of the most common reasons reports get rejected or researchers get banned, because scanners generate noise that overwhelms triage teams.",
            "Mistake: treating 'minimum necessary impact' as optional once you're confident the bug is real. The rule exists regardless of how confident you are — overreach is judged by what you actually did, not by your certainty beforehand.",
          ],
          tone: "defense",
        },
        {
          kind: "practice",
          title: "Guided practice",
          body: [
            "A program's policy states: 'Out of scope: automated vulnerability scanners (e.g. Nessus, Nuclei run against the entire scope without manual review).' You personally review each nuclei template before running a small, targeted set against one specific in-scope host.",
          ],
          check: {
            type: "mc",
            q: "Is this likely compliant with the policy?",
            options: [
              "No — any use of nuclei is banned regardless of context",
              "Likely yes — the policy targets unreviewed, blanket automated scanning across the whole program; a small, manually-reviewed, targeted set against one in-scope host is a different activity, though you should still read the exact wording carefully",
              "Yes, because nuclei is a well-known tool so it's always allowed",
              "No, because only Nessus is explicitly named as disallowed",
            ],
            answer: 1,
            why: [
              "The policy's concern is about blanket, unreviewed scanning, not the mere existence of the tool name — read the actual condition, not just the tool name.",
              "",
              "Tool popularity doesn't determine policy compliance; the specific wording does.",
              "The policy gives Nessus as an example ('e.g.'), not an exhaustive list — nuclei used the same way would be equally prohibited.",
            ],
            explain: "Policies that ban 'automated scanners run against the entire scope without manual review' are targeting the behaviour (blanket, careless automation) not a specific tool name. Always read the precise condition rather than pattern-matching on a tool's name, and when genuinely unsure, ask the program before proceeding.",
            ref: "Reading a program policy",
          },
        },
        {
          kind: "relevance",
          title: "What this proves — and what it doesn't",
          body: [
            "Understanding scope and minimum-necessary-impact lets you convert a recon finding or vulnerability into a legitimate, protected report instead of an unauthorised intrusion — this is what keeps security research legal and ethical.",
            "It does NOT mean 'anything technically reachable is fair game', and it does NOT mean a safe-harbour clause protects actions outside the stated policy. Always re-verify scope for each new asset you discover, even ones that look like obvious subdomains of an in-scope target.",
            "This closes the loop on the whole unit: recon (DNS, subdomains, OSINT) generates leads; scope-checking decides what you're allowed to act on; minimum-necessary-impact governs how far you go once you do.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You find an SQLi on an in-scope endpoint. What is the right proof for the report?",
          options: [
            "A screenshot of `SELECT * FROM users` returning 10,000 real emails",
            "A screenshot of `SELECT version()` or `SELECT current_database()` plus the exact payload used",
            "A full database export attached to the report",
            "Just a sentence stating 'SQLi exists' with no evidence",
          ],
          answer: 1,
          why: [
            "Dumping real user data is itself a privacy violation and exceeds minimum necessary impact, regardless of how compelling the evidence would be.",
            "",
            "A full export is far beyond proof-of-concept and constitutes serious overreach.",
            "No evidence at all makes the report unverifiable and unlikely to be actioned by triage.",
          ],
          hints: [
            "Think minimum necessary impact: what's the smallest proof that conclusively shows the flaw?",
            "`version()`/`current_database()` reveal nothing sensitive about real users.",
          ],
          explain: "Enough to prove impact, nothing more. Dumping real user data is itself a breach and may void the bounty — and your safe harbour — even though the underlying SQLi finding was genuine.",
          ref: "The minimum necessary impact rule, generalised",
        },
        {
          type: "mc",
          q: "A program's policy excludes 'automated scanners run against the whole scope'. You run nuclei with its full template set against every in-scope host. Likely outcome?",
          options: [
            "Instant payout regardless of findings",
            "Report rejected, and possibly removal from the program, because this directly matches the excluded behaviour",
            "The company publicly thanks you for thoroughness",
            "No consequence since nuclei found real issues",
          ],
          answer: 1,
          why: [
            "Payout isn't automatic or guaranteed by activity — it depends on valid, in-policy findings.",
            "",
            "Programs typically penalise, not praise, policy violations even when something real is found.",
            "Finding real issues doesn't excuse violating an explicit, stated exclusion.",
          ],
          hints: [
            "Compare this scenario to the guided-practice example — what made that one potentially compliant?",
            "Here, is the scanning targeted/reviewed or blanket/unreviewed?",
          ],
          explain: "This is exactly the blanket, unreviewed, whole-scope automated scanning the policy excludes. Programs ban this pattern because it drowns triage teams in noise — read and respect these rules even when your tool technically finds something.",
          ref: "Reading a program policy",
        },
        {
          type: "fill",
          q: "What is the term for a policy clause promising not to pursue legal action against researchers who stay within the rules and act in good faith?",
          answers: ["safe harbour", "safe harbor", "safe-harbour clause", "safe-harbor clause"],
          hints: ["Two words, nautical in origin.", "Covered directly under its own heading in this lesson."],
          explain: "A safe-harbour clause is the program's written promise not to pursue legal action for compliant, good-faith testing — but it only covers actions that actually stayed within the policy.",
          ref: "Safe-harbour clauses",
        },
        {
          type: "mc",
          q: "`vendor-support.target.example` resolves and looks like it belongs to the target, but the program's out-of-scope list says 'third-party vendor platforms are excluded even on target.example subdomains.' What should you do?",
          options: [
            "Test it anyway since the domain pattern matches the in-scope wildcard",
            "Treat it as out of scope per the explicit exclusion, regardless of the subdomain pattern, and not test it further",
            "Test it, but only report it if you find something serious",
            "Ask a friend to test it instead, since the rule only applies to you",
          ],
          answer: 1,
          why: [
            "Explicit exclusions in the written policy override the general domain pattern — this is the exact scenario worked through in this lesson's example.",
            "",
            "Severity of a finding doesn't retroactively make an out-of-scope test authorised.",
            "Scope rules bind the activity and the asset, not a specific individual — having someone else test it doesn't make it authorised.",
          ],
          hints: [
            "Review the worked example about partner-portal.target.example — same pattern here.",
            "Explicit exclusions in the text override general wildcard patterns.",
          ],
          explain: "Even though the hostname matches the general `*.target.example` pattern, the policy's explicit exclusion for third-party-hosted subdomains takes precedence. Always read the full scope text rather than pattern-matching on the domain name.",
          ref: "Worked example: checking scope before acting on a recon lead",
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
