import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "linux-cli",
    title: "Linux CLI for Hunters",
    summary: "Master the shell basics and text processing tools required to triage a compromised host.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you will be able to: chain pipes to filter a log file down to actionable data, extract and count columns with `awk`/`sort`/`uniq`, read Unix permission numbers (e.g. `chmod 750`), and explain why `$PATH` and world-readable key files are common security weaknesses.",
        ],
      },
      {
        title: "The shell as a scalpel, not a hammer",
        kind: "intuition",
        body: [
          "Think of a shell session like a detective sifting through a warehouse of paper records. You never read every page — you ask narrower and narrower questions: 'show me only pages mentioning X', 'now show me only the names on those pages', 'now count how many times each name appears'.",
          "In Linux, each command does exactly one of those narrowing steps, and the pipe `|` hands the output of one step straight into the next, so you build a precise query out of small, reusable tools instead of one giant program.",
          "Where the analogy breaks: a detective reads meaning into each page. The shell tools are 'dumb' — `grep` just matches text, `awk` just splits on whitespace/columns. All the intelligence comes from how *you* chain them, which is exactly why hunters need to know the tools cold rather than relying on one all-in-one command.",
        ],
      },
      {
        title: "Prerequisite: stdin, stdout, and the pipe",
        kind: "prereq",
        body: [
          "Every Linux process has three default data streams: standard input (stdin, what it reads), standard output (stdout, its normal results) and standard error (stderr, its error messages) — numbered file descriptors 0, 1, and 2.",
          "A pipe `|` connects the stdout of the command on its left to the stdin of the command on its right. `cat file | grep x` means: cat writes the file's contents to stdout, and grep reads that same stream from its stdin instead of from a file.",
          "Redirection (`>`, `>>`) is different from piping: `>` sends stdout to a *file* (overwriting it), `>>` appends to a file. `2>` redirects only stderr. Confusing these causes hunters to silently overwrite evidence files instead of appending to them.",
        ],
        code: `command1 | command2 | command3
#  stdout of 1 --> stdin of 2 --> stdin of 3

grep 'error' app.log > errors.txt   # overwrite errors.txt
grep 'error' app.log >> errors.txt  # append to errors.txt`,
        check: {
          type: "mc",
          q: "In `cat access.log | grep '404'`, what does grep read its input from?",
          options: [
            "It re-opens access.log itself",
            "The stdout of the cat command, via the pipe",
            "The keyboard (stdin of the terminal)",
            "A temporary file created by cat",
          ],
          answer: 1,
          why: [
            "grep never touches the file directly here — it only sees what cat sent it.",
            "",
            "That is the whole point of a pipe: it's the terminal's normal stdin that gets replaced, not a new file.",
            "No temporary file is created; the pipe is an in-memory stream between the two processes.",
          ],
          explain: "The pipe wires cat's stdout directly into grep's stdin, so grep filters whatever cat printed, line by line.",
          hints: ["What does the `|` symbol connect — files or streams?"],
        },
      },
      {
        title: "Chaining filters: grep, awk, sort, uniq",
        kind: "explain",
        body: [
          "`grep PATTERN` prints only the lines matching PATTERN; `grep -v PATTERN` prints lines that do *not* match (useful for excluding known-good noise). `grep -i` ignores case; `grep -c` just counts matching lines.",
          "`awk '{print $N}'` splits each line on whitespace and prints the Nth field (column) — `$1` is the first column, `$0` is the whole line. Log lines are often structured as `IP - - [date] \"request\" status`, so `$1` is usually the source IP.",
          "`sort` orders lines (needed before `uniq`, which only merges *adjacent* duplicate lines). `sort | uniq -c` produces a count of how many times each unique line appeared — the single most common hunter pipeline for 'which IP did this the most'.",
        ],
        code: `grep 'failed' auth.log | awk '{print $1, $9}' | sort | uniq -c
#   1. grep:  keep only failed-login lines
#   2. awk:   keep only the IP ($1) and username ($9) fields
#   3. sort:  group identical lines together
#   4. uniq -c: count how many times each (IP, user) pair appears`,
        check: {
          type: "fill",
          q: "Why must `sort` run before `uniq -c` in a pipeline that counts duplicate lines? (one word: what uniq only compares)",
          answers: ["adjacent", "adjacent lines", "neighbouring lines", "neighboring lines"],
          explain: "`uniq` only collapses duplicates that are next to each other in the stream; unsorted identical lines scattered through the file would each be counted separately unless sorted first.",
          hints: ["uniq does not scan the whole file for matches — only compares each line to the one right before it."],
        },
      },
      {
        title: "Permissions and $PATH as attack surface",
        kind: "explain",
        body: [
          "Linux permissions are three groups of 3 bits — owner, group, others — each meaning read(4), write(2), execute(1). `chmod 750 file` sets owner=rwx(7), group=r-x(5), others=---(0). `chmod 400 key` means only the owner can read it, nobody can write or execute it — the correct mode for a private SSH key.",
          "`ls -la` shows these as a string like `-rw-r--r--`: dash/d for file type, then three rwx triplets for owner/group/others. A private key showing `-rw-r--r--` (644, world-readable) is a serious finding — any local user could steal it.",
          "`$PATH` is a colon-separated list of directories the shell searches, in order, when you type a bare command name (no `/`). If a writable or user-controlled directory appears *before* the legitimate one in `$PATH`, an attacker can plant a malicious file with the same name as a common command — a classic PATH-hijacking persistence technique.",
        ],
        code: `$ ls -la /home/user/.ssh
-rw-r--r-- 1 user user 1823 Jan  5 id_rsa      # BAD: world-readable private key
-rw------- 1 user user  398 Jan  5 id_rsa.pub

$ echo $PATH
/home/user/bin:/usr/local/bin:/usr/bin:/bin`,
        check: {
          type: "fill",
          q: "Convert the permission string `rwxr-x---` to its numeric chmod form (3 digits).",
          answers: ["750"],
          explain: "Owner rwx = 4+2+1 = 7, group r-x = 4+0+1 = 5, others --- = 0. So 750.",
          hints: ["Each rwx triplet maps to a single digit: r=4, w=2, x=1, summed."],
        },
      },
      {
        title: "Worked example: triaging a brute-force attempt",
        kind: "example",
        body: [
          "Scenario: `auth.log` on a server has thousands of lines, and you suspect an SSH brute-force attack. You want the top offending IP addresses.",
          "Step 1: `grep 'Failed password' auth.log` — isolate only failed-login lines, discarding successful logins and unrelated noise.",
          "Step 2: pipe into `awk '{print $(NF-3)}'` — in the standard sshd log format, the source IP is the 4th-from-last field (`NF` = number of fields, so `NF-3` counts back from the end, which is more robust than a fixed column number if usernames vary in length).",
          "Step 3: pipe into `sort` so identical IPs become adjacent.",
          "Step 4: pipe into `uniq -c` to get a count per IP, then `sort -nr | head -5` to see the 5 worst offenders by count, highest first.",
          "Why it matters: this five-command pipeline turns an unreadable multi-megabyte log into a five-line answer — 'these IPs are hammering SSH' — without writing a single line of a traditional program.",
        ],
        code: `grep 'Failed password' auth.log \\
  | awk '{print $(NF-3)}' \\
  | sort | uniq -c | sort -nr | head -5

#   34 203.0.113.77
#   12 198.51.100.4
#    3 192.0.2.19`,
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: running `uniq` without `sort` first and being confused why duplicate counts are wrong — `uniq` only merges adjacent identical lines.",
          "Mistake: using `>` instead of `>>` when trying to accumulate evidence across multiple commands, silently destroying previous output.",
          "Mistake: trusting a fixed column number (`$9`) in `awk` across logs from different tools/hosts — field positions shift if the log format differs; checking a sample line first prevents silently wrong results.",
          "Mistake: treating `chmod 777` as a quick fix for a 'permission denied' error. It makes the file writable and executable by everyone, which is almost always a worse problem than the one it 'solved'.",
        ],
      },
      {
        title: "Practice: build the pipeline",
        kind: "practice",
        body: [
          "You have `access.log` with lines like `203.0.113.77 - - [10/Jan] \"GET /admin HTTP/1.1\" 404 512`. You want a sorted, de-duplicated list of IP addresses that triggered a 404, most frequent first.",
        ],
        check: {
          type: "order",
          q: "Order the pipeline stages to list IPs causing 404s, most frequent first.",
          items: ["cat access.log", "grep '404'", "awk '{print $1}'", "sort", "uniq -c", "sort -nr"],
          explain: "Read the file, keep only 404 lines, extract the IP column, sort so duplicates are adjacent, count duplicates, then sort the counts numerically descending.",
          hints: ["uniq -c needs sorted input directly before it.", "The final sort must be numeric (-n) and reversed (-r) to put the biggest count first."],
        },
      },
      {
        title: "Practical relevance",
        kind: "relevance",
        body: [
          "This pipeline style is the backbone of log triage, CTF forensics challenges, and incident response — it scales from a 100-line file to a multi-gigabyte log without ever loading it all into memory at once.",
          "What this does NOT prove: reading a log and finding suspicious lines tells you an event *happened* on this host — it does not by itself prove root cause, attacker identity, or that the issue is fully remediated. Correlate with other hosts/timestamps before concluding.",
          "Only run these commands against logs and systems you are authorised to access — even read-only commands like `grep`/`cat` on a system you don't own or haven't been scoped to touch can constitute unauthorised access.",
        ],
        tone: "offense",
      },
    ],
    exercises: [
      {
        type: "order",
        q: "Order these commands to extract unique IP addresses that caused 404 errors from a log file, most frequent first.",
        items: ["cat access.log", "grep '404'", "awk '{print $1}'", "sort", "uniq -c", "sort -nr"],
        explain: "We start with the raw file, filter for the error, isolate the IP column, sort so duplicates are adjacent, count them, then sort the counts descending.",
        hints: ["Start with the file source.", "Extract the specific column before deduplicating.", "uniq -c needs sorted input right before it."],
        ref: "Worked example: triaging a brute-force attempt",
      },
      {
        type: "fill",
        q: "To make a script executable by the owner and group (read/write/execute), but only readable by others, you would use 'chmod ____ script.sh'.",
        answers: ["774"],
        explain: "7 (rwx) for owner, 7 (rwx) for group, 4 (r--) for others.",
        hints: ["Owner needs 4+2+1.", "Others only need the read bit (4)."],
        ref: "Permissions and $PATH as attack surface",
      },
      {
        type: "mc",
        q: "Which environment variable defines the directories the shell searches for executable programs, and can be abused for persistence if a writable directory is placed first in it?",
        options: ["$HOME", "$SHELL", "$PATH", "$PWD"],
        answer: 2,
        why: [
          "$HOME is just the user's home directory path, unrelated to command lookup.",
          "$SHELL names which shell program is the user's default, not where commands are found.",
          "",
          "$PWD is simply the current working directory, not a search list.",
        ],
        explain: "$PATH is a colon-separated list of directories checked, in order, when you run a command without a full path. A writable directory placed early in it is a classic hijack vector.",
        hints: ["It defines the 'path' to binaries.", "Manipulating this is a common persistence technique."],
        ref: "Permissions and $PATH as attack surface",
      },
      {
        type: "mc",
        q: "A teammate runs `grep 'error' app.log > findings.txt` three times in a row while investigating. What is wrong with this?",
        options: [
          "Nothing, grep automatically appends",
          "Each run overwrites findings.txt, so only the last run's matches survive",
          "> is invalid syntax for grep",
          "grep cannot write to files at all",
        ],
        answer: 1,
        why: [
          "grep has no special append behaviour — the shell's `>` operator truncates the target file every time.",
          "",
          "`>` is valid shell redirection syntax, just not the one you want here.",
          "grep itself doesn't write files directly, but the shell redirects its stdout to one just fine.",
        ],
        explain: "`>` always truncates and overwrites the destination file. To accumulate results across multiple runs, `>>` (append) is needed instead.",
        hints: ["Compare `>` and `>>`.", "Think about what 'overwrite' means for a file that already has content."],
        ref: "Prerequisite: stdin, stdout, and the pipe",
      },
      {
        type: "fill",
        q: "Fill in the single command-line flag that makes `grep` print only lines that do NOT match the pattern (useful for excluding known-good noise).",
        answers: ["-v"],
        explain: "`grep -v PATTERN` inverts the match, printing every line except those containing PATTERN.",
        hints: ["It's a single lowercase letter flag.", "Think 'inverse'."],
        ref: "Chaining filters: grep, awk, sort, uniq",
      },
      {
        type: "match",
        q: "Match each permission digit (for one rwx triplet) to what it allows.",
        pairs: [
          ["7", "read, write, and execute"],
          ["5", "read and execute only"],
          ["4", "read only"],
          ["0", "no access at all"],
        ],
        explain: "Each digit is the sum of read(4)+write(2)+execute(1) bits: 7=rwx, 5=r-x, 4=r--, 0=---.",
        hints: ["r=4, w=2, x=1 — add the ones that are granted."],
        ref: "Permissions and $PATH as attack surface",
      },
    ],
  },
  {
    id: "tls-certs",
    title: "TLS & Certificate Recon",
    summary: "Analyze TLS handshakes and Certificate Transparency logs to map attack surfaces.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you will be able to: explain why SNI leaks a hostname before encryption begins, use Certificate Transparency logs to discover subdomains, read a certificate's SAN and issuer to spot red flags, and state what certificate inspection does and does not prove about a target.",
        ],
      },
      {
        title: "A sealed envelope with the address written outside",
        kind: "intuition",
        body: [
          "TLS is often described as an envelope that hides a letter's contents from everyone but the recipient. That's true for the *body* of your HTTPS traffic — but the envelope's 'to:' address is a different story.",
          "When your browser connects to a server, it has to tell the server which *website* it wants (many sites can share one IP), and historically this had to happen before encryption was even set up — like writing the destination on the outside of the sealed envelope so the postal service can route it, even though the letter inside is sealed.",
          "Where the analogy breaks: a postal worker glancing at an address is expected and harmless. On the internet, any device *between* you and the server (your ISP, a national firewall, a coffee-shop router) can also read that same plaintext hostname — which is exactly why censorship and traffic-shaping systems use it, and why hunters use it for recon.",
        ],
      },
      {
        title: "Prerequisite: what a certificate actually certifies",
        kind: "prereq",
        body: [
          "A TLS certificate is a signed statement from a Certificate Authority (CA) saying 'the holder of this private key is authorised to represent domain X'. It contains: a Subject (the main domain), a Subject Alternative Name (SAN) list (every domain the cert is valid for, including the main one), an issuer, and an expiry date.",
          "The 'chain of trust' works like this: your browser trusts a small set of Root CAs. A Root CA signs Intermediate CAs, which sign the actual website certificates. If any link in that chain is broken, missing, expired, or self-signed (signed by the site itself rather than a trusted CA), the browser shows a warning.",
          "Certificates prove *identity/key possession*, not security quality. A perfectly valid certificate can still sit in front of an unpatched, vulnerable web application — TLS only guarantees the data in transit is encrypted and the server has proven it holds the matching private key.",
        ],
        code: `Certificate
  Subject: CN=shop.example
  SAN: DNS:shop.example, DNS:www.shop.example, DNS:api.shop.example
  Issuer: Let's Encrypt R3
  Valid: 2024-01-01 to 2024-04-01`,
        check: {
          type: "mc",
          q: "A certificate being valid (correctly signed, not expired) tells you that:",
          options: [
            "The web application behind it has no vulnerabilities",
            "The server holds the private key matching a certificate a trusted CA issued for that domain",
            "The site's data is stored securely",
            "The site cannot be subject to a MITM attack",
          ],
          answer: 1,
          why: [
            "Certificate validity says nothing about application-layer bugs like SQLi or XSS.",
            "",
            "At-rest storage security is unrelated to a TLS certificate.",
            "A valid certificate reduces MITM risk in transit but does not make MITM impossible (e.g. a compromised CA, or a trusted root installed on the victim's device).",
          ],
          explain: "TLS certificates prove identity and enable encryption in transit — they say nothing about the security of the code or data behind that connection.",
          hints: ["Separate 'the pipe is encrypted' from 'what's inside the pipe is safe'."],
        },
      },
      {
        title: "SNI: the plaintext hostname",
        kind: "explain",
        body: [
          "SNI (Server Name Indication) is a field in the TLS 'Client Hello' — the very first message of the handshake, sent *before* encryption keys are established. It tells the server which hostname the client wants, so a single IP can serve certificates for many different domains.",
          "Because the Client Hello is unencrypted, anyone capturing traffic on the path (a coffee-shop Wi-Fi, an ISP, a corporate proxy) can see which hostname you're connecting to, even though they can't see the page content that follows.",
          "Hunters watching traffic to/from a shared IP range use SNI the same way: it reveals which hidden services (`internal-admin.example.com`, `dev.example.com`) are hosted there, even if those names never appear in public DNS zone files.",
        ],
        code: `$ openssl s_client -connect 203.0.113.10:443 -servername dev.example.com
# Sends dev.example.com in the plaintext Client Hello SNI field,
# even though everything AFTER the handshake is encrypted.`,
      },
      {
        title: "Certificate Transparency logs for subdomain discovery",
        kind: "explain",
        body: [
          "Certificate Transparency (CT) is a public, append-only ledger that major CAs are required to publish every certificate they issue to. Browsers reject certificates that aren't logged, so CAs comply, which makes the logs comprehensive.",
          "Because every certificate — including ones for `dev.`, `staging.`, `vpn.`, or `internal.` subdomains that an org never intended to publicise — gets logged, hunters query CT logs (e.g. via crt.sh) to enumerate real, currently-or-previously-valid hostnames for a domain, often finding assets that would never show up via DNS brute-forcing alone.",
          "This is passive recon: querying a public log touches no infrastructure belonging to the target at all, which is why it's typically in-scope even under conservative bug bounty rules — but anything you do *with* the discovered hostnames (scanning, connecting) is a separate action governed by the program's actual scope.",
        ],
        code: `$ curl -s "https://crt.sh/?q=%25.example.com&output=json" | head
[
  {"name_value": "dev.example.com"},
  {"name_value": "vpn.example.com"},
  {"name_value": "www.example.com"}
]`,
        check: {
          type: "match",
          q: "Match the TLS/cert component to its role in security/recon.",
          pairs: [
            ["SNI", "Reveals hostname in plaintext during handshake"],
            ["CT Logs", "Public record of every certificate ever issued"],
            ["SAN", "Other domains valid for this same certificate"],
            ["Root CA", "The trust anchor a browser ships pre-installed"],
          ],
          explain: "SNI leaks names during handshake; CT logs are for discovery; SAN shows domain reuse; Root CAs validate the whole chain.",
          hints: ["One of these is a public ledger you can query without touching the target.", "One relates to multiple names on one certificate."],
        },
      },
      {
        title: "Worked example: mapping a domain's attack surface via CT",
        kind: "example",
        body: [
          "Scenario: you're authorised to test example.com's external attack surface. Public DNS only lists `www.example.com` and `shop.example.com`.",
          "Step 1: query CT logs for `%.example.com` — this returns every certificate ever issued for any subdomain, including ones since decommissioned.",
          "Step 2: the results include `dev.example.com`, `staging.example.com`, and `old-admin.example.com` — none of which appear in public DNS.",
          "Step 3: for each candidate, you resolve DNS (some may no longer point anywhere — a decommissioned cert doesn't mean a live host) and only then, within your authorised scope, probe the ones that do resolve with `curl -vI` to see what's actually running.",
          "Why it matters: this expands the real attack surface from 2 known hosts to potentially several more, entirely from public records — before a single packet is sent to the target. It also illustrates why internal naming conventions ('staging', 'old-admin') leak through certificates even when teams are careful about DNS.",
        ],
        code: `$ curl -vI https://staging.example.com
* Connected to staging.example.com (198.51.100.22) port 443
< Server: nginx/1.18.0
< X-Powered-By: PHP/7.2.1   # <- outdated version disclosed in headers`,
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: assuming a CT log result means the host is currently live. Logs are append-only and historical — a subdomain's certificate may be years old and the host long decommissioned.",
          "Mistake: treating a 'self-signed' warning as automatically malicious. Internal tools and lab environments self-sign routinely; context (public-facing login page vs. internal dashboard) matters.",
          "Mistake: confusing SAN entries with 'this cert proves these domains are related/owned by the same org'. Some CDNs and hosting providers bundle unrelated customer domains onto one shared certificate.",
          "Mistake: scanning or connecting to every subdomain found via CT logs without checking it's within your authorised scope — passive discovery and active probing have different rules.",
        ],
      },
      {
        title: "Practice: reading a suspicious cert",
        kind: "practice",
        body: [
          "You run `openssl s_client -connect 203.0.113.10:443 -servername portal.example.com` against a production customer login page and see: Issuer = portal.example.com (self-signed), SAN = portal.example.com only, Valid: yesterday to next year.",
        ],
        check: {
          type: "mc",
          q: "What is the single most concerning finding here, for a public-facing production login page?",
          options: [
            "The certificate is only valid for one year",
            "The certificate is self-signed rather than issued by a trusted CA",
            "The SAN only lists one domain",
            "The certificate was issued yesterday",
          ],
          answer: 1,
          why: [
            "A one-year validity period is completely normal and not a red flag by itself.",
            "",
            "Listing only one SAN domain is normal for a single-purpose host.",
            "A recently-issued cert is routine (e.g. auto-renewal) and not inherently suspicious.",
          ],
          explain: "A self-signed certificate on a public production login page means browsers won't trust it by default, and more importantly it could indicate a MITM proxy intercepting traffic, or a seriously misconfigured server that never got a real certificate.",
          hints: ["Self-signed means no trusted third party vouched for this identity.", "Think about what a MITM attacker would also present."],
        },
      },
      {
        title: "Practical relevance",
        kind: "relevance",
        body: [
          "CT log queries and `openssl s_client`/`curl -vI` inspection are standard, low-noise first steps in authorised recon — they build a map of real hostnames and software versions before any active scanning begins.",
          "What this does NOT prove: finding a subdomain via CT logs does not prove it's currently live, in scope, or vulnerable — it's a lead to verify, not a finding to report. A valid certificate also does not prove the application behind it is secure.",
          "Only query CT logs (passive, public data) freely; only connect to or scan discovered hosts that fall within your program's authorised scope.",
        ],
        tone: "offense",
      },
    ],
    exercises: [
      {
        type: "match",
        q: "Match the TLS component to its role in security/recon.",
        pairs: [
          ["SNI", "Reveals hostname in plaintext"],
          ["CT Logs", "History of all issued certs"],
          ["SAN", "Other domains valid for this cert"],
          ["Root CA", "The anchor of trust"],
        ],
        explain: "SNI leaks names during handshake; CT logs are for discovery; SAN shows domain reuse; Root CAs validate the chain.",
        hints: ["One of these is a public ledger.", "One relates to multiple names on one cert."],
        ref: "Certificate Transparency logs for subdomain discovery",
      },
      {
        type: "mc",
        q: "Why are Certificate Transparency (CT) logs valuable for an attacker doing recon?",
        options: [
          "They provide private keys for the domain",
          "They reveal subdomains not found via brute force, entirely from public records",
          "They bypass firewall rules",
          "They encrypt the attacker's traffic",
        ],
        answer: 1,
        why: [
          "CT logs are public metadata — they never contain private keys.",
          "",
          "Firewall rules are unaffected; CT is purely informational recon.",
          "CT logs have nothing to do with encrypting anyone's traffic.",
        ],
        explain: "CT logs record every certificate requested, including those for internal-sounding subdomains like 'vpn.company.com', without ever touching the target's infrastructure.",
        hints: ["It's about discovery, not exploitation.", "Think about what is recorded publicly when a cert is issued."],
        ref: "Certificate Transparency logs for subdomain discovery",
      },
      {
        type: "fill",
        q: "The plaintext field in a TLS Client Hello that identifies the target website before encryption is established is called ____.",
        answers: ["sni", "server name indication"],
        explain: "SNI allows the server to present the correct certificate for the requested site, but is sent unencrypted.",
        hints: ["Three letters.", "It stands for Server Name Indication."],
        ref: "SNI: the plaintext hostname",
      },
      {
        type: "mc",
        q: "You find via CT logs that `old-admin.example.com` had a certificate issued three years ago. What should you conclude?",
        options: [
          "The host is definitely still live and running the same software",
          "It's a lead worth checking — resolve DNS and verify liveness before assuming anything",
          "CT logs only show currently active hosts, so it must still be running",
          "This finding should be reported immediately as a live vulnerability",
        ],
        answer: 1,
        why: [
          "CT logs are historical and append-only; they say nothing about current status.",
          "",
          "CT logs are the opposite of 'only current' — they keep every certificate ever logged, forever.",
          "A subdomain name alone is not a vulnerability; it must be verified as live and in-scope first.",
        ],
        explain: "CT logs are historical records. A hostname found there is only a lead — you must verify it still resolves and is within scope before treating it as a finding.",
        hints: ["Recall the 'common mistakes' card about CT log age.", "Separate 'was once issued a cert' from 'is live today'."],
        ref: "Common mistakes",
      },
      {
        type: "fill",
        q: "Fill in the certificate field name (3-letter acronym) that lists every domain a single certificate is valid for.",
        answers: ["san", "subject alternative name"],
        explain: "SAN (Subject Alternative Name) lists all hostnames the certificate covers, which can reveal unexpected domain groupings.",
        hints: ["It stands for 'Subject Alternative Name'."],
        ref: "Prerequisite: what a certificate actually certifies",
      },
      {
        type: "mc",
        q: "A production customer login page presents a self-signed certificate. What is the most responsible immediate interpretation?",
        options: [
          "It's definitely fine, self-signed certs are common everywhere",
          "It could indicate a misconfiguration or a MITM proxy, and warrants investigation within scope",
          "It proves the admin forgot to renew the certificate",
          "Self-signed certificates are always more secure than CA-issued ones",
        ],
        answer: 1,
        why: [
          "Self-signed certs are common for internal/lab tools but are unusual and risky on a public production login page.",
          "",
          "Expiry and self-signing are unrelated issues — an expired cert shows a different warning.",
          "Self-signing has nothing to do with cryptographic strength; it only affects whether a trusted third party vouched for the identity.",
        ],
        explain: "On a public-facing production login page, a self-signed cert is a red flag worth investigating — it could be a MITM intercept or a serious misconfiguration, not routine behaviour.",
        hints: ["Recall the practice card scenario.", "Context matters: internal tool vs. public login page."],
        ref: "Practice: reading a suspicious cert",
      },
    ],
  },
  {
    id: "ports-services-firewalls",
    title: "Ports, Services, and Firewalls",
    summary: "Distinguish between listening, reachable, and filtered ports while analyzing local and remote network state.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "By the end of this lesson you will be able to: distinguish a 'listening' service from a 'reachable' one, read `ss -tulpen` output to find local sockets and their bind address, interpret the difference between nmap's open/closed/filtered port states, and use `curl -v`/`tcpdump` to verify what's actually happening on the wire.",
        ],
      },
      {
        title: "A shop with a locked front door",
        kind: "intuition",
        body: [
          "A service 'listening' on a port is like a shopkeeper standing behind the counter, ready to serve customers. But whether a *customer outside* can actually reach that shopkeeper depends on whether the front door is locked (firewall), and whether the shop even faces the street or only an internal hallway (bind address).",
          "'Listening' is a purely local fact about the machine — the process is ready. 'Reachable' is a fact about the whole path from an outside client to that process, which depends on network routing and every firewall in between.",
          "Where the analogy breaks: a locked door usually gives an obvious 'locked' signal (you feel resistance). On a network, a firewall can be configured to silently drop your knock entirely (no response, as if no door existed at all) rather than telling you 'closed' — and telling these apart is one of the main skills in this lesson.",
        ],
      },
      {
        title: "Prerequisite: bind addresses and local sockets",
        kind: "prereq",
        body: [
          "A listening socket is shown as `address:port`. `0.0.0.0:80` means the process will accept connections on port 80 arriving on *any* of the machine's network interfaces (fully exposed, network-permitting). `127.0.0.1:5432` means it only accepts connections originating from the machine itself (loopback) — no amount of firewall opening will make it reachable from outside, because the OS never even looks at external traffic for that socket.",
          "`ss -tulpen` lists sockets: `-t` TCP, `-u` UDP, `-l` listening only, `-p` show the owning process, `-e` extended info, `-n` show numeric ports instead of resolving service names (faster, and avoids DNS lookups).",
          "A service bound to `127.0.0.1` is a common, deliberate hardening choice (e.g. a local database that only the web app on the same box should reach) — seeing it does not mean 'leave it as a gap', it usually means 'this is correctly restricted, check if a reverse proxy correctly limits what reaches it'.",
        ],
        code: `$ ss -tulpen
Netid  State   Local Address:Port   Process
tcp    LISTEN  0.0.0.0:80           nginx
tcp    LISTEN  127.0.0.1:5432       postgres
tcp    LISTEN  127.0.0.1:6379       redis-server`,
        check: {
          type: "mc",
          q: "A service shows as listening on `127.0.0.1:6379` in `ss -tulpen`. What does this mean for external reachability?",
          options: [
            "It is reachable from anywhere on the internet by default",
            "It can only be reached from processes running on the same machine, regardless of firewall rules",
            "It depends entirely on the firewall configuration",
            "It is reachable only from the local /24 subnet",
          ],
          answer: 1,
          why: [
            "Binding to loopback specifically prevents external reachability — it's the opposite of open to the internet.",
            "",
            "Firewall rules are irrelevant here: the OS never routes external packets to a loopback-bound socket in the first place.",
            "Loopback (127.0.0.1) is not the same as a local subnet — it means 'this machine only', not 'this LAN'.",
          ],
          explain: "Binding to 127.0.0.1 (loopback) restricts the socket to connections originating from the same host — this is a kernel-level restriction, independent of any firewall.",
          hints: ["127.0.0.1 is the loopback address — what does loopback mean?"],
        },
      },
      {
        title: "Probing with curl and tcpdump",
        kind: "explain",
        body: [
          "`curl -v` (verbose) shows the full request and response, including headers that often leak software and version info (`Server: nginx/1.18.0`, `X-Powered-By: PHP/7.2`) — useful for fingerprinting, but remember headers can be spoofed or stripped by a security-conscious admin.",
          "`curl -vI` sends a HEAD request (headers only, no body) — a lighter-weight way to see headers without downloading page content.",
          "`tcpdump -i eth0 port 80 -n` captures raw packets on interface `eth0` filtered to port 80, printing addresses numerically (`-n`, skipping slow/leaky DNS lookups). It shows ground truth: if a SYN packet you sent never gets a SYN-ACK reply, you know you're blocked or the port is filtered — no guessing based on an application's behaviour.",
        ],
        code: `$ curl -vI https://shop.example
> HEAD / HTTP/1.1
> Host: shop.example
< HTTP/1.1 200 OK
< Server: nginx/1.18.0
< X-Powered-By: PHP/7.2.1

$ tcpdump -i eth0 port 80 -n
12:01:03 IP 198.51.100.9.51342 > 203.0.113.9.80: Flags [S], seq 100
# (no reply seen afterward -> SYN appears to be dropped/filtered)`,
      },
      {
        title: "Open, closed, and filtered: reading nmap's verdict",
        kind: "explain",
        body: [
          "Nmap's **open**: something responded (SYN-ACK for TCP) — a service is actively listening and the path is clear. **closed**: the host is reachable and responded, but with an RST, meaning no service is listening there — the host is definitely alive.",
          "**filtered**: nmap got no response at all (or an ICMP unreachable), so it cannot tell whether a service is there — a firewall most likely silently dropped the probe. This is deliberately ambiguous: filtered does not mean 'nothing is there', it means 'something is hiding the answer'.",
          "Hunters pay close attention to filtered ports precisely because that silence is often where the most sensitive services are placed — administrators don't hide ports they don't consider worth protecting.",
        ],
        code: `PORT    STATE    SERVICE
22/tcp  open     ssh        <- SYN-ACK received, service running
80/tcp  open     http
443/tcp open     https
3389/tcp filtered ms-wbt-server  <- no response at all, firewall suspected
8080/tcp closed   http-proxy    <- RST received, port shut but host alive`,
        check: {
          type: "match",
          q: "Match the nmap port state to what actually happened on the wire.",
          pairs: [
            ["open", "SYN-ACK received — a service is listening"],
            ["closed", "RST received — host is alive, nothing listening"],
            ["filtered", "No response at all — likely dropped by a firewall"],
          ],
          explain: "Open and closed both get a definite response from the host; filtered means the probe vanished with no reply, usually meaning a firewall silently dropped it.",
          hints: ["Which state involves the host replying at all?", "Which state means 'I genuinely cannot tell'?"],
        },
      },
      {
        title: "Worked example: is my web server exposed?",
        kind: "example",
        body: [
          "Scenario: you deployed a web app on 203.0.113.9 and want to verify it's reachable from the internet, not just from inside your own network.",
          "Step 1: on the server, run `ss -tulpen` and see `0.0.0.0:443 nginx` — confirms the process is listening on all interfaces, not just loopback.",
          "Step 2: check `ip addr` to confirm 203.0.113.9 is actually the public-facing interface address (not an internal-only NIC).",
          "Step 3: from a *different* machine outside your network, run `curl -vI https://203.0.113.9` — if it hangs with no response, that points to a firewall blocking inbound 443, not an application problem.",
          "Step 4: on the server, run `tcpdump -i eth0 port 443 -n` while repeating step 3. If you see the incoming SYN packet arrive but no SYN-ACK leaves, the OS firewall (e.g. iptables/nftables) is dropping it before nginx ever sees it. If you see nothing at all arrive, the block is further upstream (cloud security group, ISP, router).",
          "Why it matters: each step isolates one possible failure point — listening state, interface binding, external reachability, and exactly where in the path a block occurs — rather than guessing.",
        ],
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: assuming 'listening' means 'reachable from the internet'. A service can be listening perfectly and still be completely unreachable externally due to a firewall or NAT.",
          "Mistake: treating nmap 'filtered' as equivalent to 'nothing is running there'. Filtered specifically means the scanner could not determine the state — it is not evidence of absence.",
          "Mistake: fingerprinting software purely from `curl` headers (`Server:`) without verification — headers are trivially spoofable or can be stripped/customised by a defender.",
          "Mistake: confusing a scan against your own test lab with scanning/probing systems you don't have explicit authorisation to test — port state alone has no bearing on legality.",
        ],
      },
      {
        title: "Practice: diagnose the symptom",
        kind: "practice",
        body: [
          "An nmap scan of 198.51.100.50 shows: 22/tcp open, 80/tcp open, 3306/tcp filtered. The admin insists MySQL (port 3306) isn't even installed.",
        ],
        check: {
          type: "mc",
          q: "What does the 'filtered' state on port 3306 actually tell you here?",
          options: [
            "MySQL is definitely running and reachable",
            "The admin is correct — filtered proves nothing is installed on that port",
            "Nmap could not get any response — it cannot confirm or rule out a service, the probe was likely dropped by a firewall",
            "Port 3306 is closed and nothing can be learned from it",
          ],
          answer: 2,
          why: [
            "Filtered never confirms a service is present or reachable.",
            "The admin's claim might be true, but filtered is not evidence either way — it only shows the probe was dropped.",
            "",
            "Closed is a different state (RST received); filtered means no response was received at all.",
          ],
          explain: "'Filtered' is deliberately inconclusive: it only tells you the scanner's probe got no answer, most likely because a firewall silently dropped it. It neither confirms nor denies a service is listening behind that filter.",
          hints: ["Recall the difference between closed (RST) and filtered (silence).", "Silence from a firewall doesn't prove absence."],
        },
      },
      {
        title: "Practical relevance",
        kind: "relevance",
        body: [
          "This listening-vs-reachable-vs-filtered distinction underlies almost every external attack-surface assessment: you must verify from an external vantage point, not just trust local configuration or internal scans.",
          "What this does NOT prove: an open port only proves a service is accepting connections — it says nothing about whether that service is vulnerable, misconfigured, or correctly patched. 'Open' is where investigation starts, not where it ends.",
          "Only scan or probe hosts and port ranges you are explicitly authorised to test — port scanning third-party infrastructure without permission can itself be treated as an intrusion attempt, regardless of intent.",
        ],
        tone: "offense",
      },
    ],
    exercises: [
      {
        type: "order",
        q: "Order the steps to verify if a local service is accessible from the internet.",
        items: [
          "Run 'ss -tulpen' to find the port and bind address",
          "Check 'ip addr' for the public interface",
          "Try to connect via 'curl' from a remote machine",
          "Analyze firewall logs / run tcpdump if the connection fails",
        ],
        explain: "Check if it's listening and how it's bound, find the correct public interface, test externally, then debug the block with packet capture if needed.",
        hints: ["Verify the local state first.", "Testing from the outside is the validation step, debugging comes after a failure."],
        ref: "Worked example: is my web server exposed?",
      },
      {
        type: "mc",
        q: "In the command 'ss -tulpen', what does the '-l' flag signify?",
        options: ["List all files", "Show only listening sockets", "Log output to a file", "Long format"],
        answer: 1,
        why: [
          "ss has nothing to do with the filesystem.",
          "",
          "ss does not write logs to disk; -l is unrelated to logging.",
          "There is no 'long format' meaning for -l in ss.",
        ],
        explain: "-l filters for sockets that are currently in the LISTEN state, excluding established connections.",
        hints: ["It contrasts with showing established connections.", "Think 'Listen'."],
        ref: "Prerequisite: bind addresses and local sockets",
      },
      {
        type: "match",
        q: "Match the Nmap port state to its meaning.",
        pairs: [
          ["Open", "SYN-ACK received, service accepting connections"],
          ["Closed", "RST received, host alive but nothing listening"],
          ["Filtered", "No response at all, likely dropped by a firewall"],
        ],
        explain: "Open and closed both receive a definite reply from the host; filtered gets silence, usually meaning a firewall dropped the probe.",
        hints: ["Which one is 'silent'?", "Which one involves a reset (RST) packet?"],
        ref: "Open, closed, and filtered: reading nmap's verdict",
      },
      {
        type: "fill",
        q: "Fill in the bind address that restricts a listening service to connections from the same machine only, regardless of firewall rules.",
        answers: ["127.0.0.1", "localhost", "loopback"],
        explain: "Binding to loopback (127.0.0.1) means the kernel never routes external packets to that socket at all — firewall rules are irrelevant.",
        hints: ["It's the classic 'this machine only' address."],
        ref: "Prerequisite: bind addresses and local sockets",
      },
      {
        type: "mc",
        q: "You run tcpdump on the server while probing it from outside and see the incoming SYN packet arrive, but no SYN-ACK is ever sent back. What does this most likely indicate?",
        options: [
          "The remote client made a typo in the IP address",
          "DNS is misconfigured",
          "The host's own firewall (e.g. iptables) is dropping the packet before the application sees it",
          "The application crashed after sending the SYN-ACK",
        ],
        answer: 2,
        why: [
          "A typo would mean the SYN never arrives at all — but we're told it did arrive.",
          "DNS resolution happens before the SYN is sent; it has no bearing on what occurs after the packet lands.",
          "",
          "If a SYN-ACK had been sent and then lost, that's a different (rarer) symptom; this scenario specifically shows the host-level firewall as the most likely local block since the packet arrived but got no reply.",
        ],
        explain: "Seeing the SYN arrive via tcpdump but no SYN-ACK leave means the packet reached the network interface but was blocked before reaching (or responding from) the application — classic sign of a host-based firewall rule.",
        hints: ["Recall the worked example's tcpdump diagnostic step.", "Where between 'packet arrives' and 'application responds' could it be dropped?"],
        ref: "Worked example: is my web server exposed?",
      },
      {
        type: "fill",
        q: "Fill in the one-word nmap port state that specifically means 'no response received, likely firewall-dropped' (not confirming absence or presence of a service).",
        answers: ["filtered"],
        explain: "Filtered is nmap's label for silence — a probe that got no reply at all, most often because a firewall dropped it, leaving the actual service state unknown.",
        hints: ["It's not open or closed — it's the ambiguous third state."],
        ref: "Open, closed, and filtered: reading nmap's verdict",
      },
    ],
  },
];
