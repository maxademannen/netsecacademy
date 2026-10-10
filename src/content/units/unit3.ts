import type { Unit } from "../types";

const unit3: Unit = {
  id: "scanning",
  index: 3,
  title: "Scanning & Enumeration",
  tagline: "Turn 'host is up' into 'here are 14 attack surfaces'.",
  tone: "offense",
  lessons: [
    {
      id: "scan-types",
      title: "Nmap, the proper way",
      summary: "What scanning actually detects, SYN vs connect vs UDP, and a pragmatic workflow.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can explain what a port scan actually measures (not 'is there a vulnerability' — 'did something answer on this port'), choose the right nmap technique for a situation, and read ambiguous results (like open|filtered) without over-claiming what they prove.",
          ],
        },
        {
          title: "What is a port, really?",
          kind: "intuition",
          body: [
            "A computer has one IP address but can run many network services at once — a web server, an SSH daemon, a database. A port number (0-65535) is how the operating system tells incoming traffic which program should receive it, the same way an apartment building has one street address but many apartment numbers.",
            "'Scanning' means systematically sending traffic to a range of ports on a host and recording how each one responds: a knock on every door of the building to see which apartments answer.",
            "Where the analogy breaks: a closed apartment door still proves someone lives in the building. A closed TCP port proves nothing extra — most hosts have thousands of closed ports and it tells you nothing about what's running elsewhere. Scanning only tells you about the doors that answered.",
          ],
        },
        {
          title: "Prerequisite: the TCP handshake",
          kind: "prereq",
          body: [
            "TCP (Transmission Control Protocol) sets up a connection before any data flows, using a 3-step handshake: the client sends a packet with the SYN flag ('synchronize, I want to talk'); if something is listening on that port, the server replies SYN-ACK ('acknowledged, go ahead'); the client finishes with ACK and the connection is now open.",
            "If nothing is listening on that port, the OS replies RST (reset) — 'nobody home, stop trying'. If a firewall is silently dropping the packet, there is no reply at all — the scanner just times out.",
            "These three outcomes (SYN-ACK, RST, nothing) are the entire alphabet that TCP scanning reads from. Everything nmap reports is built from them.",
          ],
          code: `Client                         Server
  |-------- SYN ---------------->|   "can we talk on port 22?"
  |<------- SYN-ACK -------------|   "yes, go ahead"  => port OPEN
  |-------- ACK ----------------->|

  |-------- SYN ---------------->|
  |<------- RST ------------------|   "nothing listening" => port CLOSED

  |-------- SYN ---------------->|
  |         (silence)             |   firewall dropped it => port FILTERED`,
        },
        {
          title: "SYN scan vs connect scan vs UDP scan",
          kind: "explain",
          body: [
            "`-sS` (SYN / half-open scan): nmap sends the SYN, reads the reply, then sends an RST instead of completing the handshake. It never fully opens a connection, so it's fast and usually isn't logged by the application — only by the OS/firewall. Requires raw-socket privileges (root/admin).",
            "`-sT` (TCP connect scan): completes the full 3-way handshake using the OS's normal connect() call. No special privileges needed, but every connection is logged by the target application, and it's slower because each socket is fully opened and closed.",
            "`-sU` (UDP scan): UDP has no handshake at all. nmap sends a probe; if it gets an ICMP 'port unreachable' message back, the port is closed. If a UDP-specific application reply comes back, the port is open. If nothing comes back, nmap must report the ambiguous state `open|filtered` — it genuinely cannot tell whether the port is open and silent or blocked by a firewall.",
          ],
          code: `-sS  SYN / half-open  : fast, needs root, default when privileged
-sT  TCP connect     : no root required, loud (full handshake, logs connection)
-sU  UDP scan        : slow; closed replies ICMP port-unreachable, open stays silent
-sV  version detect  : banner-grab + probes; feeds everything downstream
-O   OS detect       : stack-fingerprint
-sC  default scripts : runs nmap NSE scripts — tons of free wins
-A   = -sV -sC -O --traceroute   kitchen sink
--top-ports 1000     : the ports actually worth scanning first
-p-                  : all 65535. slow, but you must do it at least once per target
-T4                  : timing, 0 (paranoid) to 5 (insane). 4 is normal.`,
          check: {
            type: "mc",
            q: "A SYN scan (-sS) against a port receives no reply at all, even after retransmits. What is the most accurate state nmap reports?",
            options: ["open", "closed", "filtered", "open|filtered"],
            answer: 2,
            why: [
              "Open requires a SYN-ACK reply — that never arrived.",
              "Closed requires an RST reply — that never arrived either.",
              "",
              "open|filtered is only reported for UDP ambiguity; TCP silence after a SYN is classified as filtered because something (a firewall) is almost certainly dropping it.",
            ],
            explain:
              "In TCP scanning, silence after a SYN means a firewall is dropping the packet with no response — nmap calls this 'filtered'. Contrast with UDP, where silence is genuinely ambiguous between open and filtered because many open UDP services simply don't reply to a generic probe.",
            hints: [
              "Think about the three possible replies to a SYN: SYN-ACK, RST, or nothing.",
              "'Nothing' after a SYN is different from 'nothing' after a UDP probe — TCP almost always gets a response unless something is actively blocking it.",
            ],
            ref: "SYN scan vs connect scan vs UDP scan",
          },
        },
        {
          title: "Worked example: reading real output",
          kind: "example",
          body: [
            "You run `nmap -sS -p22,80,443,8080,161 198.51.100.17` (a documentation-range IP used for this course) and get the output below. Walk through each line.",
            "Port 22: SYN-ACK received → open. This is expected for a managed server.",
            "Port 80: SYN-ACK received → open. A web service is listening, but we know nothing about *what* it is yet — that requires -sV, covered in the next lesson.",
            "Port 443: RST received → closed. Interesting: HTTPS is closed but HTTP (80) is open. That's a configuration detail worth noting, not a vulnerability.",
            "Port 8080: SYN-ACK received → open. An alternate HTTP port, commonly used for admin panels, proxies or dev servers — worth prioritising in enumeration.",
            "Port 161/udp: no reply → open|filtered. We cannot conclude anything yet; it needs a protocol-specific SNMP probe to resolve the ambiguity (covered later in this unit).",
          ],
          code: `Nmap scan report for 198.51.100.17
PORT     STATE   SERVICE
22/tcp   open    ssh
80/tcp   open    http
443/tcp  closed  https
8080/tcp open    http-proxy

PORT     STATE         SERVICE
161/udp  open|filtered snmp`,
        },
        {
          title: "A pragmatic workflow",
          kind: "explain",
          body: [
            "Pass 1: `-sS --top-ports 1000 -T4` across the IP range. Finds the large majority of services in minutes because most services sit on well-known ports.",
            "Pass 2: `-sS -p- -T4` on hosts that looked interesting. Catches services deliberately or accidentally placed on unusual ports (admins sometimes move SSH to 22222 or run an app on 50000, hoping scanners won't check).",
            "Pass 3: `-sV -sC -p <found ports>` for versions + scripts. This is where concrete software names and version numbers appear — the input you need to look up known vulnerabilities (next lesson).",
            "Pass 4: `-sU --top-ports 100` for UDP. SNMP, DNS, NTP and similar services live here and are frequently missed because UDP scanning is slow and often skipped under time pressure.",
          ],
          code: `nmap -sS -T4 --top-ports 1000 -oA quick 198.51.100.0/24
nmap -sS -T4 -p- -oA deep 198.51.100.17 198.51.100.42
nmap -sV -sC -p22,80,443,8080,5984,27017 -oA versions 198.51.100.17`,
          tone: "offense",
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: treating 'top 1000 ports scanned, nothing interesting' as 'this host has no services'. Top-1000 is a shortlist of common ports, not all 65535 — a full `-p-` pass can reveal more.",
            "Mistake: reading `open|filtered` on a UDP port as 'confirmed open'. It explicitly means 'we don't know' — it requires further probing before you can state anything as fact.",
            "Mistake: assuming a closed port means the service doesn't exist anywhere on the network. It only means nothing is listening on *that port, on that host, at that moment* — services can run on other hosts, other ports, or be temporarily down.",
            "Mistake: confusing 'port is open' with 'this is vulnerable'. An open port only tells you a service is reachable — whether it is exploitable is a completely separate question answered by version detection, configuration review and validation (lesson 2 of this unit).",
          ],
        },
        {
          title: "Output you want to keep",
          kind: "explain",
          body: [
            "`-oA basename` saves three formats at once: .nmap (human-readable), .gnmap (grepable, one line per host), .xml (machine-parseable by other tools). Always use it — you will come back to this data later in an engagement.",
            "Piping the .gnmap file into `grep -w 'open'` quickly lists every open port found across an entire scan, which is useful for building the enumeration target list in the next lesson.",
          ],
        },
        {
          title: "Guided practice",
          kind: "practice",
          body: [
            "A scan of 203.0.113.9 (documentation range) returns: port 21/tcp → RST received; port 25/tcp → SYN-ACK received; port 53/udp → no reply at all.",
            "Classify each of the three results using exactly the vocabulary from this lesson (open / closed / filtered / open|filtered), and state what further step (if any) each one needs before you could say anything stronger about it.",
          ],
          check: {
            type: "match",
            q: "Match each scan result to its correct state.",
            pairs: [
              ["21/tcp, RST received", "closed"],
              ["25/tcp, SYN-ACK received", "open"],
              ["53/udp, no reply", "open|filtered"],
            ],
            explain:
              "RST always means closed on TCP. SYN-ACK always means open. UDP silence is inherently ambiguous and is reported as open|filtered until a protocol-specific probe (e.g. a real DNS query to port 53) resolves it.",
            hints: [
              "TCP gives a definite answer (SYN-ACK or RST) almost always.",
              "UDP silence on its own never proves a port is closed.",
            ],
            ref: "Guided practice",
          },
        },
        {
          title: "Relevance: what scanning proves and does not prove",
          kind: "relevance",
          body: [
            "Scanning proves: that a TCP/UDP endpoint responded in a way consistent with a listening service, at the moment you scanned, from the network path you scanned from.",
            "Scanning does NOT prove: that the service is vulnerable, that the result will be the same tomorrow (services restart, firewalls change, load balancers route differently), that nothing else is running (a firewall or IDS can rate-limit or selectively block your scanner, hiding real services — a false negative), or that an 'open' finding by itself is reportable as a security issue.",
            "In authorised testing, scanning is always step one: it defines where to look next (service enumeration), never the final answer. Only scan hosts and ranges explicitly covered by your written authorisation.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Match the flag to what it does.",
          pairs: [
            ["-sS", "SYN half-open scan (default when root)"],
            ["-sV", "Service / version detection"],
            ["-sC", "Run default NSE scripts"],
            ["-sU", "UDP scan"],
            ["-p-", "All 65535 TCP ports"],
          ],
          explain: "These are the five flags used throughout this unit; the lesson's 'Scan techniques' table defines each one.",
          hints: ["-s always starts a scan-type flag.", "-p always relates to port selection."],
          ref: "SYN scan vs connect scan vs UDP scan",
        },
        {
          type: "mc",
          q: "You scanned top-1000 ports and found nothing on a host your recon said was interesting. What should you try next, and why?",
          options: [
            "Give up — top-1000 already covers everything that matters",
            "Run -p- (all 65535 ports) — admins sometimes run services on unusual ports precisely to avoid casual scanners",
            "Reboot the router",
            "Switch to scanning a different, unrelated host",
          ],
          answer: 1,
          why: [
            "Top-1000 is a curated shortlist, not the full range — plenty of real services sit outside it.",
            "",
            "A full -p- sweep catches services that were deliberately or accidentally placed on non-standard ports.",
            "Rebooting a router you don't control is out of scope and irrelevant to the problem.",
            "Abandoning an interesting host based on an incomplete scan throws away a lead; the workflow in this lesson exists for this exact situation.",
          ],
          explain: "SSH on 22222, Jenkins on 50000, Elastic on 9200 — top-1000 misses all of these; the pragmatic workflow's Pass 2 exists precisely for this case.",
          hints: ["Reread the 'pragmatic workflow' card — what is Pass 2 for?"],
          ref: "A pragmatic workflow",
        },
        {
          type: "mc",
          q: "A UDP port shows 'open|filtered'. What does that specifically mean, and what would let you resolve the ambiguity?",
          options: [
            "It means the port is definitely both open and filtered at once",
            "No reply came back, so nmap cannot tell whether the port is open-and-silent or blocked by a firewall; a protocol-specific probe (e.g. -sV, or a real application query) can often resolve it",
            "The host is running Windows",
            "The traffic is encrypted, so nmap can't read it",
          ],
          answer: 1,
          why: [
            "'Both at once' is not a real network state — it's a label for 'we don't know yet'.",
            "",
            "OS identification is unrelated to this ambiguity.",
            "UDP ambiguity has nothing to do with encryption.",
          ],
          explain: "UDP has no handshake, so silence is ambiguous. Sending an application-specific probe (nmap's -sV does this, e.g. an actual SNMP or DNS query) often forces a reply that resolves the state.",
          hints: ["What two real-world situations both produce 'silence'?"],
          ref: "SYN scan vs connect scan vs UDP scan",
        },
        {
          type: "fill",
          q: "In the worked example, port 443/tcp returned an RST while port 80/tcp returned a SYN-ACK. What single-word state should 443 be recorded as?",
          answers: ["closed"],
          explain: "An RST in response to a SYN always means the port is closed — nothing is listening there, regardless of what's happening on other ports.",
          hints: ["Which of the three handshake outcomes did port 443 receive?", "RST = ?"],
          ref: "Worked example: reading real output",
        },
        {
          type: "order",
          q: "Put this scanning workflow in the correct order, from broadest/fastest to narrowest/most detailed.",
          items: [
            "-sS --top-ports 1000 across the whole range",
            "-sS -p- on the hosts that looked interesting",
            "-sV -sC on the specific ports found open",
            "-sU --top-ports 100 for UDP services",
          ],
          explain: "Start broad and cheap to triage the whole range, narrow to full-port scans on promising hosts, then layer on version/script detection, and finish with the slower UDP pass.",
          hints: ["Which pass is cheapest to run against an entire /24?", "Version detection needs to know which ports are open first."],
          ref: "A pragmatic workflow",
        },
      ],
    },
    {
      id: "service-enum",
      title: "Service enumeration",
      summary: "How service/version identification works, and turning an open port into a concrete finding.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "After this lesson you can explain how nmap identifies what software is behind an open port (not just that the port is open), follow a per-service checklist to gather more information, and state clearly why 'found a service' is not the same claim as 'found a vulnerability'.",
          ],
        },
        {
          title: "From 'something answered' to 'I know what it is'",
          kind: "intuition",
          body: [
            "Finding an open door tells you a room exists. It does not tell you what's inside. Service enumeration is walking up and asking the room what it is — and often the room announces itself without being asked.",
            "Where this breaks down: some services lie or stay silent about their identity (hardened servers strip version info), and some services answer differently depending on exactly how you ask — so identification is a best guess built from evidence, not a certainty.",
          ],
        },
        {
          title: "Prerequisite: what is a 'banner'?",
          kind: "prereq",
          body: [
            "Many network services send a short greeting message the instant a connection opens, before any request is made — this is called a banner. It usually names the software and version, because that's genuinely useful for legitimate clients to know (e.g. an email client needs to know if the SMTP server supports a certain extension).",
            "Example: connecting to an SSH server often immediately returns a line like `SSH-2.0-OpenSSH_7.4`. No scanning technique is needed for this — it is just the first bytes the server sends to anyone who connects.",
            "Not every service volunteers a banner. HTTP servers, for instance, only reveal information in response to an actual request (the `Server:` response header), and that header is sometimes deliberately removed by administrators.",
          ],
          code: `$ nc 198.51.100.17 22
SSH-2.0-OpenSSH_7.4

$ curl -I http://198.51.100.17
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)`,
        },
        {
          title: "How nmap -sV actually works",
          kind: "explain",
          body: [
            "Version detection (`-sV`) is more than reading a banner. For each open port, nmap: (1) checks if a banner was offered for free, (2) if not, sends a sequence of known probes appropriate to common protocols on that port (an HTTP GET, a TLS ClientHello, an SSL handshake, etc.) and inspects the raw bytes of the reply, (3) matches the reply against a database of thousands of known service signatures (nmap-service-probes), (4) reports its best match along with a confidence level.",
            "This is why -sV can correctly identify a web server running on port 31337 (not port 80) — it isn't trusting the port number, it's trusting the behaviour.",
            "NSE scripts (`-sC`, 'Nmap Scripting Engine') go one step further: once a service is identified, specific scripts can log in anonymously, list shares, read metadata, or check for specific known misconfigurations — turning 'what is this' into 'what can it tell me'.",
          ],
          code: `nmap --script ssh2-enum-algos,ssh-auth-methods -p22 198.51.100.17
nmap --script ftp-anon,ftp-syst -p21 198.51.100.17
nmap --script smb-vuln-* -p445 198.51.100.17`,
          tone: "offense",
          check: {
            type: "mc",
            q: "Why can nmap -sV correctly identify a web server even when it has been moved to an unusual port like 31337?",
            options: [
              "Because nmap trusts whatever label the port number conventionally implies",
              "Because -sV sends protocol probes and inspects the actual response content, rather than relying on which port number was used",
              "Because web servers are not allowed to run on non-standard ports",
              "Because nmap asks the operating system directly which program owns the port",
            ],
            answer: 1,
            why: [
              "Port-number convention is exactly what version detection does NOT rely on — that's the whole point of the technique.",
              "",
              "There is no such restriction; services can run on any port.",
              "Nmap scans remotely over the network; it has no access to the target OS's internal process table.",
            ],
            explain:
              "-sV is behaviour-based, not port-number-based: it sends real protocol probes and matches the response against a signature database, which is exactly why it catches services hiding on unconventional ports.",
            hints: ["Reread how -sV identifies services — does it read the port number or the response content?"],
            ref: "How nmap -sV actually works",
          },
        },
        {
          title: "Per-service checklists",
          kind: "explain",
          body: [
            "Each common service has a short list of 'always try this first' checks. These checks are not exploits — they are information-gathering steps that are safe within an authorised scope and frequently surface serious findings on their own (e.g. a database with no authentication at all).",
          ],
          code: `# SSH 22
ssh root@<ip>                      # banner says 'OpenSSH 7.4'? that version string is the input for a later CVE lookup

# FTP 21
nmap --script ftp-anon,ftp-syst -p21 <ip>
ftp <ip>  -> USER anonymous / PASS anonymous

# SMB 139/445
smbclient -L //<ip> -N              # null session (no credentials)
nmap --script smb-vuln-* -p445 <ip>

# DNS 53
dig AXFR @<ip> target.example       # zone transfer attempt

# SMTP 25/587
nmap --script smtp-enum-users,smtp-commands -p25 <ip>

# SNMP 161 (UDP) - default community strings are still found constantly
onesixtyone -c communities.txt <ip>
snmpwalk -v2c -c public <ip>

# Databases: 3306 mysql / 5432 postgres / 1433 mssql / 27017 mongo / 6379 redis / 9200 elastic
# Checking for default creds and unauthenticated access is a standard first step.`,
          tone: "offense",
        },
        {
          title: "Worked example: Redis with no password",
          kind: "example",
          body: [
            "You enumerate 198.51.100.21 and nmap -sV reports `6379/tcp open redis Redis key-value store`. Step by step, how do you turn this into a usable finding:",
            "Step 1 — confirm what it is: connect directly with `redis-cli -h 198.51.100.21 PING`. A reply of `PONG` confirms a live, responsive Redis instance (not just an open port — an actual conversation with the service).",
            "Step 2 — check authentication: run a command that would normally require privileges, e.g. `CONFIG GET dir`. If it succeeds without ever sending an `AUTH` command, the instance has no password configured.",
            "Step 3 — assess impact, don't exploit without authorisation: unauthenticated write access to Redis can in some configurations be escalated to remote code execution (by writing an SSH key file via CONFIG SET / SAVE), but doing so is only appropriate inside a lab or with explicit written permission to attempt it on this exact host.",
            "Step 4 — write it up: the reportable fact is 'Redis on 198.51.100.21:6379 accepts unauthenticated commands including CONFIG GET/SET', evidenced by the PING/CONFIG transcript — not a guess, not a port number alone.",
          ],
          code: `$ redis-cli -h 198.51.100.21 PING
PONG
$ redis-cli -h 198.51.100.21 CONFIG GET dir
1) "dir"
2) "/var/lib/redis"`,
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: reporting 'port 6379 open' as the finding. The reportable fact is the behaviour you observed (no authentication required), with evidence — not the port number.",
            "Mistake: treating a matched version string as proof of a specific CVE without checking the exact version and patch level. Vendors backport security fixes, so 'Apache 2.4.29' on one distro may already be patched against a CVE that affects 2.4.29 elsewhere.",
            "Mistake: assuming a service that didn't respond to one probe style doesn't exist. Firewalls, rate-limiting and strict application logic can suppress a banner or probe reply while the service is fully present and reachable through the correct request.",
            "Mistake: running exploitation steps (writing files, dumping a full database, deleting data) during what should be a verification step. Verification should use the minimum action needed to confirm a finding, especially on shared or production-adjacent systems.",
          ],
        },
        {
          title: "Guided practice",
          kind: "practice",
          body: [
            "An nmap -sV scan of 203.0.113.44 reports: `27017/tcp open mongodb MongoDB 3.6.3`, and a follow-up NSE script `mongodb-databases` lists `admin, config, local, customerdata` without ever supplying credentials.",
            "What is the one sentence you would write in a report to describe this finding accurately — and what have you NOT yet proven about it?",
          ],
          check: {
            type: "mc",
            q: "Which statement below is the accurate, well-evidenced version of this finding?",
            options: [
              "MongoDB 3.6.3 has a known remote code execution vulnerability, so this host is exploitable",
              "MongoDB on 203.0.113.44:27017 allows unauthenticated access and disclosed database names including 'customerdata', as shown by the mongodb-databases script output — the actual sensitivity of the data inside customerdata has not yet been verified",
              "Port 27017 is open, which is itself a critical finding",
              "The host is definitely compromised",
            ],
            answer: 1,
            why: [
              "No CVE was identified or confirmed in this scenario — that claim is unsupported by the evidence shown.",
              "",
              "Correct: the finding is stated precisely, tied to evidence, and honestly scopes what remains unverified.",
              "An open port alone is not a finding — the enumeration result (unauthenticated access) is what matters.",
              "No compromise (unauthorised use by a third party) was observed — only a misconfiguration.",
            ],
            explain:
              "Good findings report exactly what was observed (unauthenticated access, disclosed database names) with evidence, and explicitly separate that from claims that were not verified (the actual sensitivity/content of customerdata, or any specific CVE).",
            hints: [
              "Compare what the script actually showed versus what would need an extra verification step.",
              "Avoid both overclaiming (compromise, RCE) and underclaiming (just 'port open').",
            ],
            ref: "Guided practice",
          },
        },
        {
          title: "Relevance: discovered service vs verified vulnerability",
          kind: "relevance",
          body: [
            "A 'discovered service' is a fact about reachability and identity: something is listening on this port, and it behaves like this known piece of software at this version.",
            "A 'verified vulnerability' requires an extra step: showing that a specific, named weakness is actually exploitable (or at least clearly present) on this instance — via a safe proof-of-concept, a confirmed missing authentication check, or a config read that demonstrates the flaw, always within authorised scope.",
            "Mixing the two up is one of the most common quality problems in real security reports: 'found an old Apache version' is not a vulnerability until you show it is unpatched for a specific relevant CVE and that the CVE is actually reachable/triggerable here. This unit's lab (next) deliberately separates 'what did the scan find' from 'what did we confirm'.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Which SNMP community string is still, overwhelmingly, the most common finding when it isn't changed from its default?",
          answers: ["public"],
          explain: "'public' is SNMP's traditional default read-only community string; snmpwalk -v2c -c public reads device/system info with no authentication when it hasn't been changed.",
          hints: ["It's an adjective meaning 'open to everyone'.", "It is also the literal default shipped by most vendors."],
          ref: "Per-service checklists",
        },
        {
          type: "mc",
          q: "You find port 6379 open with no password required. What is it, and precisely what should you report?",
          options: [
            "Redis — report only 'port 6379 is open'",
            "Redis — report that CONFIG GET/SET succeeded without any AUTH command, with the command transcript as evidence; note the potential path to RCE but do not exploit without explicit authorisation",
            "A game server, harmless, no report needed",
            "An email server, log it as informational only",
          ],
          answer: 1,
          why: [
            "This under-reports the finding — the port number alone isn't the issue, the missing authentication is.",
            "",
            "This matches the worked example's methodology: confirm behaviour, capture evidence, note potential impact, stay within authorised actions.",
            "Redis's default port is 6379; this is not a game or email service.",
          ],
          explain: "The worked example in this lesson shows exactly this sequence: PING to confirm liveness, an authenticated-looking command without AUTH to prove the gap, and reporting the observed behaviour with evidence rather than speculation.",
          hints: ["What two commands did the worked example run, and in what order?"],
          ref: "Worked example: Redis with no password",
        },
        {
          type: "mc",
          q: "nmap -sV reports 'Apache httpd 2.4.29' on a target. Which conclusion is justified by this alone?",
          options: [
            "The server is definitely vulnerable to every CVE ever filed against 2.4.29",
            "The server is running software that identifies itself as Apache httpd version 2.4.29; whether any specific CVE applies depends on exact patch level and configuration, which still needs checking",
            "The server cannot be running any patches, since nmap reports a specific version",
            "This proves the site has SQL injection",
          ],
          answer: 1,
          why: [
            "Vendors frequently backport security fixes without changing the displayed version string, so this is an unsafe leap.",
            "",
            "This is the accurate, scoped conclusion — matches 'discovered service vs verified vulnerability'.",
            "Version strings don't indicate whether backported patches exist.",
            "SQL injection is an application-layer flaw unrelated to the web server's version banner.",
          ],
          explain: "This is the core distinction of the lesson: a version string is evidence of software identity, not automatic proof of any particular vulnerability, since distros backport fixes.",
          hints: ["Recall the 'common mistakes' card about CVE lookups."],
          ref: "Common mistakes",
        },
        {
          type: "fill",
          q: "In the Redis worked example, which single command confirmed the service was live and responsive before any authentication-related check was attempted?",
          answers: ["ping", "PING", "redis-cli -h 198.51.100.21 PING"],
          explain: "PING is step 1 of the worked example: confirming the service responds at all, before probing for missing authentication.",
          hints: ["What is the very first command run against Redis in the worked example?"],
          ref: "Worked example: Redis with no password",
        },
        {
          type: "order",
          q: "Order these steps the way the lesson's worked example approaches a newly discovered service.",
          items: [
            "Confirm the service responds and identify it (e.g. PING)",
            "Check whether an authenticated-only action succeeds without credentials",
            "Assess potential impact, without exploiting beyond scope",
            "Write up the specific, evidenced finding",
          ],
          explain: "This mirrors the Redis example precisely: confirm liveness, test for missing auth, consider impact responsibly, then document with evidence.",
          hints: ["Which step has to happen before you can even test authentication?", "Writing the report always comes last."],
          ref: "Worked example: Redis with no password",
        },
      ],
    },
    {
      id: "web-content",
      title: "Content discovery",
      summary: "Finding endpoints the sitemap doesn't mention, and reading status codes honestly.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "After this lesson you can explain why linked navigation only shows a fraction of a web app's real surface, run a directory/vhost/parameter brute-force responsibly, and correctly interpret HTTP status codes and 'soft 404s' rather than taking every response at face value.",
          ],
        },
        {
          title: "The web app is bigger than its homepage",
          kind: "intuition",
          body: [
            "A website's visible navigation menu is like the labelled rooms on a building's lobby directory. But buildings also have maintenance closets, staff-only staircases and basements that are real, physically present rooms — just not on the directory, because they weren't meant for visitors.",
            "Developers routinely leave similar 'unlisted but reachable' paths on web servers: /admin, /backup, /api/internal, /.git, /debug. None of these are linked from any page a normal visitor would see, but the URL still works if you type it.",
            "Where the analogy breaks: unlike a building, you cannot walk the whole web server and look — you have to guess path names and ask the server whether each one exists. That's what content discovery automates.",
          ],
        },
        {
          title: "Prerequisite: HTTP status codes",
          kind: "prereq",
          body: [
            "Every HTTP response starts with a 3-digit status code summarising the outcome. The first digit indicates the category: 2xx = success, 3xx = redirect, 4xx = client-side error (e.g. you asked for something wrong or you're not allowed), 5xx = server-side error.",
            "For content discovery, the codes that matter most are: 200 (the resource exists and was returned), 301/302 (the resource exists and redirects elsewhere — worth following), 401/403 (the resource exists, but you're not authenticated/authorised to see it — itself a useful signal that something is there), 404 (no resource at this path, as far as the server will admit).",
            "A brute-force tool works by requesting thousands of candidate paths and recording the status code (and size) of each response, then surfacing anything that isn't a plain 404.",
          ],
        },
        {
          title: "Why wordlists win",
          kind: "explain",
          body: [
            "A brute-force tool needs a list of candidate words to try as paths — this is the 'wordlist'. Rather than guessing randomly, security tooling uses curated lists built from years of observed real-world naming patterns (admin, backup, api, staging, .env, old...).",
            "SecLists is the most widely used public wordlist collection. Within it: `Discovery/Web-Content/raft-medium-*` for directories/files, `Discovery/DNS/subdomains-top1million-*.txt` for subdomains, `Discovery/Web-Content/burp-parameter-names.txt` for request parameters.",
            "Smaller, targeted lists (based on the specific tech stack observed in recon/enumeration) consistently outperform a giant generic list, because they finish faster and produce fewer irrelevant results to sift through.",
          ],
          code: `# directory brute force
ffuf -u https://target.example/FUZZ -w /lists/raft-medium-directories.txt -mc 200,204,301,302,403 -ac
feroxbuster -u https://target.example -w /lists/raft-medium-words.txt -x php,bak,old,txt -C 404 -t 50

# virtual hosts (Host header) - see also the "Virtual Host Discovery" lesson
ffuf -u https://target.example/ -H "Host: FUZZ.target.example" -w subs.txt -fs 1234

# parameter brute force
arjun -u https://target.example/api/v1/user -m GET
ffuf -u 'https://target.example/api/v1/user?FUZZ=admin' -w params.txt -fs 42`,
          tone: "offense",
        },
        {
          title: "Worked example: a soft-404 trap",
          kind: "example",
          body: [
            "You run a directory brute force against https://target.example and every single request — real or nonsense — comes back `200 OK` with roughly the same byte size. That is suspicious: it is statistically very unlikely that thousands of random guessed paths all genuinely exist.",
            "What's happening: the server has a custom 'not found' page that itself returns status 200 (instead of the correct 404) along with a near-identical page layout — a 'soft 404'. Your tool is currently useless because it can't tell real hits from the fake page.",
            "Fix: identify the fixed response size of the fake 'not found' page (e.g. by requesting an obviously nonexistent path like /thispathdoesnotexist12345 and noting its size, say 4238 bytes), then re-run the scan filtering that size out.",
            "Result after filtering: only two paths stand out with a different size — /admin (size 9120) and /api/v2 (size 512) — these are the genuine hits worth investigating further.",
          ],
          code: `$ curl -s -o /dev/null -w "%{http_code} %{size_download}\\n" https://target.example/thispathdoesnotexist12345
200 4238

$ ffuf -u https://target.example/FUZZ -w common.txt -mc 200 -fs 4238
admin      [Status: 200, Size: 9120]
api/v2     [Status: 200, Size: 512]`,
          check: {
            type: "fill",
            q: "In the worked example, what ffuf flag is used to exclude responses of the known 'fake 404' size (4238 bytes) from the results?",
            answers: ["-fs", "-fs 4238"],
            explain: "-fs (filter size) tells ffuf to hide responses of a given byte size — the standard fix for a soft-404 page that always returns 200.",
            hints: ["Look at the final ffuf command in the worked example.", "It's a 'filter' flag related to response size."],
            ref: "Worked example: a soft-404 trap",
          },
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: treating every 200 response as a confirmed finding without checking for a soft-404 baseline first, as shown above.",
            "Mistake: ignoring 401/403 responses as 'dead ends'. They confirm a resource exists and is being protected — valuable information for later authorisation testing (Unit 4), not something to discard.",
            "Mistake: assuming an endpoint you discovered is automatically a vulnerability. Finding `/api/internal/v1` proves an endpoint exists and is reachable; it proves nothing about whether it's exploitable until you examine how it actually behaves (see Unit 4 on access control).",
            "Mistake: brute-forcing at very high thread counts against a target without checking scope/rate limits, risking denial-of-service against a real system — always confirm authorised testing intensity first.",
          ],
        },
        {
          title: "Guided practice",
          kind: "practice",
          body: [
            "You brute-force https://shop.example.com and get: `/old-admin` -> 301, `/health` -> 200 (12 bytes), `/vendor` -> 403, and every nonexistent path you test by hand also returns 200 with exactly 12 bytes.",
            "Which of these four results should you actually trust as meaningful before doing anything else, and which one needs a baseline check first?",
          ],
          check: {
            type: "mc",
            q: "Which result in this scenario is most likely a soft-404 false positive requiring a baseline check?",
            options: ["/old-admin (301)", "/health (200, 12 bytes)", "/vendor (403)", "None of them need checking"],
            answer: 1,
            why: [
              "A 301 redirect is a specific, deliberate server behaviour unlikely to be the generic fallback page.",
              "",
              "Correct — every nonexistent path you manually tested also returned 200 with the identical 12-byte size, which is the exact signature of a soft-404 fallback.",
              "A 403 implies the server deliberately recognised and blocked access to something real.",
              "At least one of these needs scrutiny given the evidence.",
            ],
            explain:
              "The repeated, identical 200/12-byte response for paths you know don't exist is the textbook soft-404 signature described in the worked example — /health here cannot be trusted as a real distinct endpoint without a filter/baseline check.",
            hints: ["Which status code category are you taught to treat with the most suspicion by default?", "What did the worked example use as its tell-tale sign of a soft 404?"],
            ref: "Guided practice",
          },
        },
        {
          title: "Relevance: content discovery in authorised testing",
          kind: "relevance",
          body: [
            "Content discovery proves that a given URL path exists and is reachable, and roughly how the server treats it (success, redirect, protected, absent). It is a mapping technique, not an exploitation technique.",
            "It does NOT prove that a discovered path is misconfigured, insecure, or exposes anything sensitive — a 200 response on /backup might be an empty placeholder page, and a 403 on /admin might be correctly and robustly protected. Each discovered path is a lead to investigate, covered by the access-control and authentication material in Unit 4.",
            "Always brute-force only hosts explicitly covered by your authorised scope, and keep request rates within any limits stated by the engagement rules — aggressive scanning can degrade or crash production services.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Name the most widely used public wordlist collection referenced in this lesson for directory, subdomain and parameter brute-forcing.",
          answers: ["seclists", "SecLists"],
          explain: "SecLists is the standard, maintained collection of curated wordlists used throughout the content-discovery workflow in this lesson.",
          hints: ["It's a GitHub project, plural noun."],
          ref: "Why wordlists win",
        },
        {
          type: "mc",
          q: "ffuf returns 200 OK for every single path you try, including ones you know don't exist, all with nearly the same response size. What should you do?",
          options: [
            "Conclude the entire site is exposed and report every path as a finding",
            "Identify the response size of a known-fake path and add -fs <that size> to filter it out, then re-examine what remains",
            "Switch the scan to UDP",
            "Abandon content discovery on this target entirely",
          ],
          answer: 1,
          why: [
            "This massively over-reports — nearly all of those 200s are soft-404 noise, not real findings.",
            "",
            "This is exactly the fix demonstrated in the worked example.",
            "UDP is unrelated to HTTP content discovery.",
            "The technique still works once the soft-404 is filtered — abandoning it throws away a valid approach.",
          ],
          explain: "This is the soft-404 trap from the worked example: establish the fake page's size with a deliberately nonexistent path, then filter it with -fs to reveal genuine hits.",
          hints: ["Reread the worked example's exact two-step fix."],
          ref: "Worked example: a soft-404 trap",
        },
        {
          type: "mc",
          q: "You discover /api/internal/v1 returns 403 Forbidden. What is the correct interpretation?",
          options: [
            "The endpoint doesn't exist, so it should be discarded",
            "The endpoint exists and is being actively protected — it's a lead for access-control testing, not a dead end",
            "403 always means the server crashed",
            "403 proves the endpoint is vulnerable to SQL injection",
          ],
          answer: 1,
          why: [
            "403 specifically implies the server recognised the resource and chose to deny access — that's the opposite of nonexistent.",
            "",
            "Correct — matches the 'common mistakes' guidance about not discarding 401/403 responses.",
            "403 is an application-level access decision, not a server crash indicator.",
            "Nothing about a 403 response indicates anything about SQL injection.",
          ],
          explain: "A 403 confirms a resource exists but access is denied — valuable intel to revisit with the access-control concepts taught in Unit 4, not something to discard as a dead end.",
          hints: ["What does the HTTP status prerequisite card say 401/403 specifically mean?"],
          ref: "Common mistakes",
        },
        {
          type: "fill",
          q: "What HTTP status code category (first digit) indicates a redirect, such as a path that exists but forwards you elsewhere?",
          answers: ["3", "3xx", "300"],
          explain: "3xx status codes indicate redirection — the resource exists but the client should look elsewhere, per the prerequisite card on status codes.",
          hints: ["Review the HTTP status code prerequisite card.", "It's the digit before 01 or 02 in 301/302."],
          ref: "Prerequisite: HTTP status codes",
        },
        {
          type: "mc",
          q: "Why do smaller, targeted wordlists (based on the observed tech stack) often outperform one giant generic wordlist?",
          options: [
            "They always contain more words than generic lists",
            "They finish faster and produce fewer irrelevant hits to manually sift through, since they're tuned to the specific technology in use",
            "Generic wordlists are against the law to use",
            "Targeted wordlists never produce false positives of any kind",
          ],
          answer: 1,
          why: [
            "Targeted lists are typically smaller, not larger, than generic ones.",
            "",
            "This matches the lesson's explanation directly.",
            "There is no legal restriction on wordlist choice.",
            "Soft-404 false positives can occur regardless of wordlist choice; that's a separate problem solved by filtering, not wordlist size.",
          ],
          explain: "The lesson states this directly: targeted lists, informed by what you already know about the stack, beat a huge generic blast by being faster and more relevant.",
          hints: ["Reread the final sentence of 'Why wordlists win'."],
          ref: "Why wordlists win",
        },
      ],
    },
  ],
  lab: {
    id: "lab-scan",
    title: "Lab: scan and enumerate",
    tone: "offense",
    briefing: [
      "Target: 10.0.0.20, the shop server from the previous unit.",
      "Phase 1: scan, find all open ports and identify versions.",
      "Phase 2: enumerate the interesting ones.",
      "The flag is hidden somewhere in the enumeration output. Format: FLAG{...}",
    ],
    terminal: {
      host: "hunter@kali",
      commands: {
        "nmap -sS --top-ports 1000 10.0.0.20":
          "Nmap scan report for 10.0.0.20\nPORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\nNmap done: 1 host up, 3 ports.",
        "nmap -sS -p- 10.0.0.20":
          "PORT      STATE SERVICE\n22/tcp    open  ssh\n80/tcp    open  http\n443/tcp   open  https\n2049/tcp  open  nfs\n8080/tcp  open  http-proxy\n27017/tcp open  mongodb\n50000/tcp open  ibm-db2",
        "nmap -sV -sC -p22,80,443,8080,27017,50000 10.0.0.20":
          "22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)\n|_ssh-hostkey: 2048 ...\n80/tcp    open  http        Apache httpd 2.4.29\n|_http-title: Shop Example\n443/tcp   open  ssl/http    Apache httpd 2.4.29\n8080/tcp  open  http        Jetty 9.4.z-SNAPSHOT\n|_http-title: Jenkins [Jenkins]\n|_http-server-header: Jetty(9.4.z-SNAPSHOT)\n27017/tcp open  mongodb     MongoDB 3.6.3 (no auth)\n|_mongodb-databases: admin, config, local, shopdata\n50000/tcp open  ibm-db2?    DB2 10.5",
        "curl -s http://10.0.0.20:8080/":
          "<html><head><title>Jenkins</title></head><body>Welcome to Jenkins!<br><a href='/script'>Script Console</a> | <a href='/login'>sign in</a></body></html>",
        "mongo --host 10.0.0.20 --eval 'db.getSiblingDB(\"shopdata\").secrets.find().toArray()'":
          '[\n  { "_id": 1, "key": "adminPanelFlag", "value": "FLAG{m0ng0_w1th_n0_auth_1s_a_gift}" },\n  { "_id": 2, "key": "note", "value": "move secrets to Vault, 2019-11" }\n]',
        "ffuf -u http://10.0.0.20/FUZZ -w common.txt -mc 200,301,403 -silent":
          "admin                   [Status: 403, Size: 199]\nbackup                  [Status: 301, Size: 0]\nphpinfo.php             [Status: 200, Size: 72014]\nrobots.txt              [Status: 200, Size: 72]\n.git/HEAD               [Status: 200, Size: 23]",
        "curl -s http://10.0.0.20/robots.txt":
          "User-agent: *\nDisallow: /admin\nDisallow: /old-staff-portal\nDisallow: /api/internal/v1",
        "curl -s http://10.0.0.20/.git/HEAD":
          "ref: refs/heads/main",
        "ssh root@10.0.0.20": "ssh: connect refused by host — key auth only. Enumeration lab, not real exploitation.",
      },
      hints: [
        "nmap -sS --top-ports 1000 10.0.0.20",
        "nmap -sS -p- 10.0.0.20",
        "nmap -sV -sC -p22,80,443,8080,27017,50000 10.0.0.20",
        "ffuf -u http://10.0.0.20/FUZZ -w common.txt -mc 200,301,403 -silent",
        "curl -s http://10.0.0.20/robots.txt",
        "curl -s http://10.0.0.20/.git/HEAD",
        "curl -s http://10.0.0.20:8080/",
        "mongo --host 10.0.0.20 --eval 'db.getSiblingDB(\"shopdata\").secrets.find().toArray()'",
      ],
    },
    tasks: [
      {
        q: "How many TCP ports are open on 10.0.0.20 after a full -p- scan?",
        answers: ["7"],
        hint: "Count the entries in `nmap -sS -p- 10.0.0.20`.",
      },
      {
        q: "Which port runs an unauthenticated MongoDB that leaks the shopdata database?",
        answers: ["27017"],
        hint: "The -sV output names it.",
      },
      {
        q: "Which path discovered by ffuf should be reported as critical by itself (source-code disclosure)?",
        answers: [".git/head", ".git", ".git/HEAD"],
        hint: "An exposed .git directory often leaks the full source tree history.",
      },
      {
        q: "What is the flag? Format FLAG{...}",
        answers: ["FLAG{m0ng0_w1th_n0_auth_1s_a_gift}", "m0ng0_w1th_n0_auth_1s_a_gift"],
        hint: "Query the Mongo secrets collection.",
      },
    ],
  },
  ids: {
    name: "Scanner toolkit",
    description:
      "You can run nmap in the right phases, enumerate per-service, and brute-force content with ffuf — the daily routine of every hunter.",
    rules: [],
  },
};

export default unit3;
