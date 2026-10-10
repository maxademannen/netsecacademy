import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "udp-and-limits",
    title: "UDP & Scan Limits",
    summary: "Why UDP scanning is slower and more ambiguous than TCP, and why scan results are always incomplete.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "After this lesson you can explain why UDP scanning produces ambiguous results where TCP usually doesn't, why real-world conditions (rate limiting, firewalls) make any single scan incomplete, and what to do about that incompleteness.",
        ],
      },
      {
        title: "No handshake, no certainty",
        kind: "intuition",
        body: [
          "TCP is like a phone call: you dial, it rings, someone answers or the line is busy — you always learn something. UDP is like dropping a letter through someone's door slot: you don't know if anyone is home, whether they read it, or whether they'll ever write back, even if they actually received it.",
          "This single property — no guaranteed acknowledgement — is the root cause of every UDP scanning difficulty in this lesson.",
        ],
      },
      {
        title: "Prerequisite: ICMP",
        kind: "prereq",
        body: [
          "ICMP (Internet Control Message Protocol) is a diagnostic/error-reporting protocol that operating systems use automatically, separately from TCP/UDP. The classic example is `ping`, which uses ICMP Echo Request/Reply.",
          "When a UDP packet arrives at a closed port, the OS doesn't reply using UDP — UDP has no concept of 'error'. Instead, it sends a separate ICMP message: 'Destination Unreachable, Port Unreachable' (ICMP type 3, code 3). This is the only reliable TCP-handshake-equivalent signal UDP scanning gets.",
        ],
      },
      {
        title: "Reading UDP scan states",
        kind: "explain",
        body: [
          "Closed: an ICMP 'port unreachable' message comes back — a clear, confident signal.",
          "Open: either the application sends back a protocol-specific reply (e.g. a DNS server answers a DNS query), or nothing comes back at all because the application chooses to ignore unrecognised probes.",
          "Because 'open' and 'no reply' can look identical from the scanner's side, nmap reports the ambiguous case as `open|filtered` — it is explicitly telling you it could not distinguish 'open and silent' from 'blocked by a firewall'.",
          "To resolve the ambiguity, you send a probe the real application understands (e.g. an actual DNS query to port 53, an SNMP GET to port 161) — a genuine application reply proves 'open' beyond doubt.",
        ],
        code: `nmap -sU -p 53,69,161 198.51.100.44

PORT    STATE         SERVICE
53/udp  open          domain      <- answered a real DNS query, confirmed open
69/udp  closed        tftp        <- ICMP port-unreachable received
161/udp open|filtered snmp        <- no reply of any kind; still ambiguous`,
        tone: "offense",
        check: {
          type: "mc",
          q: "Why does Nmap label a UDP port as 'open|filtered' instead of just 'open' or 'closed'?",
          options: [
            "The port sent back a SYN/ACK packet",
            "The scanner received no response at all, and that silence is consistent with either an open-but-silent port or a firewall quietly dropping the probe",
            "The port sent an ICMP Port Unreachable message",
            "The connection used TLS encryption nmap could not decode",
          ],
          answer: 1,
          why: [
            "SYN/ACK is a TCP concept; UDP has no handshake at all.",
            "",
            "This is the precise definition given in the lesson: silence is ambiguous between two different real causes.",
            "An ICMP Port Unreachable reply would instead be classified as closed, with a confident answer.",
            "Encryption is unrelated — the issue is total absence of any reply.",
          ],
          explain: "Open|filtered means no response was received at all, and the scanner genuinely cannot tell whether that's because the port is open and the application ignored the probe, or because a firewall silently dropped it.",
          hints: ["Think about what 'silence' means in UDP, compared to TCP.", "Is silence proof of anything specific?"],
          ref: "Reading UDP scan states",
        },
      },
      {
        title: "Worked example: rate limiting hides real ports",
        kind: "example",
        body: [
          "You scan 1,000 UDP ports on a Linux host that limits outgoing ICMP error messages to roughly one per second (a common OS default meant to prevent the host itself being used in denial-of-service traffic).",
          "Of those 1,000 ports, suppose only 3 are genuinely closed and 997 are genuinely open. The host should ideally send 3 ICMP 'port unreachable' messages — one per closed port.",
          "But because of the one-per-second ICMP rate limit, and because your scanner sent all 1,000 probes within a few seconds, the OS can only emit a handful of those ICMP replies before the limit kicks in. Some genuinely closed ports will appear to get no reply at all, purely due to timing — not because they're actually open.",
          "Conclusion: the scan result for those falsely-silent closed ports will incorrectly show `open|filtered`, even though they are closed. This is a concrete, mechanical reason why a single fast scan is never a complete or fully accurate picture — not carelessness, but a real OS-level constraint.",
        ],
      },
      {
        title: "Why results are structurally incomplete",
        kind: "mistakes",
        body: [
          "Mistake: treating a scan result as a permanent fact. Services restart, firewalls get reconfigured, and load balancers route traffic differently over time — a scan is a snapshot of one moment on one network path.",
          "Mistake: assuming a scanner that reports nothing means nothing is there. Rate limiting (as shown above), aggressive IPS/firewall throttling of a noisy scanner, and simple packet loss on the network can all produce false negatives — real services that the scan simply failed to see.",
          "Mistake: scanning once and considering enumeration finished. The pragmatic response to structural incompleteness is to scan slower/retried on anything important, cross-check with a second tool or technique, and treat 'no finding' as 'no finding yet', not 'confirmed absent'.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "You scan all 65535 UDP ports on 203.0.113.80 at high speed and see 65,200 ports reported as open|filtered and only 300 reported as closed. Is it accurate to report '65,200 open UDP services' to the client?",
        ],
        check: {
          type: "mc",
          q: "What is the accurate interpretation of 65,200 'open|filtered' results from one fast scan?",
          options: [
            "All 65,200 ports are confirmed open services and should be reported as such",
            "Most of those are very likely ICMP replies suppressed by rate limiting or firewalling, not genuinely open services; a slower rescan or protocol-specific probing is needed before drawing conclusions",
            "The target has no closed ports at all",
            "The scan was a complete failure and should be discarded entirely",
          ],
          answer: 1,
          why: [
            "open|filtered explicitly means 'unconfirmed' — reporting it as confirmed open misrepresents the evidence.",
            "",
            "Correct — this matches the worked example's mechanism almost exactly; a huge open|filtered count after a fast scan is a strong signal of rate-limit interference, not a genuine service count.",
            "300 closed ports were in fact observed, so that claim is contradicted by the data.",
            "The scan still produced useful data (300 confirmed closed, a target to investigate further) — it isn't worthless, just incomplete.",
          ],
          explain: "A huge number of open|filtered results after a single fast scan is a classic symptom of ICMP rate limiting rather than a genuinely huge number of open services — the honest next step is a slower, more careful rescan or protocol-specific confirmation.",
          hints: ["Recall the worked example's numbers: 997 open vs 3 closed, but ICMP rate limited to ~1/sec.", "What does open|filtered actually promise you?"],
          ref: "Guided practice",
        },
      },
      {
        title: "Relevance: validation before reporting",
        kind: "relevance",
        body: [
          "UDP scan results tell you where to look next, not a final inventory. Before reporting any UDP finding, validate it: send a real protocol-appropriate query (DNS lookup, SNMP walk, NTP query) and only report 'open' once you've received a genuine application-level reply, not merely the absence of an ICMP error.",
          "This generalises beyond UDP: any scanning technique can under- or over-report due to timing, rate limits, and network conditions. Treating scan output as ground truth, rather than as a hypothesis to validate, is one of the most common quality failures in real engagements.",
        ],
        tone: "defense",
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "Why does Nmap label a UDP port as 'open|filtered'?",
        options: [
          "The port sent a SYN/ACK packet.",
          "The scanner received no response at all.",
          "The port sent an ICMP Port Unreachable message.",
          "The firewall explicitly rejected the connection with a reset.",
        ],
        answer: 1,
        why: [
          "SYN/ACK does not exist in UDP — there is no handshake.",
          "",
          "Correct — no response at all is exactly what produces the ambiguous open|filtered label.",
          "An ICMP Port Unreachable message is what produces the confident 'closed' state, not open|filtered.",
          "An explicit reset/rejection is a TCP concept; UDP firewalls that block typically just drop the packet silently.",
        ],
        explain: "Open|filtered occurs when no response is received at all. The scanner cannot tell if the packet reached an open port that didn't respond, or if it was dropped by a firewall.",
        hints: [
          "Think about what 'silence' means in UDP.",
          "Is silence a confirmation of an open port?",
          "A firewall dropping a packet looks identical, from the scanner's point of view, to an application ignoring a probe it didn't understand.",
        ],
        ref: "Reading UDP scan states",
      },
      {
        type: "match",
        q: "Match the UDP scan result to its most likely cause:",
        pairs: [
          ["ICMP Port Unreachable received", "Port is Closed"],
          ["Protocol-specific application response received", "Port is Open (confirmed)"],
          ["No response of any kind", "Port is Open|Filtered (ambiguous)"],
        ],
        explain: "ICMP errors give a confident closed verdict, a genuine application reply confirms open, and total silence is the ambiguous case this lesson focuses on.",
        hints: [
          "What does 'Unreachable' usually mean for a port?",
          "If a service actually answers your DNS or SNMP query, is that ambiguous or confirmed?",
        ],
        ref: "Reading UDP scan states",
      },
      {
        type: "fill",
        q: "UDP scanning accuracy is limited because many OS kernels rate-limit the number of ____ error messages they'll send per second, which Nmap relies on to identify closed ports.",
        answers: ["ICMP"],
        explain: "Operating systems limit the rate of ICMP Destination Unreachable messages (often to roughly one per second), which Nmap depends on to confidently mark UDP ports as closed.",
        hints: [
          "It's the protocol discussed in the prerequisite card of this lesson.",
          "Ping uses this same protocol for its Echo Request/Reply.",
        ],
        ref: "Prerequisite: ICMP",
      },
      {
        type: "mc",
        q: "In the worked example, why did genuinely closed UDP ports end up reported as 'open|filtered' rather than 'closed'?",
        options: [
          "Because closed ports can never be detected over UDP under any circumstances",
          "Because the host's ICMP rate limit meant some of the 'port unreachable' replies for closed ports were never sent in time, making them indistinguishable from silence",
          "Because the scanner used the wrong protocol by mistake",
          "Because the target was behind a VPN",
        ],
        answer: 1,
        why: [
          "Closed UDP ports can be detected — that's exactly how the 300 confirmed closed ports in the practice question were found.",
          "",
          "Correct — this is the precise mechanism explained in the worked example: ICMP rate limiting suppresses some genuine 'closed' replies.",
          "The scanner used the correct UDP protocol throughout the example.",
          "VPN usage was never mentioned and isn't the cause described.",
        ],
        explain: "The worked example shows that ICMP rate limiting (e.g. ~1/sec) can suppress the 'port unreachable' reply for some genuinely closed ports when many probes are sent quickly, making them look identical to open|filtered results.",
        hints: ["Reread the worked example's numbers and its final conclusion sentence."],
        ref: "Worked example: rate limiting hides real ports",
      },
    ],
  },
  {
    id: "vhosts",
    title: "Virtual Host Discovery",
    summary: "How one IP can host many hidden web applications, and how to find them via Host-header fuzzing.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "After this lesson you can explain why a single IP can serve multiple distinct websites, use the Host header to discover ones that aren't linked anywhere public, and avoid the false-positive trap of a default catch-all page.",
        ],
      },
      {
        title: "One address, many tenants",
        kind: "intuition",
        body: [
          "Think of an apartment building with one street address that contains many separate flats. The postal address alone doesn't tell the postman which flat a letter is for — that information is on the envelope itself.",
          "A web server IP is the building's street address; the HTTP `Host` header is the apartment number written on the envelope. One server process, one IP, can serve completely different websites depending only on what hostname the visitor asked for.",
        ],
      },
      {
        title: "Prerequisite: what the Host header does",
        kind: "prereq",
        body: [
          "Every HTTP/1.1 request must include a `Host` header stating which hostname the client intends to reach, because the underlying TCP connection only knows the IP address, not the human-readable domain name.",
          "A single server can be configured to check this header and serve different content for different values: `site-a.example.com` might return a public marketing site, while `dev.internal.example.com` on the exact same IP returns an internal development build, with no public link pointing to it.",
          "If you connect directly to the IP (or send a Host value the server doesn't recognise), most servers fall back to a 'default' virtual host — often a generic placeholder page, not the real hidden application.",
        ],
        code: `GET / HTTP/1.1
Host: dev.internal.example.com`,
      },
      {
        title: "Fuzzing the Host header",
        kind: "explain",
        body: [
          "Because the hidden vhost's hostname usually isn't published anywhere, discovering it means guessing candidate hostnames systematically — the same brute-force principle as content discovery, applied to the Host header instead of the URL path.",
          "A tool like ffuf sends the same request repeatedly, substituting a different candidate hostname into the Host header each time, and records how the response differs. Common candidates include dev, staging, api, git, vpn, admin, internal.",
          "A response that differs meaningfully in size or content from the 'default' fallback page is a strong signal you've found a real, distinct virtual host.",
        ],
        code: `ffuf -w subdomains.txt -u http://198.51.100.9 -H "Host: FUZZ.target.example"`,
        tone: "offense",
      },
      {
        title: "Worked example: filtering the default page",
        kind: "example",
        body: [
          "You run the fuzz above against 198.51.100.9 with a 5,000-word subdomain list. Nearly all 5,000 attempts return `200 OK` with exactly 4,242 bytes — the server's default fallback page, served whenever the Host header doesn't match a configured vhost.",
          "Step 1: confirm the baseline. Request the IP with an obviously made-up Host value, e.g. `Host: doesnotexist.target.example`, and note the response size — 4,242 bytes, matching almost everything else.",
          "Step 2: filter it out. Re-run the fuzz with `-fs 4242` to hide every response matching that exact size.",
          "Step 3: inspect what remains. Two candidates survive the filter: `staging.target.example` (9,811 bytes, a full staging site) and `git.target.example` (301 redirect to a login page). These are the genuine, previously-undiscovered virtual hosts.",
        ],
        code: `$ curl -s -o /dev/null -w "%{size_download}\\n" -H "Host: doesnotexist.target.example" http://198.51.100.9
4242

$ ffuf -u http://198.51.100.9 -H "Host: FUZZ.target.example" -w subdomains.txt -fs 4242
staging                 [Status: 200, Size: 9811]
git                     [Status: 301, Size: 0]`,
        check: {
          type: "mc",
          q: "Why does the worked example first send a request with an obviously fake Host header before running the full fuzz?",
          options: [
            "To crash the server as a denial-of-service test",
            "To establish the baseline size of the server's default/fallback response, so it can later be filtered out of the real results",
            "Because fake Host headers are required by the HTTP specification",
            "To bypass authentication",
          ],
          answer: 1,
          why: [
            "This is a measurement step, not an attack — no disruption is intended or caused.",
            "",
            "Correct — this mirrors the soft-404 baseline technique from the content-discovery lesson, applied to vhosts.",
            "The HTTP spec has no such requirement; this is a reconnaissance technique, not a protocol rule.",
            "This step has nothing to do with authentication.",
          ],
          explain: "Establishing the default page's size first lets you filter it out with -fs, so only genuinely different (real) virtual hosts remain visible in the results — the same baseline-then-filter pattern used for soft 404s.",
          hints: ["Compare this to the soft-404 technique taught in Content discovery.", "What does step 1 let you do in step 2?"],
          ref: "Worked example: filtering the default page",
        },
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: treating every 200 OK response as a discovered vhost, without first checking whether it just matches the default page's size — exactly the false-positive trap the worked example walks through.",
          "Mistake: assuming a discovered vhost is automatically insecure. Finding `staging.target.example` proves an additional application surface exists; it says nothing yet about whether that staging environment has any actual weaknesses.",
          "Mistake: confusing vhost discovery (same IP, different Host header) with subdomain DNS enumeration (different IPs entirely, found via DNS records, covered in Unit 2). They often overlap in practice, but the discovery method and what each result proves are different.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "A fuzz of Host headers against 203.0.113.60 shows: `www` -> 200, 7010 bytes (known real site); `dev` -> 200, 7010 bytes; `shop-api` -> 200, 512 bytes; `intranet` -> 403, 128 bytes. You already confirmed the default fallback page for this server is 7010 bytes.",
        ],
        check: {
          type: "order",
          q: "Order these four Host-header results from 'most clearly a real, distinct finding' to 'most clearly just the default fallback page'.",
          items: ["shop-api (200, 512 bytes)", "intranet (403, 128 bytes)", "www (200, 7010 bytes)", "dev (200, 7010 bytes)"],
          explain: "shop-api has a unique size unrelated to the default page — the clearest real finding. intranet is explicitly protected, confirming it exists as something distinct. www is the known legitimate site serving the same size as the baseline, which is expected for it specifically. dev matches the default fallback size exactly and most likely isn't a distinct vhost at all without further checking.",
          hints: [
            "Which result's size doesn't match the known default-page baseline at all?",
            "A 403 still proves the server recognised the hostname as something specific.",
            "'www' being the same size as default makes sense because www IS the main/real site; 'dev' being the same size is more suspicious since dev isn't expected to equal the fallback.",
          ],
          ref: "Guided practice",
        },
      },
      {
        title: "Relevance: what vhost discovery proves",
        kind: "relevance",
        body: [
          "Vhost discovery proves that a server is configured to respond differently to a specific hostname — i.e. that an additional, often undocumented, application exists on infrastructure you already have in scope.",
          "It does NOT prove that application is misconfigured or vulnerable. A newly found staging or admin vhost is a new place to apply the same careful enumeration and validation process taught throughout this unit — not an automatic finding by itself.",
          "Only fuzz Host headers against IP addresses and domains explicitly included in your authorised scope; a discovered hostname pointing outside that scope should be left alone or reported, not tested.",
        ],
        tone: "defense",
      },
    ],
    exercises: [
      {
        type: "order",
        q: "Order the steps to perform VHost discovery on a target IP (203.0.113.60):",
        items: [
          "Identify the default/fallback response size using an obviously fake Host value",
          "Select a subdomain wordlist",
          "Run ffuf with the -H 'Host: FUZZ.target.example' flag",
          "Filter out the default response size using -fs",
          "Manually inspect the unique surviving results",
        ],
        explain: "First establish a baseline (the default page's size), then fuzz while filtering that baseline out, and finally verify the genuine outliers manually — this is exactly the worked example's sequence.",
        hints: [
          "You can't tell 'different' from 'normal' without first knowing what 'normal' looks like.",
          "Filtering requires knowing the size to filter before you can apply -fs usefully.",
          "Manual inspection is always the final verification step, never the first.",
        ],
        ref: "Worked example: filtering the default page",
      },
      {
        type: "mc",
        q: "Which HTTP header is most critical for Virtual Host routing, and why?",
        options: [
          "User-Agent — it tells the server what browser is being used",
          "Host — it tells the server which hostname was requested, which is the only way one IP can serve multiple distinct sites",
          "X-Forwarded-For — it records the original client IP",
          "Cookie — it carries session state",
        ],
        answer: 1,
        why: [
          "User-Agent identifies the client software, unrelated to vhost routing.",
          "",
          "Correct — exactly the mechanism explained in the prerequisite card.",
          "X-Forwarded-For is about tracking original client IPs through proxies, not vhost selection.",
          "Cookies carry session data, not hostname routing information.",
        ],
        explain: "The Host header tells the web server which specific domain the client is requesting, which is what allows multiple sites to exist behind one IP address.",
        hints: ["Which header did the prerequisite card say every HTTP/1.1 request must include for this purpose?"],
        ref: "Prerequisite: what the Host header does",
      },
      {
        type: "match",
        q: "Match the ffuf flag to its function in a vhost discovery scan:",
        pairs: [
          ["-u", "Target URL (the IP or base address being probed)"],
          ["-w", "Path to the wordlist of candidate hostnames"],
          ["-H", "Sets a custom header, here the Host header with FUZZ"],
          ["-fs", "Filters out responses of a given byte size (the default page)"],
        ],
        explain: "These four flags are exactly what's used in the lesson's vhost fuzzing commands: target, wordlist, custom Host header, and size-based filtering.",
        hints: ["-u is for the endpoint.", "-w is for the list of strings to try.", "-fs stands for 'filter size'."],
        ref: "Fuzzing the Host header",
      },
      {
        type: "mc",
        q: "A vhost fuzz finds 'intranet.target.example' returning 403 Forbidden, a different size than the default page. What's the correct interpretation?",
        options: [
          "It's a false positive and should be ignored",
          "It's a real, distinct virtual host that the server explicitly recognises and protects — worth further authorised investigation, not an automatic vulnerability",
          "403 means the vhost fuzz failed completely",
          "The server is down",
        ],
        answer: 1,
        why: [
          "A deliberate 403 (different from the default page) is actually strong evidence of a real, distinct vhost — not noise.",
          "",
          "Correct — matches both the guided practice reasoning and the 'common mistakes' guidance about not assuming automatic vulnerability.",
          "A 403 is a successful, informative response, not a failure of the scan.",
          "A 403 indicates the server is very much up and actively making an access decision.",
        ],
        explain: "A protected response that differs from the known default page confirms a genuine, distinct vhost exists — exactly the reasoning used in the guided practice for the 'intranet' result.",
        hints: ["Compare this to the 'intranet' result in the guided practice."],
        ref: "Guided practice",
      },
    ],
  },
  {
    id: "scan-tuning",
    title: "Scan Tuning & Verification",
    summary: "Balancing scan speed with accuracy, staying within scope, and manually validating every finding.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: [
          "After this lesson you can explain why scanning speed trades off against safety and accuracy, apply rate limiting and scope exclusions correctly, and manually verify a scanner's claim before treating it as a reportable finding.",
        ],
      },
      {
        title: "A scanner is a tool, not an oracle",
        kind: "intuition",
        body: [
          "A smoke detector sometimes beeps from burnt toast, and sometimes fails to notice a smouldering fire slowly starting in a wall cavity. It's a useful, imperfect signal — not a verdict. A port scanner behaves the same way: fast settings and automation produce false alarms (false positives) and missed detections (false negatives) just like a cheap smoke detector.",
          "Treating any single automated scan result as proven fact, without checking it yourself, is the single most common way inexperienced testers produce an inaccurate report.",
        ],
      },
      {
        title: "Prerequisite: false positive vs false negative",
        kind: "prereq",
        body: [
          "A false positive is when a tool reports something that isn't actually true — e.g. a scanner claims a vulnerability exists, but manual testing shows it doesn't.",
          "A false negative is the opposite: something real exists, but the tool failed to detect or report it — e.g. a service is genuinely running, but a too-fast scan, firewall throttling, or packet loss caused the scanner to miss it.",
          "Both error types matter in security testing: false positives waste the client's remediation time on non-issues, while false negatives mean a real exposure goes unreported.",
        ],
      },
      {
        title: "Safety and scope",
        kind: "explain",
        body: [
          "Scanning too fast can overwhelm fragile legacy services or trigger automated defensive responses (temporary bans, alerting, even service crashes). Every authorised engagement has 'Rules of Engagement' (RoE) — written limits on timing, intensity and which assets are in scope — and these must be followed exactly.",
          "`--max-rate` caps how many packets per second nmap sends, letting you deliberately trade speed for safety on sensitive targets.",
          "`--exclude` removes specific hosts from a scan even if they fall within an otherwise-scanned range, which is essential when part of a /24 is out of scope.",
        ],
        code: `nmap --max-rate 100 --exclude 10.0.0.5 10.0.0.0/24`,
        tone: "defense",
        check: {
          type: "fill",
          q: "Which nmap flag caps the number of packets sent per second, trading scan speed for safety on sensitive targets?",
          answers: ["--max-rate", "max-rate"],
          explain: "--max-rate <n> is the flag used to limit nmap's packet-per-second rate, reducing the risk of overwhelming a fragile or rate-limited target.",
          hints: ["Look at the example command in this card.", "It starts with two dashes and the word 'max'."],
          ref: "Safety and scope",
        },
      },
      {
        title: "Worked example: verifying before reporting",
        kind: "example",
        body: [
          "nmap -sV reports `8080/tcp open http Jetty 9.4.z-SNAPSHOT` with an NSE script noting `|_http-title: Jenkins [Jenkins]`. Before writing a finding, you verify it manually.",
          "Step 1 — confirm the service with a direct request: `curl -I http://198.51.100.17:8080/`. The response headers (`Server: Jetty(9.4.z-SNAPSHOT)`) match the scanner's claim, confirming it isn't a misidentification.",
          "Step 2 — check for an unauthenticated feature the scanner only hinted at: visiting `/script` in a browser (Jenkins's built-in script console, which — if reachable without login — allows arbitrary code execution) returns a login prompt rather than the console itself. This means the specific unauthenticated-RCE concern is NOT confirmed here, even though the service and version are real.",
          "Step 3 — report precisely: 'Jenkins (Jetty 9.4.z-SNAPSHOT) identified on 198.51.100.17:8080, version confirmed via banner; the /script console required authentication during testing' — an accurate statement that neither overstates nor understates what was actually found.",
        ],
        code: `$ curl -I http://198.51.100.17:8080/
HTTP/1.1 200 OK
Server: Jetty(9.4.z-SNAPSHOT)

$ curl -s http://198.51.100.17:8080/script
<html>...<form action="/login">...</form></html>`,
      },
      {
        title: "Common mistakes",
        kind: "mistakes",
        body: [
          "Mistake: reporting a scanner's automated 'vulnerability detected' output verbatim without manually reproducing it — a classic source of false positives that damages a report's credibility.",
          "Mistake: running exploitation tooling immediately upon finding an open port, skipping the verification step entirely — risky, often out of scope, and not necessary to produce a solid finding.",
          "Mistake: assuming a quiet scan (few or no findings) means the target has no issues, when it may simply mean rate limiting or scope restrictions reduced visibility — see the UDP lesson for a concrete mechanism behind this.",
          "Mistake: ignoring the Rules of Engagement's timing/intensity limits because 'it would be faster' — violating RoE can cause real outages and is a serious professional and sometimes legal problem.",
        ],
      },
      {
        title: "Guided practice",
        kind: "practice",
        body: [
          "A scanner flags port 8080 as 'open — Jenkins, CRITICAL: unauthenticated RCE via script console'. You manually visit the script console URL and it prompts for a login, exactly as in the worked example.",
        ],
        check: {
          type: "mc",
          q: "What should your report say about this finding?",
          options: [
            "Report it as a confirmed critical RCE exactly as the scanner stated",
            "Report that Jenkins was identified and version-confirmed, but that the specific unauthenticated script-console access the scanner flagged was not reproducible — authentication was required when manually tested",
            "Don't mention Jenkins at all since the scanner was wrong",
            "Report that the entire scan was invalid and rerun it from scratch",
          ],
          answer: 1,
          why: [
            "This repeats an unverified, apparently false claim as if confirmed — exactly the false-positive mistake this lesson warns against.",
            "",
            "Correct — accurately separates what was confirmed (the service/version) from what wasn't (the specific RCE claim), matching the worked example's reporting style.",
            "The service itself is real and worth noting even though the critical claim didn't hold up.",
            "One unconfirmed automated flag doesn't invalidate an entire scan's other results.",
          ],
          explain: "Good reporting separates what you personally verified from what a tool merely claimed, exactly as shown in the Jenkins worked example — stating both the confirmed fact (service identity) and the unconfirmed/disproven claim (the RCE path) accurately.",
          hints: ["Compare this directly to the worked example's Step 3 report wording."],
          ref: "Guided practice",
        },
      },
      {
        title: "Relevance: scan tuning in a real engagement",
        kind: "relevance",
        body: [
          "Rate limiting and scope exclusions protect the client's infrastructure and keep you inside your authorisation — both are professional obligations, not optional extras. Manual verification protects the integrity of your report.",
          "A scan result — any scan result, from any tool — is a hypothesis about the target's state, not a fact. The discipline taught across this entire unit (scan, enumerate, verify, then report precisely what was confirmed versus what wasn't) is what separates a credible security assessment from a noisy automated printout.",
        ],
        tone: "defense",
      },
    ],
    exercises: [
      {
        type: "fill",
        q: "To limit an Nmap scan to 100 packets per second, which flag (with value) would you add to the command?",
        answers: ["--max-rate 100", "max-rate 100", "--max-rate"],
        explain: "--max-rate caps the packets-per-second nmap will send, which is crucial for not overwhelming the network or a fragile target.",
        hints: ["Opposite of a minimum rate.", "It caps the speed."],
        ref: "Safety and scope",
      },
      {
        type: "mc",
        q: "An automated scanner reports a 'critical' finding on port 8080. What is the best next step for a professional tester before writing the report?",
        options: [
          "Immediately report it as a critical finding, since the scanner said so",
          "Run an automated exploit tool against it immediately",
          "Manually verify the specific claim (e.g. with curl or a browser) before deciding what to report",
          "Ignore it and move to a different host",
        ],
        answer: 2,
        why: [
          "Scanner output needs independent verification, as the Jenkins worked example demonstrates — reporting it unverified risks a false positive.",
          "",
          "Jumping to exploitation tooling before verification is both unnecessary and often outside authorised scope.",
          "Correct — matches the worked example's methodology exactly.",
          "Dismissing a flagged finding without checking it risks a false negative in the other direction.",
        ],
        explain: "Manual verification ensures the finding is real and gives you the accurate wording for a report, as shown by confirming the Jenkins service but finding the specific RCE claim unreproducible.",
        hints: ["What did the worked example do between the scanner's claim and writing the final report sentence?"],
        ref: "Worked example: verifying before reporting",
      },
      {
        type: "order",
        q: "Based on this lesson's reasoning, rank these four scan results by how much immediate investigative priority they deserve, from highest to lowest.",
        items: [
          "HTTP port returning a specific banner, e.g. 'Server: Apache/2.4.1 (Unix)'",
          "TCP port 445 (SMB) reported as open",
          "UDP port 161 (SNMP) reported as open|filtered",
          "A host that didn't respond to ping at all",
        ],
        explain: "A concrete, identified software/version banner gives the most to investigate immediately. A known historically-risky open service like SMB is next. An ambiguous open|filtered UDP result needs more work before it's actionable. A non-responding host could simply be blocking ICMP and needs a completely different check (e.g. a direct port scan) rather than being deprioritised outright, but among these four it offers the least immediate signal.",
        hints: [
          "A specific, confirmed version string gives you the most concrete next step (e.g. a targeted search for known issues).",
          "SMB has a long history of high-impact misconfigurations, making it a high-value target even before version info.",
          "Ambiguous UDP results need more work before they're actionable at all.",
        ],
        ref: "Common mistakes",
      },
      {
        type: "mc",
        q: "What is the key difference between a false positive and a false negative in scanning?",
        options: [
          "They mean the same thing",
          "A false positive reports something that isn't true; a false negative fails to report something that is true",
          "A false positive is always worse than a false negative",
          "False positives only happen with UDP scans",
        ],
        answer: 1,
        why: [
          "They are opposite error types, not synonyms.",
          "",
          "Correct — this is the exact distinction given in the prerequisite card.",
          "Neither is universally 'worse' — each causes a different kind of harm (wasted effort vs missed exposure).",
          "False positives can occur in any scan type, not just UDP.",
        ],
        explain: "A false positive is an incorrect claim of something being present; a false negative is a real thing the tool failed to detect — both covered as the prerequisite for discussing verification.",
        hints: ["Reread the prerequisite card's two definitions carefully."],
        ref: "Prerequisite: false positive vs false negative",
      },
    ],
  },
];
