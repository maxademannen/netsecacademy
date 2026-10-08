import type { Unit } from "../types";
import { tcp, udp, http } from "../pkt";

const scanTraffic = [
  http(0.1, "10.0.0.12", "10.0.0.20", "GET / HTTP/1.1\nHost: shop.local"),
  tcp(0.3, "10.0.0.12", 49200, "10.0.0.20", 443, "S"),
  tcp(0.31, "10.0.0.20", 443, "10.0.0.12", 49200, "SA"),
  tcp(0.32, "10.0.0.12", 49200, "10.0.0.20", 443, "A"),
  ...Array.from({ length: 18 }, (_, i) =>
    tcp(2 + i * 0.05, "203.0.113.77", 40000 + i, "10.0.0.20", [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 8080][i]!, "S", {
      label: "port-scan",
      ttl: 44,
    }),
  ),
  ...Array.from({ length: 6 }, (_, i) =>
    tcp(2.02 + i * 0.05, "10.0.0.20", [21, 22, 23, 25, 53, 80][i]!, "203.0.113.77", 40000 + i, "R"),
  ),
  udp(5.0, "10.0.0.12", 53122, "10.0.0.1", 53, { payload: "QUERY A shop.local" }),
];

const unit3: Unit = {
  id: "recon",
  index: 3,
  title: "Recon & Scanning",
  tagline: "How an attacker maps you — and the footprints that leaves.",
  tone: "offense",
  lessons: [
    {
      id: "recon-ladder",
      title: "The reconnaissance ladder",
      summary: "Passive to active, quiet to loud.",
      cards: [
        {
          title: "Nobody attacks blind",
          body: [
            "Every intrusion starts with mapping: which hosts exist, which ports answer, which software is behind them.",
            "Recon escalates from completely passive (WHOIS, certificate transparency logs, search engines — invisible to you) to loudly active (full port sweeps, version probes).",
            "Your detection opportunity begins the moment it turns active.",
          ],
          tone: "offense",
        },
        {
          title: "Host discovery",
          body: [
            "ICMP echo is the classic sweep, but it is widely blocked, so scanners also use TCP SYN to port 80/443, TCP ACK, and ARP on the local segment.",
            "ARP sweeps are the quietest on a LAN and the hardest to block, because ARP must work.",
          ],
          code: `nmap -sn 10.0.0.0/24          ping sweep, no port scan
nmap -PS80,443 10.0.0.0/24    TCP SYN discovery
arp-scan --localnet           layer 2, cannot be firewalled off`,
        },
        {
          title: "Why defenders care about the order",
          body: [
            "A sweep followed minutes later by a focused port scan of the three hosts that answered is a far stronger signal than either event alone.",
            "Good detection correlates across time, not just per packet.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Which recon activity will your network sensor never see?",
          options: ["A SYN scan", "A WHOIS lookup of your domain", "An ARP sweep", "A version probe"],
          answer: 1,
          explain: "Passive recon happens against third parties. Only active probes touch your wire.",
        },
        {
          type: "order",
          q: "Order a typical attack chain from first to last.",
          items: ["Passive OSINT", "Host discovery sweep", "Port scan of live hosts", "Service version probing", "Exploitation"],
          explain: "Each step narrows the target set. Detecting step two or three buys you time before step five.",
        },
      ],
    },
    {
      id: "scan-types",
      title: "Scan types and their fingerprints",
      summary: "SYN, connect, FIN, Xmas, null, UDP — each leaves different packets.",
      cards: [
        {
          title: "The main techniques",
          body: ["Every scan is a question asked with a crafted packet. The response — or silence — is the answer."],
          code: `-sS  SYN / half-open : send SYN, read SYN-ACK or RST, never finish
-sT  TCP connect     : full handshake, gets logged by applications
-sF  FIN scan        : lone FIN. Closed ports RST, open ports stay silent
-sX  Xmas scan       : FIN+PSH+URG set together. No real stack does this
-sN  Null scan       : no flags at all
-sU  UDP scan        : slow; closed ports reply ICMP port-unreachable
-sV  Version probe   : connects and reads banners`,
        },
        {
          title: "Open vs closed vs filtered",
          body: [
            "Open: SYN-ACK comes back.",
            "Closed: RST comes back.",
            "Filtered: nothing comes back at all, because a firewall silently dropped it. That silence is information too.",
          ],
        },
        {
          title: "Detection angles",
          body: [
            "Rate: many distinct destination ports from one source in a short window.",
            "Impossible flags: Xmas and null packets can be alerted on with a single rule and essentially never false-positive.",
            "Incomplete handshakes: lots of SYNs from one source with almost no completed sessions.",
            "Timing evasion exists — nmap's -T0 can take a day per host — so your rules need long correlation windows as well as short ones.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A packet arrives with FIN, PSH and URG all set. What is it?",
          options: ["Normal connection teardown", "An Xmas scan", "A retransmission", "A TLS handshake"],
          answer: 1,
          explain: "No legitimate stack sends that combination, which makes it a perfect zero-false-positive signature.",
        },
        {
          type: "mc",
          q: "Why is a SYN (half-open) scan quieter than a connect scan?",
          options: [
            "It uses fewer bytes",
            "The handshake never completes, so many applications never log a connection",
            "It is encrypted",
            "It uses UDP",
          ],
          answer: 1,
          explain: "Application logs typically record accepted connections. Half-open scans stop before that.",
        },
        {
          type: "match",
          q: "Match the response to the port state.",
          pairs: [
            ["SYN-ACK", "Open"],
            ["RST", "Closed"],
            ["No response", "Filtered"],
            ["ICMP port unreachable", "Closed UDP port"],
          ],
          explain: "Silence means a firewall dropped the probe — different from an actively refused port.",
        },
        {
          type: "fill",
          q: "Which nmap flag performs a half-open SYN scan?",
          answers: ["-ss", "-sS"],
          explain: "-sS. It is nmap's default when run with privileges.",
        },
      ],
    },
    {
      id: "fingerprinting",
      title: "Fingerprinting and banners",
      summary: "Turning an open port into a software version.",
      cards: [
        {
          title: "Banners give it away",
          body: [
            "Many services announce themselves on connect. That one line tells an attacker which exploits to try.",
          ],
          code: `$ nc 10.0.0.20 22
SSH-2.0-OpenSSH_7.4

$ curl -I http://10.0.0.20
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/5.6.40`,
        },
        {
          title: "OS fingerprinting",
          body: [
            "Even without banners, stacks differ: initial TTL, TCP window size, option ordering, how they respond to malformed packets.",
            "nmap -O sends a battery of deliberately strange probes and matches the responses against a database.",
          ],
          tone: "offense",
        },
        {
          title: "Defensive response",
          body: [
            "Suppress or fake banners where you can, but do not rely on it — obscurity is not control.",
            "Better: alert on the probe pattern itself. A burst of malformed TCP options from one source is OS fingerprinting, full stop.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          exhibit: "Server: Apache/2.4.29 (Ubuntu)\nX-Powered-By: PHP/5.6.40",
          q: "What is the most urgent problem this response reveals?",
          options: [
            "Apache is running",
            "PHP 5.6 is long end-of-life and unpatched",
            "The server uses Ubuntu",
            "Nothing, headers are harmless",
          ],
          answer: 1,
          explain: "Version disclosure matters because the version named is unsupported and has public exploits.",
        },
        {
          type: "fill",
          q: "Which nmap flag attempts OS detection?",
          answers: ["-o", "-O"],
          explain: "-O, usually combined with -sV for service versions.",
        },
      ],
    },
    {
      id: "detect-scans",
      title: "Detecting scans",
      summary: "From single-packet signatures to rate thresholds.",
      cards: [
        {
          title: "Two detection families",
          body: [
            "Signature: this one packet is impossible or forbidden. Cheap, precise, limited.",
            "Threshold: this many events from one source within N seconds. Catches behaviour no single packet reveals.",
          ],
          code: `# single-packet signature
alert tcp any any -> $HOME_NET any (msg:"Xmas scan"; flags:FPU; sid:1001;)

# rate threshold
alert tcp any any -> $HOME_NET any (msg:"Port scan";
  flags:S; threshold: type threshold, track by_src, count 15, seconds 5;
  sid:1002;)`,
        },
        {
          title: "Choosing the count",
          body: [
            "Too low and your busiest load balancer becomes an attacker every morning. Too high and a patient scanner walks straight past.",
            "Measure your real traffic first, then set the threshold above the 99th percentile of normal.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Which rule option limits an alert to bursts rather than every matching packet?",
          options: ["nocase", "threshold", "dsize", "content"],
          answer: 1,
          explain: "threshold (or detection_filter) counts events per source or destination inside a time window.",
        },
        {
          type: "rule",
          q: "Write a rule that detects the port scan in this traffic — and does not alert on the normal web browsing.",
          traffic: scanTraffic,
          starter:
            '# HOME_NET is 10.0.0.0/24\n# Hint: bare SYN packets, many ports, one source, short window.\n# Add a threshold option so normal browsing stays quiet.\nalert tcp any any -> $HOME_NET any (msg:"Port scan detected"; flags:S; sid:1000001;)\n',
          explain:
            "A bare-SYN rule with a by_src threshold fires on the scanner while a handful of legitimate connections stay below the count.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-scan",
    title: "Lab: scan it, then catch it",
    tone: "offense",
    briefing: [
      "Phase 1 — attacker seat: use the terminal to scan 10.0.0.20 and find what it is running.",
      "Phase 2 — defender seat: write a rule that would have caught you.",
      "Everything here is simulated; nothing leaves your browser.",
    ],
    terminal: {
      host: "attacker@kali",
      commands: {
        "nmap -sn 10.0.0.0/24":
          "Starting Nmap 7.94\nNmap scan report for 10.0.0.1  (gateway)   Host is up\nNmap scan report for 10.0.0.12 (desktop)   Host is up\nNmap scan report for 10.0.0.20 (shop)      Host is up\nNmap scan report for 10.0.0.44 (laptop)    Host is up\nNmap done: 256 IP addresses (4 hosts up) scanned in 2.31 seconds",
        "nmap -sS 10.0.0.20":
          "Starting Nmap 7.94\nNmap scan report for 10.0.0.20\nPORT     STATE    SERVICE\n22/tcp   open     ssh\n80/tcp   open     http\n443/tcp  open     https\n3306/tcp filtered mysql\n8080/tcp closed   http-proxy\nNmap done: 1 IP address (1 host up) scanned in 4.02 seconds",
        "nmap -sV 10.0.0.20":
          "PORT    STATE SERVICE VERSION\n22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)\n80/tcp  open  http    Apache httpd 2.4.29 ((Ubuntu))\n443/tcp open  ssl/http Apache httpd 2.4.29\nService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel",
        "nmap -O 10.0.0.20":
          "Running: Linux 4.X\nOS CPE: cpe:/o:linux:linux_kernel:4.15\nOS details: Linux 4.15 - 5.6\nNetwork Distance: 1 hop",
        "nmap -sX 10.0.0.20":
          "PORT     STATE         SERVICE\n22/tcp   open|filtered ssh\n80/tcp   open|filtered http\n8080/tcp closed        http-proxy\nNote: Xmas scan cannot distinguish open from filtered on this stack.",
        "nc 10.0.0.20 22": "SSH-2.0-OpenSSH_7.4",
        "curl -I http://10.0.0.20":
          "HTTP/1.1 200 OK\nServer: Apache/2.4.29 (Ubuntu)\nX-Powered-By: PHP/5.6.40\nContent-Type: text/html",
      },
      hints: ["nmap -sn 10.0.0.0/24", "nmap -sS 10.0.0.20", "nmap -sV 10.0.0.20", "nc 10.0.0.20 22", "curl -I http://10.0.0.20"],
    },
    ruleChallenge: {
      goal: "Alert on the port scan from 203.0.113.77 without alerting on the three normal connections.",
      traffic: scanTraffic,
      starter:
        '# HOME_NET = 10.0.0.0/24\n# Goal: catch the scan, raise zero false positives.\n# This naive rule fires on every connection attempt. Fix it.\nalert tcp any any -> $HOME_NET any (msg:"TCP port scan"; flags:S; sid:1000010;)\n',
    },
    packets: scanTraffic,
    tasks: [
      {
        q: "Which TCP port on 10.0.0.20 is FILTERED rather than open or closed?",
        answers: ["3306"],
        hint: "Run `nmap -sS 10.0.0.20`.",
      },
      {
        q: "What SSH version is the host running? (e.g. OpenSSH_X.Y)",
        answers: ["openssh 7.4", "openssh_7.4", "7.4"],
        hint: "Banner-grab with `nc 10.0.0.20 22` or run `nmap -sV`.",
      },
      {
        q: "Which outdated scripting language version does the web server disclose?",
        answers: ["php 5.6", "php/5.6.40", "5.6.40", "php 5.6.40"],
        hint: "Try `curl -I http://10.0.0.20`.",
      },
    ],
  },
  ids: {
    name: "Scan detector",
    description:
      "Threshold tracking by source: your IDS now counts bare SYNs and impossible flag combinations and raises scan alerts.",
    rules: [
      'alert tcp any any -> $HOME_NET any (msg:"IDS: TCP port scan"; flags:S; threshold: type threshold, track by_src, count 15, seconds 5; sid:9003001;)',
      'alert tcp any any -> $HOME_NET any (msg:"IDS: Xmas scan"; flags:FPU; sid:9003002;)',
      'alert tcp any any -> $HOME_NET any (msg:"IDS: Null scan"; flags:0; sid:9003003;)',
    ],
  },
};

export default unit3;
