import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "udp-and-limits",
    title: "UDP & Scan Limits",
    summary: "Understand why UDP scanning is slower and more ambiguous than TCP, and how environment limits impact scan accuracy.",
    cards: [
      {
        title: "The UDP Challenge",
        body: [
          "Unlike TCP, UDP is connectionless. When we send a probe, we don't get a 'SYN/ACK' back. A target port simply processes the data or ignores it.",
          "If a port is open, the application might respond, but it often stays silent. If a port is closed, the target OS usually sends an 'ICMP Port Unreachable' message.",
          "This 'silence vs. error' logic makes scanning slow. Scanners must wait for a timeout before assuming a port might be open."
        ],
        tone: "info"
      },
      {
        title: "Ambiguity: Open|Filtered",
        body: [
          "In Nmap, you'll often see 'open|filtered'. This means the scanner received no response at all.",
          "This happens for two reasons: either the port is truly open and the application didn't respond to the probe, or a firewall dropped the packet entirely.",
          "To resolve this, you often need to send protocol-specific payloads (like a DNS query for port 53) to force the application to talk back."
        ],
        code: "nmap -sU -p 53,69,161 <target>",
        tone: "offense"
      },
      {
        title: "Rate Limits & Network Shaping",
        body: [
          "UDP scanning is heavily throttled by modern operating systems. Linux, for example, often limits ICMP error messages to one per second.",
          "If you scan 1,000 UDP ports quickly, you will only see 1 'Closed' response, and 999 will appear 'open|filtered' because the kernel refused to send more ICMP errors.",
          "Network shaping and IPS can also 'hush' your scanner if you trigger too many alerts, leading to false negatives where active hosts seem down."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "Why does Nmap label a UDP port as 'open|filtered'?",
        options: [
          "The port sent a SYN/ACK packet.",
          "The scanner received no response at all.",
          "The port sent an ICMP Port Unreachable message.",
          "The firewall explicitly rejected the connection."
        ],
        answer: 1,
        explain: "Open|filtered occurs when no response is received. The scanner cannot tell if the packet reached an open port that didn't respond, or if it was dropped by a firewall.",
        hints: [
          "Think about what 'silence' means in UDP.",
          "Is silence a confirmation of an open port?",
          "A firewall dropping a packet looks the same as an application ignoring one."
        ]
      },
      {
        type: "match",
        q: "Match the UDP scan result to its most likely cause:",
        pairs: [
          ["ICMP Port Unreachable", "Port is Closed"],
          ["Protocol-specific Response", "Port is Open"],
          ["No Response", "Port is Open|Filtered"],
          ["ICMP Type 3 Code 13", "Port is Filtered (Firewall)"]
        ],
        explain: "ICMP errors indicate closed or filtered states, while a lack of response is ambiguous in UDP scanning.",
        hints: [
          "What does 'Unreachable' usually mean for a port?",
          "If a service actually answers your DNS or SNMP query, it's definitely open.",
          "Code 13 specifically indicates 'Communication Administratively Prohibited'."
        ]
      },
      {
        type: "fill",
        q: "UDP scanning is slow because many OS kernels limit the rate of ____ error messages to prevent DoS.",
        answers: ["ICMP"],
        explain: "Linux and other systems limit the rate at which they send ICMP Destination Unreachable packets, which Nmap relies on to identify closed ports.",
        hints: [
          "It's a protocol used for diagnostic messages.",
          "Ping uses this protocol, but so do 'Port Unreachable' errors.",
          "Four letters, starts with I."
        ]
      }
    ]
  },
  {
    id: "vhosts",
    title: "Virtual Host Discovery",
    summary: "Learn how to find hidden web applications sharing the same IP address using Host-header fuzzing.",
    cards: [
      {
        title: "What are VHosts?",
        body: [
          "Virtual Hosting allows one web server (at one IP) to host multiple domains (e.g., site-a.com and site-b.com).",
          "The server decides which content to serve based on the 'Host' header sent by your browser.",
          "If you browse to the IP directly, you usually see a 'default' page. The 'real' application might be hidden behind a specific hostname like 'dev.internal.local'."
        ],
        code: "GET / HTTP/1.1\nHost: dev.internal.local",
        tone: "info"
      },
      {
        title: "Fuzzing the Host Header",
        body: [
          "Attackers use tools like 'ffuf' or 'gobuster' to test thousands of potential hostnames against a single IP.",
          "We look for differences in the HTTP response. If 'Host: test.target.com' returns 500 bytes but 'Host: admin.target.com' returns 4500 bytes, we found a new VHost.",
          "Common subdomains to fuzz include: dev, staging, api, git, vpn, and admin."
        ],
        code: "ffuf -w subdomains.txt -u http://10.10.10.10 -H \"Host: FUZZ.target.com\"",
        tone: "offense"
      },
      {
        title: "Filtering Results",
        body: [
          "Most VHost fuzzing results in thousands of '200 OK' responses that just show the default page. This is a false positive.",
          "To find the needle in the haystack, we must filter out the 'default' response size.",
          "In ffuf, we use '-fs' (filter size) to ignore the common response length and only see the unique ones."
        ],
        code: "ffuf -u http://10.10.10.10 -H \"Host: FUZZ.target.com\" -w wordlist.txt -fs 4242",
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "order",
        q: "Order the steps to perform VHost discovery on a target IP (10.1.1.5):",
        items: [
          "Identify the default response size of the IP",
          "Select a subdomain wordlist",
          "Run ffuf with the -H 'Host: FUZZ.target.com' flag",
          "Filter out the default response size using -fs",
          "Manually inspect the unique results in a browser"
        ],
        explain: "First you need a baseline (default size), then you fuzz while filtering that baseline to find outliers.",
        hints: [
          "You can't find 'different' results if you don't know what 'normal' looks like.",
          "Filtering comes after or during the fuzzing process.",
          "Manual inspection is always the final verification step."
        ]
      },
      {
        type: "mc",
        q: "Which HTTP header is most critical for Virtual Host routing?",
        options: [
          "User-Agent",
          "Host",
          "X-Forwarded-For",
          "Cookie"
        ],
        answer: 1,
        explain: "The 'Host' header tells the web server which specific domain the client is requesting, allowing multiple sites to exist on one IP.",
        hints: [
          "It's the header that specifies the domain name.",
          "HTTP/1.1 made this header mandatory.",
          "It rhymes with 'most'."
        ]
      },
      {
        type: "match",
        q: "Match the ffuf flag to its function:",
        pairs: [
          ["-u", "Target URL"],
          ["-w", "Wordlist path"],
          ["-H", "Custom Header"],
          ["-fs", "Filter by HTTP response size"]
        ],
        explain: "These flags are essential for configuring ffuf for VHost discovery and result filtering.",
        hints: [
          "-u is for the endpoint.",
          "-w is for the list of strings to try.",
          "-fs stands for Filter Size."
        ]
      }
    ]
  },
  {
    id: "scan-tuning",
    title: "Scan Tuning & Verification",
    summary: "Learn to balance scan speed with accuracy, stay within scope, and manually verify findings.",
    cards: [
      {
        title: "Safety and Scope",
        body: [
          "Scanning too fast can crash legacy services or trigger DoS protections. Always respect the 'Rules of Engagement' (RoE).",
          "Use rate limiting to stay under the radar and avoid breaking things. Nmap's '--max-rate' allows you to cap packets per second.",
          "Always exclude out-of-scope assets using '--exclude' to avoid legal or operational issues."
        ],
        code: "nmap --max-rate 100 --exclude 10.0.0.5 10.0.0.0/24",
        tone: "defense"
      },
      {
        title: "Interpreting Results",
        body: [
          "Scanners make mistakes. A 'False Positive' is when a scanner reports a service or vulnerability that isn't actually there.",
          "A 'False Negative' is when a service exists but the scanner missed it (often due to speed or firewalls).",
          "Common causes of false positives include 'catch-all' DNS or WAFs that respond '200 OK' to every request."
        ],
        tone: "info"
      },
      {
        title: "Manual Verification",
        body: [
          "Never report a finding based solely on a scanner's output. Verify it manually.",
          "Use 'curl' to check web headers, or 'nc' (Netcat) to interact with a raw port to see if it's truly responsive.",
          "Verification helps you prioritize targets. A port that returns a specific version string is a much higher priority than one that just says 'open|filtered'."
        ],
        code: "curl -I http://target.com\nnc -nv 10.10.10.10 80",
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "fill",
        q: "To limit an Nmap scan to 50 packets per second, you would use the flag: --____-rate 50",
        answers: ["max"],
        explain: "--max-rate is crucial for ensuring your scan doesn't overwhelm the network or the target system.",
        hints: [
          "Opposite of minimum.",
          "It caps the speed.",
          "Three letters."
        ]
      },
      {
        type: "mc",
        q: "You find an open port 8080 with Nmap. What is the best next step for a professional tester?",
        options: [
          "Immediately report it as a critical finding.",
          "Run an automated exploit tool immediately.",
          "Manually verify the port using curl or a browser.",
          "Ignore it and move to a different IP."
        ],
        answer: 2,
        explain: "Manual verification ensures the finding is real and provides more context (like service headers) before taking further action.",
        hints: [
          "Scanners can give false positives.",
          "You need more info before reporting or exploiting.",
          "Trust but verify."
        ]
      },
      {
        type: "order",
        q: "Prioritize these scan results from highest to lowest interest for an initial attack:",
        items: [
          "HTTP port returning 'Server: Apache/2.4.1 (Unix)'",
          "TCP port 445 (SMB) reported as 'open'",
          "UDP port 161 (SNMP) reported as 'open|filtered'",
          "ICMP Echo Request (Ping) timed out"
        ],
        explain: "Specific version strings provide immediate exploit paths, followed by known risky services like SMB, then ambiguous UDP results, and finally inactive hosts.",
        hints: [
          "Version strings are gold mines.",
          "SMB is a very high-value target.",
          "Ambiguous results take more time to investigate."
        ]
      }
    ]
  }
];
