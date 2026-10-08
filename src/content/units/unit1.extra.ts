import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "linux-cli",
    title: "Linux CLI for Hunters",
    summary: "Master the shell basics and text processing tools required to triage a compromised host.",
    cards: [
      {
        title: "The Hunter's Shell",
        body: [
          "In Linux, everything is a file, and the shell is your scalpel. The power lies in **pipes** (`|`), which redirect the output of one command into the input of another.",
          "Commands like `cat`, `grep`, and `head` are basic building blocks. A hunter chains them to filter massive logs into actionable intelligence."
        ],
        code: "cat access.log | grep '404' | head -n 5",
        tone: "info"
      },
      {
        title: "Text Processing: Grep, Awk, Sed",
        body: [
          "When triaging, you don't read logs; you query them. `grep` finds strings, `awk` processes columns, and `sed` transforms text.",
          "Use `awk '{print $1}'` to extract the first column (often an IP address) or `grep -v` to exclude known-good noise from your results."
        ],
        code: "grep 'failed' auth.log | awk '{print $1, $9}' | sort | uniq -c",
        tone: "offense"
      },
      {
        title: "Hunter Reflex: Environment & Perms",
        body: [
          "Always check your surroundings. `env` reveals session variables that might contain secrets or modify execution paths ($PATH).",
          "Understand permissions: `chmod 400` makes a private key readable only by you. If a hunter finds a world-readable `.ssh` folder, the box is already lost."
        ],
        code: "ls -la /home/user/.ssh\necho $PATH",
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "order",
        q: "Order these commands to extract unique IP addresses that caused 404 errors from a log file.",
        items: ["cat access.log", "grep '404'", "awk '{print $1}'", "sort", "uniq"],
        explain: "We start with the raw file, filter for the error, isolate the IP column, sort them for uniq, then remove duplicates.",
        hints: ["Start with the file source.", "Extract the specific column before deduplicating."]
      },
      {
        type: "fill",
        q: "To make a script executable by the owner and group, but only readable by others, you would use 'chmod ____ script.sh'.",
        answers: ["774"],
        explain: "7 (rwx) for owner, 7 (rwx) for group, 4 (r--) for others.",
        hints: ["Owner needs 4+2+1.", "Others only need 4."]
      },
      {
        type: "mc",
        q: "Which environment variable defines the directories the shell searches for executable programs?",
        options: ["$HOME", "$SHELL", "$PATH", "$PWD"],
        answer: 2,
        explain: "$PATH is a colon-separated list of directories checked when you run a command without a full path.",
        hints: ["It defines the 'path' to binaries.", "Manipulating this is a common persistence technique."]
      }
    ]
  },
  {
    id: "tls-certs",
    title: "TLS & Certificate Recon",
    summary: "Analyze TLS handshakes and Certificate Transparency logs to map attack surfaces.",
    cards: [
      {
        title: "The TLS Handshake & SNI",
        body: [
          "TLS encrypts traffic, but the **SNI (Server Name Indication)** extension often sends the requested hostname in plaintext during the initial handshake.",
          "Hunters monitor SNI to identify which hidden services are hosted on a single IP address before the encryption layer is fully established."
        ],
        code: "openssl s_client -connect google.com:443 -servername google.com",
        tone: "info"
      },
      {
        title: "Certificate Transparency (CT)",
        body: [
          "CT logs are a public, append-only ledger of every SSL/TLS certificate ever issued. They are a goldmine for subdomain discovery.",
          "By querying logs for a domain, hunters can find `dev`, `staging`, or `internal` subdomains that aren't listed in public DNS records."
        ],
        tone: "offense"
      },
      {
        title: "Hunter Reflex: Certificate Chain Triage",
        body: [
          "Check the issuer. A 'Self-Signed' certificate on a public site is a huge red flag—it might indicate a Man-in-the-Middle (MITM) attack or a lazy admin.",
          "Verify the expiration and the 'Subject Alternative Name' (SAN) to see if the certificate is being reused across multiple unrelated domains."
        ],
        code: "curl -vI https://example.com",
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "match",
        q: "Match the TLS component to its role in security/recon.",
        pairs: [
          ["SNI", "Reveals hostname in plaintext"],
          ["CT Logs", "History of all issued certs"],
          ["SAN", "Other domains valid for this cert"],
          ["Root CA", "The anchor of trust"]
        ],
        explain: "SNI leaks names during handshake; CT logs are for discovery; SAN shows domain reuse; Root CAs validate the chain.",
        hints: ["One of these is a public ledger.", "One relates to multiple names on one cert."]
      },
      {
        type: "mc",
        q: "Why are Certificate Transparency (CT) logs valuable for an attacker?",
        options: [
          "They provide private keys for the domain",
          "They reveal subdomains not found via brute force",
          "They bypass firewall rules",
          "They encrypt the attacker's traffic"
        ],
        answer: 1,
        explain: "CT logs record every cert requested, including those for internal-sounding subdomains like 'vpn.company.com'.",
        hints: ["It's about discovery, not exploitation.", "Think about what is recorded when a cert is issued."]
      },
      {
        type: "fill",
        q: "The plaintext field in a TLS Client Hello that identifies the target website is called ____.",
        answers: ["SNI", "Server Name Indication"],
        explain: "SNI allows the server to present the correct certificate for the requested site.",
        hints: ["Three letters.", "It stands for Server Name Indication."]
      }
    ]
  },
  {
    id: "ports-services-firewalls",
    title: "Ports, Services, and Firewalls",
    summary: "Distinguish between listening, reachable, and filtered ports while analyzing local and remote network state.",
    cards: [
      {
        title: "Listening vs. Reachable",
        body: [
          "A service 'listening' on a port (`0.0.0.0:80`) is ready for connections locally. However, a firewall may prevent it from being 'reachable' from the outside.",
          "Use `ss -tulpen` to see local listening sockets. If it's listening on `127.0.0.1`, it's only accessible from the box itself."
        ],
        code: "ss -tulpen",
        tone: "info"
      },
      {
        title: "Probing with Curl & Tcpdump",
        body: [
          "Basic connectivity tests aren't enough. `curl -v` reveals HTTP headers (Server, X-Powered-By) that leak software versions.",
          "For raw analysis, `tcpdump` shows you exactly what packets are hitting your interface. It's the ultimate truth in networking."
        ],
        code: "tcpdump -i eth0 port 80 -n",
        tone: "offense"
      },
      {
        title: "Hunter Reflex: Interpreting the Wall",
        body: [
          "Nmap 'Filtered' means the firewall dropped the packet (no response). 'Closed' means the host sent an RST (port is shut, but host is alive).",
          "Hunters look for 'Open' ports to exploit, but 'Filtered' ports tell you where the most sensitive assets are being hidden."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "order",
        q: "Order the steps to verify if a local service is accessible from the internet.",
        items: [
          "Run 'ss -tulpen' to find the port",
          "Check 'ip addr' for the public interface",
          "Try to connect via 'curl' from a remote machine",
          "Analyze firewall logs if the connection fails"
        ],
        explain: "Check if it's listening, find where it's listening, test externally, then debug the block.",
        hints: ["Verify the local state first.", "Testing from the outside is the final validation."]
      },
      {
        type: "mc",
        q: "In the command 'ss -tulpen', what does the '-l' flag signify?",
        options: ["List all files", "Show only listening sockets", "Log output to a file", "Long format"],
        answer: 1,
        explain: "-l filters for sockets that are currently in the LISTEN state.",
        hints: ["It contrasts with showing established connections.", "Think 'Listen'."]
      },
      {
        type: "match",
        q: "Match the Nmap port state to its meaning.",
        pairs: [
          ["Open", "Accepting connections"],
          ["Closed", "Host replied with RST"],
          ["Filtered", "Packet dropped, no response"],
          ["Unfiltered", "Port is accessible but state unknown"]
        ],
        explain: "Open accepts; Closed rejects actively; Filtered is silent; Unfiltered responds to probes but state is unclear.",
        hints: ["Which one is 'silent'?", "Which one involves a reset (RST) packet?"]
      }
    ]
  }
];
