import type { Unit } from "../types";
import { tcp, udp, dns, icmp, http } from "../pkt";

const unit1: Unit = {
  id: "foundations",
  index: 1,
  title: "Networking Foundations",
  tagline: "The protocols every hacker reads first — and the fields that leak the most.",
  tone: "foundation",
  lessons: [
    {
      id: "layers",
      title: "The layer model",
      summary: "How a message is wrapped on its way out and unwrapped on its way in.",
      cards: [
        {
          title: "Why layers exist",
          body: [
            "A network has to solve several unrelated problems at once: moving electrical signals, finding a machine across the planet, keeping bytes in order, and understanding what those bytes mean.",
            "Instead of one giant protocol, we stack small ones. Each layer only talks to the layer above and below it.",
            "The practical model is the four-layer TCP/IP stack. The seven-layer OSI model is the vocabulary everyone quotes in interviews.",
          ],
          code: `OSI                      TCP/IP            Example
7 Application  ─┐
6 Presentation  ├─ Application      HTTP, DNS, TLS
5 Session      ─┘
4 Transport     ── Transport        TCP, UDP
3 Network       ── Internet         IP, ICMP
2 Data link    ─┐
1 Physical      ┴─ Link             Ethernet, ARP, Wi-Fi`,
        },
        {
          title: "Encapsulation",
          body: [
            "Sending data is a nesting-doll operation. Your HTTP request gets a TCP header, that gets an IP header, that gets an Ethernet header.",
            "Every header is a small fixed set of fields. Every attack is, at heart, an unusual combination of those fields or an unexpected payload inside them.",
          ],
          code: `[ Ethernet | IP | TCP | GET /index.html HTTP/1.1 ]
  dst MAC   src IP  src port   the thing you actually wanted
  src MAC   dst IP  dst port
  type      proto   flags, seq`,
        },
        {
          title: "Where an attacker lives",
          body: [
            "A remote bug-bounty hunter touches layers 3–7: IP, TCP/UDP, TLS, and the application.",
            "A hunter on the same Wi-Fi can also touch layer 2 — ARP spoofing, rogue DHCP, evil-twin APs.",
            "Knowing which layer a bug lives at tells you which tool reaches it. Burp Suite is layer 7. Nmap is layers 3–4. Wireshark reads all seven.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A TCP port number lives in which layer's header?",
          options: ["Link layer", "Internet layer", "Transport layer", "Application layer"],
          answer: 2,
          explain: "Ports are a transport-layer concept. IP addresses machines; ports address services on them.",
        },
        {
          type: "order",
          q: "Put the headers in the order a packet is built, outermost first.",
          items: ["Ethernet header", "IP header", "TCP header", "HTTP payload"],
          explain: "Each layer wraps the one above it, so Ethernet is on the outside and the application data is at the core.",
        },
        {
          type: "match",
          q: "Match each tool to the layer it mostly works at.",
          pairs: [
            ["Burp Suite", "Application"],
            ["Nmap", "Transport"],
            ["Wireshark", "All layers"],
            ["arpspoof", "Link"],
          ],
          explain: "Picking the right layer-tool is 80% of being efficient. A web bug does not need Wireshark.",
        },
      ],
    },
    {
      id: "addressing",
      title: "IP addresses and subnets",
      summary: "Reading CIDR, knowing what is local and what is not — essential for scoping.",
      cards: [
        {
          title: "Dotted quads and masks",
          body: [
            "An IPv4 address is 32 bits written as four bytes. A subnet mask says how many of those leading bits identify the network rather than the host.",
            "10.0.0.5/24 means the first 24 bits (10.0.0) are the network and the last 8 bits (.5) are the host. That network holds 10.0.0.0 to 10.0.0.255.",
          ],
          code: `10.0.0.5/24
 network : 10.0.0.0
 broadcast: 10.0.0.255
 usable  : 10.0.0.1 - 10.0.0.254  (254 hosts)

/16 -> 65 534 hosts    /25 -> 126 hosts
/24 -> 254 hosts       /30 -> 2 hosts (point-to-point links)`,
        },
        {
          title: "Why scoping lives here",
          body: [
            "Every bug bounty program names an IP range or domain list that is in-scope. Testing outside it is unauthorised access — a crime, not a bug.",
            "If the scope is `*.example.com and 203.0.113.0/24`, you'd better be able to read '203.0.113.42 is inside that /24' at a glance.",
          ],
          tone: "offense",
        },
        {
          title: "Private ranges",
          body: [
            "RFC1918 reserves three ranges that never appear on the public internet: 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.",
            "Seeing one of these in a bug-bounty response can be gold: an app leaking an internal IP has usually leaked something more interesting — an SSRF target, an internal API, a staging host.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Is 10.0.0.200 inside 10.0.0.0/24?",
          options: ["Yes", "No, it is in a different /24", "Only if the gateway allows it", "Cannot tell without the MAC"],
          answer: 0,
          explain: "A /24 covers .0 through .255 of that third octet, so .200 is inside.",
        },
        {
          type: "fill",
          q: "How many usable host addresses does a /26 network have?",
          answers: ["62"],
          explain: "/26 leaves 6 host bits = 64 addresses, minus the network and broadcast address = 62.",
        },
        {
          type: "mc",
          q: "A bug-bounty program's scope reads `*.shop.example and 198.51.100.0/24`. You discover the host api.staging.shop.example resolves to 192.0.2.17. Can you test it?",
          options: [
            "Yes, the subdomain matches *.shop.example",
            "No, the IP is outside 198.51.100.0/24 so the scope rules exclude it",
            "Only on weekends",
            "Only with permission from the ISP",
          ],
          answer: 0,
          explain:
            "Scope rules are usually read as OR across lines: match EITHER the wildcard subdomain OR the IP range. The subdomain match is enough. Always re-read the exact wording per program.",
        },
      ],
    },
    {
      id: "tcp-udp",
      title: "TCP, UDP and the handshake",
      summary: "Flags, sequence numbers, and why 'closed' is useful information.",
      cards: [
        {
          title: "Two transports, two philosophies",
          body: [
            "TCP is a conversation: it sets up a connection, numbers every byte, retransmits what gets lost, and tears down cleanly.",
            "UDP is a postcard: one datagram, no setup, no guarantee. DNS, QUIC, VoIP and most flood attacks live here.",
          ],
          code: `TCP header flags
  S (SYN)  start a connection
  A (ACK)  acknowledging data
  F (FIN)  polite close
  R (RST)  abrupt refusal / reset
  P (PSH)  deliver this to the app now
  U (URG)  urgent pointer valid`,
        },
        {
          title: "The three-way handshake",
          body: [
            "Every TCP connection opens the same way, and almost every scanning technique is a deliberate deviation from it.",
          ],
          code: `client            server
   | ---- SYN ------->|   "can we talk? my seq = x"
   | <-- SYN,ACK -----|   "yes, my seq = y, ack = x+1"
   | ---- ACK ------->|   "confirmed"
   |   established    |`,
        },
        {
          title: "What silence vs reset tells an attacker",
          body: [
            "SYN-ACK back → the port is OPEN. Interesting.",
            "RST back → the port is CLOSED but the host exists. Still interesting.",
            "No reply at all → FILTERED by a firewall. Different kind of interesting.",
            "Three different answers from three different packets, and nothing had to log in. That is why scanning works.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "order",
          q: "Order the three-way handshake.",
          items: ["Client sends SYN", "Server replies SYN,ACK", "Client sends ACK"],
          explain: "SYN, SYN-ACK, ACK. Memorise it; half of network attacks are shaped around skipping or breaking a step.",
        },
        {
          type: "mc",
          q: "A host replies RST to your SYN. What do you learn?",
          options: ["The port is open", "The port is closed but the host is up", "The host is down", "A firewall dropped the packet"],
          answer: 1,
          explain: "A reset means nothing is listening on that port. Silence (no reply) is what usually indicates a filtering firewall.",
        },
        {
          type: "fill",
          q: "Which single TCP flag letter marks the very first packet of a connection?",
          answers: ["S", "SYN"],
          explain: "SYN — synchronise sequence numbers.",
        },
      ],
    },
    {
      id: "dns-http",
      title: "DNS and HTTP in the wild",
      summary: "The two protocols you will exploit most often.",
      cards: [
        {
          title: "DNS: the attacker's map",
          body: [
            "Before you can attack anything you need to know its address, and DNS is how you find it. Before almost any user action there is a DNS lookup.",
            "A query is normally UDP port 53. TCP 53 is used for large answers and (historically) zone transfers — a misconfiguration that still works surprisingly often on obscure hosts.",
          ],
          code: `$ dig +short shop.example
93.184.216.34

$ dig AXFR @ns1.old-vendor.net example.com   # zone transfer attempt
; often blocked; on a bad config, dumps every subdomain.

$ dig +short txt example.com                 # TXT records leak more than people think:
"v=spf1 include:_spf.google.com include:mail.staging-corp.net ~all"`,
        },
        {
          title: "HTTP: plain text you can modify",
          body: [
            "An HTTP request is literally editable text. Any field — method, path, query string, headers, body, cookies — is attacker-controlled on the wire.",
            "A hunter's instinct: tamper every parameter, change the method, flip a '1' to '2', double every character, inject a quote, strip a cookie.",
          ],
          code: `GET /account?id=42 HTTP/1.1
Host: shop.example
Cookie: session=abc123
User-Agent: Mozilla/5.0

↓ tamper every piece ↓

PUT /account?id=43 HTTP/1.1
Host: shop.example
Cookie: session=abc123
X-Original-URL: /admin

?id=43'  ?id=42+UNION+SELECT+1--  ?id=../../etc/passwd`,
          tone: "offense",
        },
        {
          title: "Status codes you want to see",
          body: [
            "200 OK with content you shouldn't be seeing → the actual vulnerability.",
            "302 Found redirecting you away from an admin page → look at where it redirects. The response body often leaks the page anyway.",
            "500 Internal Server Error with a stack trace → version info, framework, maybe a SQL fragment. Chef's kiss.",
            "403 Forbidden on /admin but 200 on /ADMIN or /admin/ or /admin;jsessionid=x → access-control bypasses are often one byte away.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You see `/admin` returns 403 and `/admin/` returns 200. What does that most likely indicate?",
          options: [
            "Just a URL alias — same page",
            "An access-control rule that only matched the exact string `/admin`, bypassed by a trailing slash",
            "A DNS problem",
            "A TLS mismatch",
          ],
          answer: 1,
          explain: "This is a textbook authorisation bypass. Many frameworks route both forms to the same handler but check ACLs with string equality.",
        },
        {
          type: "mc",
          exhibit:
            "HTTP/1.1 500 Internal Server Error\nX-Powered-By: PHP/5.6.40\n\n...\nFile: /var/www/html/pay.php on line 72\nQuery: SELECT * FROM users WHERE email='x\\'' AND status=1",
          q: "Which single detail is the strongest lead?",
          options: [
            "The 500 status",
            "The disclosed PHP version AND the SQL fragment, together revealing an unescaped quote",
            "The Host header",
            "Nothing — this is normal",
          ],
          answer: 1,
          explain:
            "500 + stack trace + raw SQL = version info, a confirmed injection point, and a known-EOL interpreter. Three findings in one error page.",
        },
        {
          type: "fill",
          q: "Name the HTTP header that tells a server which site a request is for.",
          answers: ["host", "host header"],
          explain: "The Host header. It is also how one IP can serve many sites — and tampering it is the basis of host-header injection and virtual-host confusion.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-recon-basics",
    title: "Lab: read your first capture",
    tone: "defense",
    briefing: [
      "A capture from a small office network, 10.0.0.0/24, has been loaded.",
      "Learning to read raw traffic is where every network hacker starts — Wireshark, Burp Suite, mitmproxy, all of them show you the same thing: fields and bytes.",
      "Click any packet to see decoded headers and payload. Use the terminal to run a few sensor commands.",
    ],
    terminal: {
      host: "analyst@sensor",
      commands: {
        "ip addr":
          "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.9/24 brd 10.0.0.255 scope global eth0",
        "ping 10.0.0.1":
          "PING 10.0.0.1 56(84) bytes of data.\n64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.41 ms\n64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.38 ms\n--- 10.0.0.1 ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss",
        "dig shop.local":
          ";; ANSWER SECTION:\nshop.local.   300  IN  A  10.0.0.20\n\n;; SERVER: 10.0.0.1#53(10.0.0.1)",
        "tcpdump -n -c 5":
          "listening on eth0\n12:00:01 IP 10.0.0.12.49722 > 10.0.0.20.80: Flags [S], seq 1\n12:00:01 IP 10.0.0.20.80 > 10.0.0.12.49722: Flags [S.], seq 9\n12:00:01 IP 10.0.0.12.49722 > 10.0.0.20.80: Flags [.], ack 10\n12:00:01 IP 10.0.0.12.49722 > 10.0.0.20.80: Flags [P.], length 86\n12:00:02 IP 10.0.0.20.80 > 10.0.0.12.49722: Flags [.], ack 87",
        "netstat -tn":
          "Proto Recv-Q Send-Q Local Address        Foreign Address      State\ntcp        0      0 10.0.0.9:22          10.0.0.12:51233      ESTABLISHED",
      },
      hints: ["ip addr", "ping 10.0.0.1", "dig shop.local", "tcpdump -n -c 5", "netstat -tn"],
    },
    packets: [
      dns(0.2, "10.0.0.12", "10.0.0.1", "shop.local"),
      udp(0.3, "10.0.0.1", 53, "10.0.0.12", 53122, { payload: "RESPONSE A shop.local 10.0.0.20", info: "Standard query response A 10.0.0.20" }),
      tcp(0.5, "10.0.0.12", 49722, "10.0.0.20", 80, "S"),
      tcp(0.51, "10.0.0.20", 80, "10.0.0.12", 49722, "SA"),
      tcp(0.52, "10.0.0.12", 49722, "10.0.0.20", 80, "A"),
      http(0.6, "10.0.0.12", "10.0.0.20", "GET /index.html HTTP/1.1\nHost: shop.local", { sport: 49722 }),
      tcp(0.9, "10.0.0.20", 80, "10.0.0.12", 49722, "PA", { payload: "HTTP/1.1 200 OK\nContent-Type: text/html" }),
      icmp(2.0, "10.0.0.9", "10.0.0.1", 8),
      icmp(2.01, "10.0.0.1", "10.0.0.9", 0),
      tcp(3.0, "10.0.0.12", 49723, "10.0.0.20", 443, "S"),
      tcp(3.01, "10.0.0.20", 443, "10.0.0.12", 49723, "SA"),
      tcp(3.02, "10.0.0.12", 49723, "10.0.0.20", 443, "A"),
      tcp(4.0, "10.0.0.12", 49724, "10.0.0.20", 8080, "S"),
      tcp(4.01, "10.0.0.20", 8080, "10.0.0.12", 49724, "R"),
    ],
    tasks: [
      {
        q: "Which IP is the DNS server on this network?",
        answers: ["10.0.0.1"],
        hint: "Look for the destination of the query on port 53.",
      },
      {
        q: "Which port did 10.0.0.12 find CLOSED on the server?",
        answers: ["8080"],
        hint: "A closed port answers with an R (RST) flag.",
      },
      {
        q: "Run the right command in the terminal: what is the sensor's own IP address?",
        answers: ["10.0.0.9", "10.0.0.9/24"],
        hint: "Try `ip addr`.",
      },
    ],
  },
  ids: {
    name: "Protocol literacy",
    description:
      "You can read IP/TCP/UDP headers, understand the handshake, and spot normal vs abnormal traffic. Every tool past this point assumes it.",
    rules: [],
  },
};

export default unit1;
