import type { Unit } from "../types";
import { tcp, udp, dns, icmp, http } from "../pkt";

const unit1: Unit = {
  id: "foundations",
  index: 1,
  title: "Networking Foundations",
  tagline: "Addresses, layers and the handshake everything is built on.",
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
            "Every header is a small fixed set of fields. An intrusion detection system is, at heart, a program that reads those fields and decides whether the combination looks hostile.",
          ],
          code: `[ Ethernet | IP | TCP | GET /index.html HTTP/1.1 ]
  dst MAC   src IP  src port   the thing you actually wanted
  src MAC   dst IP  dst port
  type      proto   flags, seq`,
        },
        {
          title: "Where a defender sits",
          body: [
            "A network IDS taps the wire and sees layers 2-7 for every packet. A host IDS sees one machine's behaviour in detail.",
            "Everything you build in this course is a network IDS: it will read the headers above and raise alerts.",
          ],
          tone: "defense",
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
          q: "Match each protocol to its layer.",
          pairs: [
            ["ARP", "Link"],
            ["IP", "Internet"],
            ["UDP", "Transport"],
            ["DNS", "Application"],
          ],
          explain: "ARP maps IP to MAC on the local segment, so it sits at the link layer even though it mentions IP addresses.",
        },
      ],
    },
    {
      id: "addressing",
      title: "IP addresses and subnets",
      summary: "Reading CIDR, knowing what is local and what is not.",
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
          title: "HOME_NET",
          body: [
            "Detection rules almost always start by splitting the world into 'us' and 'them'. In Snort and Suricata that is the $HOME_NET and $EXTERNAL_NET variables.",
            "Getting HOME_NET wrong is the single most common reason a rule set is silently useless: if your own network is not listed, inbound-only rules never fire.",
            "Throughout this course HOME_NET is 10.0.0.0/24.",
          ],
          tone: "defense",
        },
        {
          title: "Private ranges",
          body: [
            "RFC1918 reserves three ranges that never appear on the public internet: 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.",
            "Seeing a private source address arrive from the internet-facing interface is itself an alert — somebody is spoofing.",
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
          q: "A packet arrives on your internet uplink with source 192.168.1.40. What is the correct reading?",
          options: [
            "Normal traffic from a home user",
            "Spoofed source address — private ranges are not routable on the internet",
            "A DNS response",
            "An ARP broadcast",
          ],
          answer: 1,
          explain: "RFC1918 addresses are never routed publicly, so an inbound packet claiming one has a forged source.",
        },
      ],
    },
    {
      id: "tcp-udp",
      title: "TCP, UDP and the handshake",
      summary: "Flags, sequence numbers, and why half-open connections matter.",
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
            "Every TCP connection opens the same way, and almost every scanning and flooding technique is a deliberate deviation from it.",
          ],
          code: `client            server
   | ---- SYN ------->|   "can we talk? my seq = x"
   | <-- SYN,ACK -----|   "yes, my seq = y, ack = x+1"
   | ---- ACK ------->|   "confirmed"
   |   established    |`,
        },
        {
          title: "Deviations are signal",
          body: [
            "SYN with no follow-up ACK: a half-open scan, or a SYN flood.",
            "SYN,ACK arriving at a host that sent no SYN: backscatter from a spoofed attack elsewhere.",
            "RST straight back: the port is closed — exactly what a scanner wants to learn.",
            "No flags at all, or FIN+PSH+URG together: a crafted 'null' or 'Xmas' scan, since no real stack sends those.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "order",
          q: "Order the three-way handshake.",
          items: ["Client sends SYN", "Server replies SYN,ACK", "Client sends ACK"],
          explain: "SYN, SYN-ACK, ACK. Memorise it; half of network detection is noticing when it does not complete.",
        },
        {
          type: "mc",
          q: "A host receives SYN and answers RST. What does the sender learn?",
          options: ["The port is open", "The port is closed", "The host is down", "A firewall dropped it"],
          answer: 1,
          explain: "A reset means nothing is listening. Silence (no reply) is what usually indicates a filtering firewall.",
        },
        {
          type: "fill",
          q: "Which single TCP flag letter marks the very first packet of a connection?",
          answers: ["S", "SYN"],
          explain: "SYN — synchronise sequence numbers.",
        },
        {
          type: "mc",
          q: "Why do attackers like UDP for floods?",
          options: [
            "UDP packets are larger",
            "No handshake is required, so the source can be forged freely",
            "UDP is encrypted",
            "Firewalls cannot see UDP",
          ],
          answer: 1,
          explain: "With no handshake there is nothing to complete, so spoofed sources work and reflection/amplification becomes possible.",
        },
      ],
    },
    {
      id: "dns-http",
      title: "DNS and HTTP in the wild",
      summary: "The two protocols you will read most often in a capture.",
      cards: [
        {
          title: "DNS: the network's phone book",
          body: [
            "Before almost any connection there is a DNS lookup. That makes DNS logs the richest early-warning source a defender has.",
            "A query is normally UDP port 53. TCP 53 is used for large answers and zone transfers.",
          ],
          code: `10.0.0.12:53122 -> 10.0.0.1:53   QUERY  A  shop.example.com
10.0.0.1:53     -> 10.0.0.12:53122 RESPONSE A 93.184.216.34  TTL 300`,
        },
        {
          title: "HTTP: plain text you can grep",
          body: [
            "An unencrypted HTTP request is literally readable ASCII, which is why signature rules for web attacks are so effective on it.",
            "With HTTPS the body is encrypted — detection then relies on metadata: SNI, certificate details, timing, volumes.",
          ],
          code: `GET /login?user=admin HTTP/1.1
Host: shop.local
User-Agent: Mozilla/5.0
Cookie: session=abc123`,
        },
        {
          title: "Suspicious shapes to remember",
          body: [
            "Very long random subdomains repeated to one nameserver: DNS tunnelling or algorithm-generated domains.",
            "A User-Agent of 'sqlmap' or 'nmap' — attackers often forget to change it.",
            "Hundreds of requests per second from one client to one login URL: brute force.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Which transport and port does an ordinary DNS query use?",
          options: ["TCP 53", "UDP 53", "UDP 67", "TCP 853"],
          answer: 1,
          explain: "UDP 53 for normal queries; TCP 53 for oversized answers and zone transfers.",
        },
        {
          type: "mc",
          exhibit: "GET /?q=' OR 1=1-- HTTP/1.1\nHost: shop.local\nUser-Agent: sqlmap/1.7",
          q: "Which single field in this request is the strongest detection opportunity?",
          options: ["Host header", "The HTTP version", "User-Agent: sqlmap/1.7", "The GET method"],
          answer: 2,
          explain: "A self-identifying attack tool in the User-Agent is a one-line, near-zero-false-positive signature.",
        },
        {
          type: "fill",
          q: "Name the HTTP header that tells a server which site a request is for.",
          answers: ["host", "host header"],
          explain: "The Host header. It is also how one IP can serve many sites.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-recon-basics",
    title: "Lab: read your first capture",
    tone: "defense",
    briefing: [
      "You are sitting on the span port of a small office network, 10.0.0.0/24.",
      "A capture of 60 seconds has been loaded. Use the packet viewer to answer the questions, then try the terminal.",
      "Click any packet to see its decoded headers.",
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
    name: "Packet model",
    description:
      "Your IDS can now represent a packet: addresses, ports, protocol, flags and payload. Everything else plugs into this.",
    rules: [],
  },
};

export default unit1;
