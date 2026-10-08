import type { Unit } from "../types";
import { tcp, udp, dns, http, icmp } from "../pkt";

const unit2: Unit = {
  id: "packets",
  index: 2,
  title: "Packet Analysis",
  tagline: "Capture, filter and read traffic byte by byte.",
  tone: "foundation",
  lessons: [
    {
      id: "capture",
      title: "How capture works",
      summary: "Taps, SPAN ports, promiscuous mode and where your sensor should live.",
      cards: [
        {
          title: "Getting a copy of the traffic",
          body: [
            "A switch normally only sends you frames addressed to you. To monitor a network you need a deliberate copy.",
            "A SPAN/mirror port tells the switch to duplicate traffic to your sensor. A network TAP is a physical device that does the same without relying on switch CPU.",
            "Your interface must be in promiscuous mode or it will discard frames not addressed to its MAC.",
          ],
          code: `tcpdump -i eth0 -n -s 0 -w capture.pcap
  -i  interface
  -n  do not resolve names (faster, no DNS noise)
  -s0 full packet, no truncation
  -w  write raw pcap for later analysis`,
        },
        {
          title: "Placement decides what you can see",
          body: [
            "In front of the firewall you see every attack attempt, including the ones the firewall blocks — noisy, but great for threat intel.",
            "Behind the firewall you only see what got through — far fewer alerts and every one matters more.",
            "Inside a segment you can see lateral movement, which perimeter sensors are completely blind to.",
          ],
          tone: "defense",
        },
        {
          title: "Capture filters vs display filters",
          body: [
            "A capture filter (BPF) decides what is written to disk. You cannot get that data back later, so be conservative.",
            "A display filter decides what you look at right now and is freely reversible.",
          ],
          code: `BPF capture filter:      tcp port 80 and host 10.0.0.20
Wireshark display filter: http.request.method == "POST"`,
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Your sensor is connected to a plain switch port with no mirroring. What do you see?",
          options: [
            "All traffic on the network",
            "Only broadcast/multicast traffic and traffic addressed to the sensor",
            "Nothing at all",
            "Only TCP traffic",
          ],
          answer: 1,
          explain: "Switches forward unicast only to the right port. Without a SPAN port or TAP, you see broadcasts and your own traffic.",
        },
        {
          type: "mc",
          q: "Which choice is irreversible?",
          options: ["A display filter", "A capture filter", "Sorting by time", "Colouring rules"],
          answer: 1,
          explain: "Packets excluded by the capture filter are never written, so that decision cannot be undone later.",
        },
        {
          type: "fill",
          q: "Which tcpdump flag writes raw packets to a file?",
          answers: ["-w"],
          explain: "-w file.pcap. Use -r to read one back.",
        },
      ],
    },
    {
      id: "headers",
      title: "Reading headers",
      summary: "The fields that matter in IP and TCP, and what they leak.",
      cards: [
        {
          title: "The IP header fields you will use",
          body: [
            "Version/IHL, Total Length, Identification, Flags/Fragment offset, TTL, Protocol, Checksum, Source, Destination.",
            "TTL is unexpectedly useful: operating systems start at different values (Linux 64, Windows 128, many network devices 255). A TTL of 57 arriving from far away probably started at 64.",
          ],
          code: ` 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------+-------+---------------+-------------------------------+
|Version|  IHL  |      TOS      |          Total Length         |
+-------+-------+---------------+-----+-------------------------+
|         Identification        |Flags|      Fragment Offset    |
+---------------+---------------+-----+-------------------------+
|      TTL      |    Protocol   |         Header Checksum       |
+---------------+---------------+-------------------------------+
|                       Source Address                          |
+---------------------------------------------------------------+
|                    Destination Address                        |
+---------------------------------------------------------------+`,
        },
        {
          title: "The TCP header",
          body: [
            "Source port, destination port, sequence number, acknowledgement number, data offset, flags, window, checksum, urgent pointer.",
            "Window size and options fingerprint the sending OS — the same trick nmap uses, in reverse, for passive defence.",
          ],
        },
        {
          title: "Fragments: an evasion classic",
          body: [
            "IP can split a packet into fragments. An IDS that inspects each fragment separately will never see a signature that spans the split.",
            "The counter is reassembly: a real IDS rebuilds the full datagram before matching. Overlapping fragments with conflicting data are themselves an alert.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You see an inbound packet with TTL 119. What is the likely sending OS family?",
          options: ["Linux (starts at 64)", "Windows (starts at 128)", "Cisco IOS (starts at 255)", "Impossible to guess"],
          answer: 1,
          explain: "119 is 128 minus 9 hops. Linux would have had to pass through a negative number of hops to reach 119 from 64.",
        },
        {
          type: "match",
          q: "Match each header field to what it tells a defender.",
          pairs: [
            ["TTL", "Rough hop count and OS family"],
            ["TCP window size", "OS/stack fingerprint"],
            ["Fragment offset", "Possible evasion attempt"],
            ["Protocol field", "Which transport follows"],
          ],
          explain: "Fingerprinting and evasion detection both come from fields that have nothing to do with the payload.",
        },
        {
          type: "mc",
          q: "Why do attackers fragment attack payloads?",
          options: [
            "It makes them faster",
            "A signature split across fragments may not match if the IDS does not reassemble",
            "Fragments are encrypted",
            "Firewalls always allow fragments",
          ],
          answer: 1,
          explain: "Evasion through fragmentation is defeated by stream reassembly before matching.",
        },
      ],
    },
    {
      id: "filters",
      title: "Filtering like an analyst",
      summary: "BPF and display filter syntax that gets you to the interesting packets.",
      cards: [
        {
          title: "BPF essentials",
          body: ["Primitives combine with and / or / not. These five cover most of daily work."],
          code: `host 10.0.0.20              traffic to or from a host
net 10.0.0.0/24             a whole subnet
port 443                    either direction
src host 10.0.0.12 and dst port 22
tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0
   ^ SYN without ACK: connection attempts only`,
        },
        {
          title: "Display filters",
          body: ["Wireshark's language is field-based and far richer, because the packet is already dissected."],
          code: `http.request.uri contains "admin"
dns.qry.name matches "[a-z0-9]{25,}"
tcp.flags.syn == 1 && tcp.flags.ack == 0
ip.src == 10.0.0.12 && frame.len > 1400`,
        },
        {
          title: "The analyst loop",
          body: [
            "Filter wide, spot an anomaly, filter narrow around it, follow the stream, then write a rule so the machine finds it next time.",
            "That last step is the whole point of this course.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Write the BPF filter for all traffic involving the subnet 10.0.0.0/24.",
          answers: ["net 10.0.0.0/24", "net 10.0.0.0/24 "],
          explain: "`net 10.0.0.0/24` — use `src net` or `dst net` to pick a direction.",
        },
        {
          type: "mc",
          q: "Which filter isolates connection attempts only?",
          options: ["tcp port 80", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "ip.ttl < 64", "udp"],
          answer: 1,
          explain: "A bare SYN is the opening packet; adding ACK would include the server's reply.",
        },
      ],
    },
    {
      id: "streams",
      title: "Following a stream",
      summary: "Turning scattered packets back into a conversation.",
      cards: [
        {
          title: "A flow is five fields",
          body: [
            "Source IP, source port, destination IP, destination port, protocol. That five-tuple identifies one conversation.",
            "Flow records (NetFlow/IPFIX) keep only those plus counters and timings. No payload, tiny storage, and still enough to spot scans, beacons and exfiltration.",
          ],
          code: `5-tuple:  10.0.0.12:49722 -> 10.0.0.20:80  TCP
flow record: 14 packets, 8 212 bytes, 2.1 s, flags SAPF`,
        },
        {
          title: "Reassembly",
          body: [
            "TCP delivers bytes, not messages. A single HTTP request can arrive in three segments and a single segment can carry two requests.",
            "Your IDS must reassemble the byte stream before content matching, or an attacker simply splits the word 'UNION' across two packets.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "order",
          q: "Order the steps of analysing an alert.",
          items: [
            "Filter to the alerting five-tuple",
            "Follow the TCP stream to read the full conversation",
            "Decide benign or malicious",
            "Write or tune a rule",
          ],
          explain: "Always end by improving detection — otherwise you will do the same manual work again next week.",
        },
        {
          type: "fill",
          q: "How many fields make up the classic flow five-tuple?",
          answers: ["5", "five"],
          explain: "src IP, src port, dst IP, dst port, protocol.",
        },
        {
          type: "mc",
          q: "Why is content matching on individual packets unsafe?",
          options: [
            "Packets are encrypted",
            "An attacker can split a keyword across two segments so no single packet contains it",
            "Packets arrive out of order only on UDP",
            "It is too fast",
          ],
          answer: 1,
          explain: "Stream reassembly before matching is what defeats segmentation evasion.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-packet-reading",
    title: "Lab: decode the capture",
    tone: "defense",
    briefing: [
      "A workstation on 10.0.0.0/24 behaved oddly last night. Here are 20 packets from that window.",
      "Use the packet viewer: click rows, read the header breakdown and the payload pane.",
      "One client is doing something it should not. Find it.",
    ],
    packets: [
      dns(0.1, "10.0.0.33", "10.0.0.1", "updates.vendor.com"),
      udp(0.2, "10.0.0.1", 53, "10.0.0.33", 53311, { payload: "RESPONSE A 203.0.113.10", info: "Standard query response" }),
      tcp(0.4, "10.0.0.33", 51000, "203.0.113.10", 443, "S"),
      tcp(0.41, "203.0.113.10", 443, "10.0.0.33", 51000, "SA", { ttl: 119 }),
      tcp(0.42, "10.0.0.33", 51000, "203.0.113.10", 443, "A"),
      http(1.0, "10.0.0.12", "10.0.0.20", "GET /products HTTP/1.1\nHost: shop.local\nUser-Agent: Mozilla/5.0"),
      tcp(1.2, "10.0.0.20", 80, "10.0.0.12", 49100, "PA", { payload: "HTTP/1.1 200 OK\nContent-Length: 4120" }),
      dns(2.0, "10.0.0.44", "10.0.0.1", "a7f3k2m9x1qp8zd4nv6.exfil-node.net", {
        label: "dns-tunnel",
      }),
      dns(2.4, "10.0.0.44", "10.0.0.1", "b2c8y5w3r0ts7ln1he9.exfil-node.net", { label: "dns-tunnel" }),
      dns(2.9, "10.0.0.44", "10.0.0.1", "k9m4p2v7xz3qb8ld0fa.exfil-node.net", { label: "dns-tunnel" }),
      dns(3.3, "10.0.0.44", "10.0.0.1", "t5n1j8h6gd2ws4ye7uq.exfil-node.net", { label: "dns-tunnel" }),
      icmp(4.0, "10.0.0.12", "10.0.0.1", 8),
      icmp(4.01, "10.0.0.1", "10.0.0.12", 0),
      tcp(5.0, "10.0.0.12", 49120, "10.0.0.20", 22, "S"),
      tcp(5.01, "10.0.0.20", 22, "10.0.0.12", 49120, "SA"),
      tcp(5.02, "10.0.0.12", 49120, "10.0.0.20", 22, "A"),
      http(6.0, "10.0.0.12", "10.0.0.20", "POST /cart HTTP/1.1\nHost: shop.local\nContent-Length: 42"),
      dns(7.0, "10.0.0.44", "10.0.0.1", "w3e9r1t5y7u2i4o6p8a.exfil-node.net", { label: "dns-tunnel" }),
      tcp(8.0, "10.0.0.33", 51000, "203.0.113.10", 443, "PA", { payload: "<TLS application data>" }),
      tcp(9.0, "10.0.0.33", 51000, "203.0.113.10", 443, "FA"),
    ],
    tasks: [
      {
        q: "Which internal IP is sending long random subdomain lookups?",
        answers: ["10.0.0.44"],
        hint: "Sort by protocol and look at the DNS query names.",
      },
      {
        q: "What is the attacker's domain (the part after the random label)?",
        answers: ["exfil-node.net"],
        hint: "All five suspicious queries share a parent domain.",
      },
      {
        q: "The SYN,ACK from 203.0.113.10 has TTL 119. Which OS family is that host likely running?",
        answers: ["windows"],
        hint: "128 minus a handful of hops.",
      },
      {
        q: "Which technique is 10.0.0.44 using? (two words, hyphen or space)",
        answers: ["dns tunneling", "dns tunnelling", "dns-tunneling", "dns exfiltration"],
        hint: "Data is being encoded into the hostname itself.",
      },
    ],
  },
  ids: {
    name: "Packet parser",
    description:
      "Your IDS now decodes IP/TCP/UDP headers and reassembles payloads, so later modules can match on real content.",
    rules: [],
  },
};

export default unit2;
