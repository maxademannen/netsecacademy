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
      summary: "How a message is wrapped, routed hop-by-hop, and unwrapped on arrival.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you will be able to: name the layer a given header/field belongs to, explain encapsulation (why a packet is 'headers wrapped around headers'), and explain how a router moves a packet one hop closer to its destination using the destination IP address.",
          ],
        },
        {
          title: "The problem layers solve",
          kind: "intuition",
          body: [
            "Imagine you had to ship a letter, but the postal service, the delivery truck, the sorting warehouse and the actual reader of the letter all had to be re-designed every time the message format changed. That is what networking would look like without layers.",
            "A network has to solve several independent problems at once: how to move electrical/radio signals between two directly connected machines, how to find a machine anywhere on the planet, how to make sure bytes arrive in order and undamaged, and how to make sense of what those bytes mean (a webpage? an email?).",
            "Instead of one giant protocol that does everything, engineers stacked several small, focused protocols. Each layer only has to talk to the layer directly above and below it — like each worker in the postal service only needing to understand their own job.",
            "Where the analogy breaks: a real letter is only wrapped once (an envelope). A network message is wrapped *and unwrapped again at every hop* along the path, as you will see in the routing card below.",
          ],
        },
        {
          title: "The four/seven-layer stack",
          kind: "explain",
          body: [
            "The practical model used day to day is the four-layer TCP/IP stack. The seven-layer OSI model is the vocabulary everyone quotes in interviews and documentation — they describe the same reality at different granularity.",
            "Link layer: moves bits between two machines on the same physical/local segment (Ethernet, Wi-Fi). Internet layer: finds a path between two machines anywhere, using IP addresses. Transport layer: delivers data to the right *application* on a machine, using port numbers, and optionally guarantees ordering/delivery (TCP) or does not (UDP). Application layer: the actual meaning of the data — a web page, a DNS answer, an email.",
          ],
          code: `OSI                      TCP/IP            Example
7 Application  ─┐
6 Presentation  ├─ Application      HTTP, DNS, TLS
5 Session      ─┘
4 Transport     ── Transport        TCP, UDP
3 Network       ── Internet         IP, ICMP
2 Data link    ─┐
1 Physical      ┴─ Link             Ethernet, ARP, Wi-Fi`,
          check: {
            type: "mc",
            q: "A TCP port number lives in which layer's header?",
            options: ["Link layer", "Internet layer", "Transport layer", "Application layer"],
            answer: 2,
            why: [
              "The link layer deals with MAC addresses on a local segment, not ports.",
              "The internet layer (IP) addresses machines, not the services running on them.",
              "",
              "The application layer is the data itself (e.g. an HTTP request); the port number that routes it to the right program is added by the transport layer.",
            ],
            explain: "Ports are a transport-layer concept. IP addresses machines; ports address services running on a machine.",
            hints: ["Which layer adds the header that contains sport/dport fields?"],
          },
        },
        {
          title: "Encapsulation",
          kind: "explain",
          body: [
            "Sending data is a nesting-doll operation. Your HTTP request gets a TCP header put in front of it (now it's a TCP segment), that gets an IP header put in front of it (now it's an IP packet), and that gets an Ethernet header and trailer put around it (now it's an Ethernet frame) before it goes out on the wire.",
            "Each header is a small, fixed set of fields — source/destination addresses, flags, lengths, checksums. A huge share of real attacks are, at their core, an unusual combination of those fields, or an unexpected payload riding inside them (e.g. a crafted HTTP body, or a TCP flag combination no normal stack sends).",
            "On arrival, the receiving machine does the reverse: strip the Ethernet header, read the IP header to see if the packet is for this machine, strip it, read the TCP header to find which application is listening on that port, strip it, and hand the remaining bytes to that application.",
          ],
          code: `[ Ethernet | IP | TCP | GET /index.html HTTP/1.1 ]
  dst MAC   src IP  src port   the thing you actually wanted
  src MAC   dst IP  dst port
  type      proto   flags, seq`,
        },
        {
          title: "Routing: how a packet finds its way",
          kind: "explain",
          body: [
            "Encapsulation explains how one packet is built. Routing explains how it actually *travels* from your laptop to a server possibly thousands of kilometres away, through machines neither you nor the server own.",
            "Every IP-capable device keeps a routing table: a list of 'to reach this network, send it to this next-hop'. Your laptop's simplest rule is usually 'if the destination isn't on my local network, send it to my default gateway' — normally your home router or office router.",
            "Each router that receives the packet looks only at the destination IP address, finds the best-matching entry in its own routing table, and forwards the packet one hop closer. No single router needs to know the entire path — just the next hop. This is why the system scales to the whole internet.",
            "Every IP header carries a TTL (Time To Live) field, a hop counter that starts at some value (e.g. 64) and is decremented by one at every router. If it hits zero, the packet is dropped and an ICMP 'Time Exceeded' message is sent back. The `traceroute`/`tracert` tool exploits exactly this: it sends packets with TTL=1, 2, 3... and records who replies at each hop, mapping the path.",
          ],
          code: `$ traceroute shop.example
 1  10.0.0.1 (home-router)        1.1 ms
 2  100.72.4.1 (isp-edge)         9.4 ms
 3  203.0.113.254 (isp-core)     14.2 ms
 4  198.51.100.9 (hosting-edge)  22.8 ms
 5  198.51.100.50 (shop.example) 23.1 ms`,
          check: {
            type: "fill",
            q: "Name the IP header field that a traceroute abuses (by sending packets with increasing small values of it) to discover each router along a path.",
            answers: ["ttl", "time to live"],
            explain: "TTL (Time To Live). Each router decrements it by one; when it hits 0 the router discards the packet and replies with an ICMP Time Exceeded message, revealing itself.",
            hints: ["It is also the field that stops a mis-routed packet from looping forever."],
          },
        },
        {
          title: "Worked example: one HTTP request, three hops",
          kind: "example",
          body: [
            "Scenario: your laptop (10.0.0.12) requests http://shop.example, which resolves to 198.51.100.50, reached via your home router (10.0.0.1) and one ISP router (203.0.113.254).",
            "Step 1 — Application layer: your browser builds the text `GET / HTTP/1.1\\r\\nHost: shop.example`.",
            "Step 2 — Transport layer: the OS wraps it in a TCP segment with source port e.g. 51200 and destination port 80 (the well-known HTTP port), after completing a handshake (next lesson).",
            "Step 3 — Internet layer: IP wraps that in a packet with src 10.0.0.12, dst 198.51.100.50, TTL=64.",
            "Step 4 — Link layer: since 198.51.100.50 is not on the local network, the packet's Ethernet frame is addressed to the *router's* MAC address (not the server's) — the IP destination stays the server, but the link-layer destination is only the next hop.",
            "Step 5 — at the home router: it strips the Ethernet frame, reads the IP header, decrements TTL to 63, looks up its routing table, and re-wraps the packet in a new Ethernet (or ISP-link) frame addressed to the next hop. It never touches the TCP/HTTP contents.",
            "Step 6 — this repeats at the ISP router (TTL becomes 62) until the packet reaches 198.51.100.50, which recognises the destination IP as its own, strips every header down to the HTTP request, and hands it to the web server process listening on port 80.",
            "Why it matters: notice each router only ever reads the IP header to decide where next — it is not reading your HTTP request. That is also why TLS (later lesson) only needs to hide the *application data*, not the routing information.",
          ],
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: thinking a router 'knows the whole path' to the destination. It only knows the next hop — the path emerges from many independent, local decisions.",
            "Mistake: assuming MAC addresses travel end to end. The link-layer (Ethernet) addresses change at every hop; only the IP addresses (and above) stay the same from source to final destination.",
            "Mistake: confusing 'my packet reached the destination' with 'the destination process accepted it'. Routing only gets a packet to the right machine; the transport/application layers decide if anything is listening and willing to respond.",
          ],
        },
        {
          title: "Practice: trace the headers",
          kind: "practice",
          body: [
            "A packet leaves your laptop (10.0.0.12) for a server on the open internet (203.0.113.9) via your home router (10.0.0.1).",
          ],
          check: {
            type: "order",
            q: "Put the headers in the order they are stacked on the outgoing HTTP request, outermost first.",
            items: ["Ethernet header", "IP header", "TCP header", "HTTP request text"],
            explain: "Each layer wraps the one above it, so Ethernet (built fresh at every hop) sits on the outside, and the application data is the innermost, unchanged payload.",
            hints: ["The layer that only matters for the current physical hop is the outermost one."],
          },
        },
        {
          title: "Practical relevance",
          kind: "relevance",
          body: [
            "Knowing which layer a bug lives at tells you which tool reaches it. Burp Suite inspects layer 7 (HTTP). Nmap works at layers 3–4 (IP/TCP/UDP). Wireshark can decode all of them, which is also why it's slower to triage with.",
            "A remote bug-bounty hunter mostly touches layers 3–7: IP, TCP/UDP, TLS, the application. Someone on the same Wi-Fi/LAN can also touch layer 2 — ARP spoofing, rogue DHCP, evil-twin access points.",
            "What this does NOT prove: seeing a packet travel through a router tells you nothing about whether the destination application is vulnerable — routing is purely about delivery, not about what happens once data arrives. Don't confuse 'I can reach it' with 'it is exploitable'.",
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
          why: [
            "The link layer only carries MAC addresses, not ports.",
            "The internet (IP) layer identifies machines, not services on them.",
            "",
            "Application-layer data (e.g. HTTP text) has no port field of its own — it sits inside the transport segment.",
          ],
          explain: "Ports are a transport-layer concept. IP addresses machines; ports address services on them.",
          hints: ["Think about which header has 'sport'/'dport' fields."],
          ref: "The four/seven-layer stack",
        },
        {
          type: "order",
          q: "Put the headers in the order a packet is built, outermost first.",
          items: ["Ethernet header", "IP header", "TCP header", "HTTP payload"],
          explain: "Each layer wraps the one above it, so Ethernet is on the outside and the application data is at the core.",
          hints: ["Which header is rebuilt fresh at every router hop?"],
          ref: "Encapsulation",
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
          explain: "Picking the right layer-tool is most of being efficient. A web bug does not need Wireshark; a port scan does not need Burp Suite.",
          hints: ["Which tool decodes raw frames all the way up?"],
          ref: "Practical relevance",
        },
        {
          type: "fill",
          q: "Name the IP header field that a router decrements by 1 at every hop, which traceroute exploits to map a path.",
          answers: ["ttl", "time to live"],
          explain: "TTL (Time To Live) prevents packets from looping forever and lets traceroute provoke an ICMP reply from each hop in turn.",
          hints: ["It is a hop counter, not a timer measured in seconds."],
          ref: "Routing: how a packet finds its way",
        },
        {
          type: "mc",
          q: "Why does a packet's Ethernet (link-layer) header change at every router hop, while the IP source/destination addresses stay the same?",
          options: [
            "Ethernet headers are optional and randomly added",
            "The IP header identifies the ultimate source/destination machine end-to-end, while the Ethernet header only needs to get the frame across the current physical hop",
            "Routers rewrite the IP addresses for security",
            "TCP handles the addressing, not IP",
          ],
          answer: 1,
          why: [
            "Ethernet headers are required for the frame to be delivered on the local segment, not optional.",
            "",
            "Routers don't rewrite IP addresses as part of normal forwarding (that's a separate feature called NAT).",
            "TCP has no address fields at all — it only has port numbers.",
          ],
          explain: "IP addressing is end-to-end; link-layer addressing is only hop-to-hop, which is exactly what lets independent routers forward packets without knowing the whole path.",
          hints: ["Compare what traceroute reveals to what stays constant throughout."],
          ref: "Worked example: one HTTP request, three hops",
        },
      ],
    },
    {
      id: "addressing",
      title: "IP addresses and subnets",
      summary: "Binary, prefixes, masks, and telling exactly which addresses belong to a subnet — essential for reading scope.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you will be able to: convert an IPv4 octet between decimal and binary, explain what a CIDR prefix length means, derive a subnet mask from a prefix, determine whether a given address belongs to a given subnet, compute a subnet's network address, broadcast address and usable host range for arbitrary prefixes (not just /24), and correctly read an IP range inside an authorised testing scope.",
          ],
        },
        {
          title: "Why addresses are grouped into subnets",
          kind: "intuition",
          body: [
            "Think of a large office building. Instead of giving every room a totally unrelated, random number, the building is split into floors, and rooms are numbered '3rd floor, room 14'. Anyone can tell from the number alone which floor a room is on, without a master directory.",
            "IP networks do the same thing: addresses are grouped into subnets (floors) so that routers can make a fast decision — 'is this destination on my own local network, or do I need to forward it elsewhere?' — just by looking at part of the address, without keeping track of every single machine on the internet individually.",
            "Where the analogy breaks: floor numbers in a building are usually written as separate information ('3rd floor, room 14'). In an IP address, the 'floor part' and the 'room part' are both silently packed into the *same* 32-bit number, and you need a mask to know where one ends and the other begins. That's the whole topic of this lesson.",
          ],
        },
        {
          title: "Prerequisite: bits, binary, and octets",
          kind: "prereq",
          body: [
            "Computers store numbers in binary (base 2): each digit (a 'bit') is 0 or 1. An 8-bit group is called a byte, or in networking, an octet (meaning 'a group of eight').",
            "An 8-bit octet can represent 2^8 = 256 different values: the decimal numbers 0 through 255. Each bit position is worth a power of two, counting from the right: 128, 64, 32, 16, 8, 4, 2, 1.",
            "To convert binary to decimal, add up the position-values of the bits that are 1. Example: 11000000 = 128 + 64 = 192. To convert decimal to binary, repeatedly subtract the largest power of two that fits: 200 → 128 fits (200-128=72) → 64 fits (72-64=8) → 8 fits (8-8=0) → so bits 128, 64, and 8 are set: 11001000.",
          ],
          code: `bit value:  128  64  32  16   8   4   2   1
192      =  1    1   0   0   0   0   0   0   (128+64)
200      =  1    1   0   0   1   0   0   0   (128+64+8)
255      =  1    1   1   1   1   1   1   1   (all bits on)`,
          check: {
            type: "fill",
            q: "Convert the binary octet 11100000 to decimal.",
            answers: ["224"],
            explain: "128 + 64 + 32 = 224. The three leftmost bits are set; the rest are 0.",
            hints: ["Add the position-values of the bits that are 1, counting 128, 64, 32... from the left."],
          },
        },
        {
          title: "32 bits, four octets",
          kind: "explain",
          body: [
            "An IPv4 address is a single 32-bit number. 32 bits is simply four 8-bit octets glued together — that size was fixed when IPv4 was designed in the early internet, giving roughly 4.3 billion possible addresses (2^32), which is why the internet eventually ran low on them (a separate story, IPv6).",
            "For humans, that 32-bit number is written as 'dotted decimal': each of the four octets converted to decimal, separated by dots. 192.0.2.17 is really the 32-bit number whose first octet is 11000000, second is 00000000, third is 00000010, fourth is 00010001.",
            "Every IPv4 address you will ever see — 192.0.2.17, 10.0.0.5, 203.0.113.42 — is just this same four-octet, 32-bit structure. None of the four numbers can exceed 255, because each is only 8 bits.",
          ],
          code: `192   .   0   .   2   .  17
11000000.00000000.00000010.00010001   (32 bits total)`,
        },
        {
          title: "Network portion vs host portion",
          kind: "explain",
          body: [
            "An IP address by itself does not tell you where the 'subnet boundary' is — you always need a second piece of information alongside it: the prefix length (or mask). Together, address + prefix split the 32 bits into two parts: the network portion (identifies the subnet) and the host portion (identifies one specific machine inside that subnet).",
            "CIDR notation writes this as address/prefix, e.g. 192.0.2.17/24. The number after the slash says how many of the 32 bits, counting from the left, are the network portion. The remaining bits (32 - prefix) are the host portion.",
            "Example: 192.0.2.17/24 → the first 24 bits (192.0.2) are the network portion; the last 8 bits (.17) are the host portion. Every address that shares the same first 24 bits — 192.0.2.0 through 192.0.2.255 — is in the same subnet.",
          ],
          code: `192.0.2.17/24
 network bits (24): 11000000.00000000.00000010 (192.0.2)
 host bits (8):      00010001                   (.17)`,
        },
        {
          title: "From prefix to subnet mask",
          kind: "explain",
          body: [
            "A subnet mask is the same idea as the prefix length, written out as a full 32-bit number: write a 1 for every network bit, a 0 for every host bit, then read it as four decimal octets, just like an address.",
            "/24 → 24 ones then 8 zeros → 11111111.11111111.11111111.00000000 → 255.255.255.0. /26 → 26 ones then 6 zeros → 11111111.11111111.11111111.11000000 → 255.255.255.192.",
            "To test whether an address is in a subnet, a computer performs a bitwise AND between the address and the mask (a 1 in the mask keeps that address bit, a 0 forces it to 0). If the result equals the subnet's network address, the IP belongs to that subnet. This is literally how your operating system decides 'is this destination local, or do I send it to my gateway?' from the layers lesson.",
          ],
          code: `/24  -> 11111111.11111111.11111111.00000000 -> 255.255.255.0
/26  -> 11111111.11111111.11111111.11000000 -> 255.255.255.192
/16  -> 11111111.11111111.00000000.00000000 -> 255.255.0.0`,
          check: {
            type: "fill",
            q: "Write the subnet mask that corresponds to a /16 prefix, in dotted decimal.",
            answers: ["255.255.0.0"],
            explain: "/16 means 16 leading 1-bits (the first two octets), and 16 trailing 0-bits (the last two octets): 255.255.0.0.",
            hints: ["Each full octet of 1s is 255; each full octet of 0s is 0."],
          },
        },
        {
          title: "/24: the familiar case",
          kind: "explain",
          body: [
            "/24 is special because it aligns exactly with the octet boundaries you already read naturally: the network portion is the first three octets, and the host portion is the entire last octet. That is why '203.0.113.0/24' feels obvious: it is every address from 203.0.113.0 to 203.0.113.255.",
            "A /24 has 8 host bits, so 2^8 = 256 total addresses in the block. But not all 256 are assignable to individual machines: the very first address of the block (all host bits 0, e.g. 203.0.113.0) is the network address, which identifies the subnet itself and is never assigned to a host. The very last address (all host bits 1, e.g. 203.0.113.255) is the broadcast address, used to send a packet to every host on that subnet at once, and is also never assigned to a single host.",
            "That leaves 256 - 2 = 254 usable host addresses in a conventional /24: 203.0.113.1 through 203.0.113.254.",
          ],
          code: `203.0.113.0/24
 total addresses : 256   (2^8, 8 host bits)
 network address : 203.0.113.0    (all host bits 0 — not assignable)
 broadcast address: 203.0.113.255 (all host bits 1 — not assignable)
 usable hosts     : 203.0.113.1 – 203.0.113.254  (254 addresses)`,
        },
        {
          title: "Edge cases: /31 and /32",
          kind: "explain",
          body: [
            "Be careful generalising 'subtract 2 for network and broadcast' to every prefix — it is only the convention for normal host subnets, not a law of the protocol.",
            "/32 has zero host bits: it identifies exactly one single address (used e.g. to describe one specific host in a routing table or a firewall rule, or sometimes in scope definitions to name exactly one in-scope IP).",
            "/31 has exactly one host bit, so mathematically it would give 2 addresses with 'network' and 'broadcast' being the same two addresses — RFC 3021 defines /31 as a special case used on point-to-point links (e.g. between two routers) where BOTH addresses are usable as host addresses, because there is no need for a broadcast address between exactly two machines.",
            "Takeaway: always ask 'how many host bits, and does this prefix fall into one of the special small cases?' rather than assuming every subnet loses exactly 2 addresses.",
          ],
          check: {
            type: "mc",
            q: "How many usable host addresses does a conventional /30 subnet have?",
            options: ["4", "2", "1", "0"],
            answer: 1,
            why: [
              "4 is the total address count (2^2 host bits), before removing network and broadcast.",
              "",
              "/30 has 2 host bits → 4 total, minus network and broadcast = 2 usable, not 1.",
              "A /30 is a valid, commonly-used subnet (e.g. for router-to-router links before /31 became common) — it is not empty.",
            ],
            explain: "/30 leaves 2 host bits → 4 total addresses. Following the normal convention, the first is the network address and the last is the broadcast address, leaving 2 usable — a classic size for a point-to-point link.",
            hints: ["2 host bits means 2^2 total addresses before removing network/broadcast."],
          },
        },
        {
          title: "Unfamiliar prefixes: /26 subnet boundaries",
          kind: "explain",
          body: [
            "/24 feels easy because the boundary lands exactly on an octet. A /26 splits a single octet in half (26 = 24 + 2, so 2 extra bits are borrowed from what would be the host octet in a /24).",
            "Method — block size: the number of addresses in each subnet is 2^(host bits). /26 has 32-26 = 6 host bits → 2^6 = 64 addresses per subnet. Because a /24's last octet has 256 addresses total, dividing by the block size (256/64 = 4) tells you there are exactly 4 /26 subnets inside one /24, and each one starts at a multiple of 64 in the last octet.",
            "So inside 203.0.113.0/24, the four /26 blocks are: 203.0.113.0/26 (.0–.63), 203.0.113.64/26 (.64–.127), 203.0.113.128/26 (.128–.191), and 203.0.113.192/26 (.192–.255). This 'list the multiples of the block size' method works for any prefix that splits one octet — /25 (block size 128), /27 (block size 32), /28 (16), and so on.",
          ],
          code: `203.0.113.0/24 split into four /26 blocks (block size = 64):
  203.0.113.0/26    range .0   - .63    (network .0,  broadcast .63)
  203.0.113.64/26   range .64  - .127   (network .64, broadcast .127)
  203.0.113.128/26  range .128 - .191   (network .128,broadcast .191)
  203.0.113.192/26  range .192 - .255   (network .192,broadcast .255)`,
        },
        {
          title: "Worked example: is 203.0.113.100 inside 203.0.113.64/26?",
          kind: "example",
          body: [
            "Question: given the scope line '203.0.113.64/26', is the address 203.0.113.100 in scope?",
            "Step 1 — find the block size: /26 has 6 host bits, block size = 2^6 = 64.",
            "Step 2 — list the block boundaries in the last octet: since 64 fits into 256 exactly 4 times, the blocks start at 0, 64, 128, 192. 203.0.113.64/26 is the block starting at 64, so it covers addresses .64 through .127 (the next boundary, 128, minus 1).",
            "Step 3 — compare: is 100 between 64 and 127 inclusive? Yes. So 203.0.113.100 is inside 203.0.113.64/26.",
            "Step 4 — identify the special addresses in that block, in case they matter: network address = 203.0.113.64 (not a usable host), broadcast address = 203.0.113.127 (not a usable host), usable range = 203.0.113.65–203.0.113.126.",
            "Why each step matters: step 1 tells you the subnet's *size*; step 2 tells you *where* each same-sized subnet starts; step 3 is the actual membership test; step 4 stops you from treating the boundary addresses as live, testable hosts.",
          ],
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: treating the network address or broadcast address as a normal host. 203.0.113.64 identifies the /26 subnet itself; pinging or scanning it is not scanning a real machine (though in practice some misconfigured devices do respond).",
            "Mistake: assuming every subnet loses exactly 2 addresses to network/broadcast. That is only the convention for ordinary host subnets — /31 and /32 are explicit exceptions (previous card).",
            "Mistake: comparing only the first three octets and ignoring the prefix when it isn't /24. 203.0.113.100 and 203.0.113.200 share the first three octets, but under a /26 mask they are in *different* subnets (.64/26 vs .192/26) — the mask, not 'looks similar', decides membership.",
            "Mistake: assuming a /16 or /8 scope means 'basically unlimited, don't bother checking'. A /16 is still a precise, bounded range (65,536 addresses) — an address just one octet off (e.g. the wrong third octet) can be completely outside it.",
          ],
        },
        {
          title: "Practice: calculate a /27",
          kind: "practice",
          body: [
            "A testing scope includes the subnet 198.51.100.32/27. Work out its block size, its boundaries, and whether 198.51.100.50 is inside it.",
          ],
          check: {
            type: "fill",
            q: "What is the broadcast address of 198.51.100.32/27?",
            answers: ["198.51.100.63"],
            explain: "/27 has 5 host bits → block size 2^5 = 32. Starting at 32, the block covers .32–.63, so the broadcast (all-ones host bits, the last address) is 198.51.100.63.",
            hints: [
              "First find the block size: 32 - 27 = 5 host bits, so 2^5 addresses per block.",
              "The block starts at .32, so it must end 32 addresses later, at .63 (since .32 is already address 0 of the block).",
            ],
          },
        },
        {
          title: "Practical relevance: reading authorised scope",
          kind: "relevance",
          body: [
            "Every bug bounty or pentest engagement names an exact in-scope IP range or domain list. Testing outside it is unauthorised access — a legal problem, not a bug you can report. Being able to read '203.0.113.42 is inside 203.0.113.0/24' — or, harder, 'inside 203.0.113.0/26 but NOT inside 203.0.113.64/26' — at a glance is a basic professional requirement before you touch anything.",
            "What subnet knowledge proves: whether a given IP address falls within a stated range. What it does NOT prove: whether a host at that address is reachable, running any particular service, or vulnerable — that requires the scanning and enumeration techniques taught in later units. A correct subnet calculation only tells you 'may I test this address at all', never 'is this address interesting'.",
            "RFC1918 reserves three ranges that never appear on the public internet: 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16. Seeing one of these leak out of a public response (e.g. in an error message or redirect) is often valuable: it reveals an internal hostname or IP that the scope's public surface was supposed to hide.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Convert the decimal octet 200 to its 8-bit binary form.",
          answers: ["11001000"],
          explain: "200 = 128 + 64 + 8, so the bits for 128, 64 and 8 are set: 11001000.",
          hints: ["Start by checking if 128 fits into 200 (it does, remainder 72).", "Then check if 64 fits into the remainder."],
          ref: "Prerequisite: bits, binary, and octets",
        },
        {
          type: "mc",
          q: "Is 10.0.0.200 inside the subnet 10.0.0.0/24?",
          options: ["Yes", "No, it is in a different /24", "Only if the gateway allows it", "Cannot tell without the MAC address"],
          answer: 0,
          why: [
            "",
            "A /24 covers every value of the last octet, 0–255, so .200 is well within range — there is no 'different /24' here.",
            "Gateway configuration does not change which addresses mathematically belong to a subnet.",
            "MAC addresses are a link-layer detail unrelated to IP subnet membership.",
          ],
          explain: "A /24 covers .0 through .255 of the last octet, so .200 is inside — the network portion (10.0.0) is identical.",
          hints: ["/24 means only the first three octets define the subnet; the last octet can be anything 0-255."],
          ref: "/24: the familiar case",
        },
        {
          type: "fill",
          q: "How many usable host addresses does a conventional /26 network have?",
          answers: ["62"],
          explain: "/26 leaves 6 host bits = 2^6 = 64 total addresses, minus the network address and the broadcast address = 62 usable.",
          hints: ["First find the total block size (2^host-bits).", "Then subtract 2 for network + broadcast, as with a normal /24."],
          ref: "Unfamiliar prefixes: /26 subnet boundaries",
        },
        {
          type: "mc",
          q: "Scope reads `198.51.100.0/26`. Is 198.51.100.140 in scope?",
          options: [
            "Yes, it starts with 198.51.100 so it matches",
            "No — /26 only covers addresses .0 through .63 in the last octet; .140 falls in a different /26 block entirely",
            "Yes, because /26 scopes always cover the full last octet",
            "Cannot be determined without a mask",
          ],
          answer: 1,
          why: [
            "Matching the first three octets is necessary but not sufficient once the prefix splits the last octet, as /26 does.",
            "",
            "/26 explicitly does NOT cover the full last octet — only a 64-address block starting at the stated network address.",
            "The mask is already determinable: /26 directly tells you the mask is 255.255.255.192.",
          ],
          explain: "198.51.100.0/26 covers only .0–.63. 198.51.100.140 falls in the third /26 block of that /24 (.128–.191), a sibling subnet, not this one.",
          hints: ["Find the block size for /26 (2^6=64), then list the block boundaries: 0, 64, 128, 192."],
          ref: "Worked example: is 203.0.113.100 inside 203.0.113.64/26?",
        },
        {
          type: "mc",
          q: "A bug-bounty program's scope reads `*.shop.example and 198.51.100.0/24`. You discover the host api.staging.shop.example resolves to 192.0.2.17. Can you test it?",
          options: [
            "Yes, the subdomain matches *.shop.example even though the IP is outside the listed /24",
            "No, the IP is outside 198.51.100.0/24 so the scope rules exclude it",
            "Only on weekends",
            "Only with permission from the ISP",
          ],
          answer: 0,
          why: [
            "",
            "Scope lines are typically read as OR, not AND — matching the subdomain rule alone is sufficient even if the IP rule doesn't also match.",
            "Scope does not depend on the day of the week.",
            "ISPs are not part of the authorisation chain for a bug bounty program.",
          ],
          explain: "Scope rules are usually read as OR across lines: match EITHER the wildcard subdomain OR the IP range. The subdomain match is enough. Always re-read the exact wording per program, since some do write AND conditions.",
          hints: ["Check whether the two scope lines are separated by 'and' meaning 'either of these' or a strict combined condition — re-read the program's exact policy text in real engagements."],
          ref: "Practical relevance: reading authorised scope",
        },
        {
          type: "fill",
          q: "What is the network address of the subnet that contains 203.0.113.200/26?",
          answers: ["203.0.113.192"],
          explain: "/26 block size is 64. The blocks start at 0, 64, 128, 192. 200 falls between 192 and 255, so the network (first) address of that block is 203.0.113.192.",
          hints: ["List the /26 block boundaries: 0, 64, 128, 192.", "Find which boundary is just below 200."],
          ref: "Unfamiliar prefixes: /26 subnet boundaries",
        },
      ],
    },
    {
      id: "tcp-udp",
      title: "TCP, UDP and the handshake",
      summary: "What a port is, two transport philosophies, and why a TCP reset is useful information.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you will be able to: explain what a port number is and why it exists, describe the TCP three-way handshake step by step with the reason for each step, contrast TCP and UDP's guarantees, and interpret SYN-ACK / RST / silence as three distinct, meaningful outcomes of probing a port.",
          ],
        },
        {
          title: "Why you need more than an IP address",
          kind: "intuition",
          body: [
            "An IP address gets your data to the right *building* (machine). But a server usually runs many programs at once — a web server, a mail server, an SSH daemon. Which one should receive an arriving packet?",
            "This is exactly like a building having one street address but many apartments: the street address alone isn't enough, you also need the apartment number. In networking, that 'apartment number' is the port number.",
            "Where the analogy breaks: apartment numbers are fixed per resident. Port numbers are closer to 'department extensions' — some are standard by convention (port 80 means 'the HTTP department', port 22 means 'the SSH department'), but any program can choose to listen on almost any port.",
          ],
        },
        {
          title: "Prerequisite: what a port number is",
          kind: "prereq",
          body: [
            "A port is a 16-bit number (0–65535) that the transport layer (TCP or UDP) uses to identify *which application* on a machine a packet belongs to, in addition to the IP address.",
            "Well-known ports (0–1023) are conventionally reserved for common services: 80 = HTTP, 443 = HTTPS, 22 = SSH, 53 = DNS, 25 = SMTP. A server 'listens' on a port, meaning an application has told the OS 'deliver anything arriving on this port to me'. A client making an outgoing connection is usually assigned a random high-numbered 'ephemeral' source port by its own OS (e.g. 51200), while it connects to a well-known destination port on the server (e.g. 80).",
            "A single TCP connection is therefore uniquely identified by four numbers together, called a socket pair: source IP, source port, destination IP, destination port.",
          ],
          code: `client 10.0.0.12 : 51200  <--->  server 198.51.100.50 : 80
   ^ephemeral, random          ^well-known, fixed by convention`,
          check: {
            type: "fill",
            q: "What is the conventional well-known port number for unencrypted HTTP?",
            answers: ["80"],
            explain: "Port 80 is the IANA-assigned well-known port for HTTP; 443 is its encrypted counterpart, HTTPS.",
            hints: ["It's a two-digit number, smaller than 1000."],
          },
        },
        {
          title: "Two transports, two philosophies",
          kind: "explain",
          body: [
            "TCP is a conversation: before any data flows, it sets up a connection, numbers every byte it sends (so the receiver can reassemble things in order and detect loss), retransmits anything lost, and tears the connection down cleanly when done. This reliability costs a little time and overhead.",
            "UDP is a postcard: one datagram is sent, with no setup, no sequence numbers, and no guarantee it arrives or arrives in order. If you need reliability over UDP, the application itself has to build it (as QUIC/HTTP3 does). DNS queries, video calls, and many flood-style attacks use UDP because of its low overhead and lack of handshake.",
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
          kind: "explain",
          body: [
            "Every TCP connection opens the same way, and almost every scanning technique (later units) is a deliberate deviation from it.",
            "Step 1, client → server: SYN, carrying the client's chosen initial sequence number x. Meaning: 'I want to talk; let's agree my byte stream starts counting from x.'",
            "Step 2, server → client: SYN-ACK, carrying the server's own initial sequence number y, and acknowledgement x+1. Meaning: 'I heard you start at x (so I expect your next byte to be x+1), and I'm starting my own stream at y — only sent if something is actually listening on that port.'",
            "Step 3, client → server: ACK, acknowledgement y+1. Meaning: 'Confirmed, I heard you start at y.' After this, both sides consider the connection established and real application data (e.g. the HTTP request) can flow.",
            "Why three steps and not two: both sides need to prove they can both send AND receive, and both need to agree on starting sequence numbers in both directions — a two-way exchange only proves one direction works.",
          ],
          code: `client            server
   | ---- SYN, seq=x --------->|   "can we talk? my seq = x"
   | <-- SYN,ACK, seq=y,ack=x+1-|   "yes, my seq = y, ack = x+1"
   | ---- ACK, ack=y+1 ------->|   "confirmed"
   |        established        |`,
          check: {
            type: "order",
            q: "Order the three-way handshake.",
            items: ["Client sends SYN", "Server replies SYN,ACK", "Client sends ACK"],
            explain: "SYN, SYN-ACK, ACK. Each step confirms the ability to send and receive in one direction, which is why three (not two) messages are required.",
            hints: ["Who speaks first — the one wanting the connection, or the one waiting for it?"],
          },
        },
        {
          title: "What silence vs reset tells you",
          kind: "explain",
          body: [
            "Sending a single SYN packet to a port and watching the reply (or lack of one) reveals three distinct states, without ever logging in or sending valid application data:",
            "SYN-ACK back → the port is OPEN: something is listening and willing to complete the handshake.",
            "RST (reset) back → the port is CLOSED, but the host itself is up and reachable: the OS actively refused because nothing is listening there.",
            "No reply at all → the port is FILTERED: a firewall (or similar device) is silently dropping the packet, so you cannot tell if anything would have answered.",
            "These three different, information-rich outcomes from one tiny packet are exactly why port scanning works as a reconnaissance technique.",
          ],
          tone: "offense",
          check: {
            type: "mc",
            q: "A host replies RST to your SYN. What do you learn?",
            options: ["The port is open", "The port is closed, but the host is up and reachable", "The host is down", "A firewall silently dropped the packet"],
            answer: 1,
            why: [
              "An open port would reply SYN-ACK, not RST.",
              "",
              "A down host would typically produce no reply at all (or an ICMP host-unreachable), not an active RST.",
              "A firewall dropping the packet produces silence, not an RST — RST is an active, deliberate reply from the OS's TCP stack.",
            ],
            explain: "A reset means the TCP stack on that host actively refused — nothing is listening on that port, but the host and its network stack are definitely alive.",
            hints: ["RST is a reply, which means something on the network stack is actually processing your packet."],
          },
        },
        {
          title: "Worked example: three scans, three outcomes",
          kind: "example",
          body: [
            "You send a single SYN packet to three ports on 198.51.100.50 to find out what's running, without any prior knowledge.",
            "Port 80: reply is SYN-ACK, seq from server, ack = your seq+1. Conclusion: a service is actively listening on 80 and completed step 2 of the handshake correctly — you would send ACK next (or, for a lighter scan, an RST to abandon the half-open connection immediately, which is what a 'SYN scan' does).",
            "Port 8080: reply is RST. Conclusion: the host's TCP stack is up and responding, but no application has asked the OS to listen on 8080.",
            "Port 25 (SMTP): no reply within the timeout window, even after retransmitting your SYN. Conclusion: a firewall somewhere between you and the host is dropping packets to that port — you cannot tell whether a mail server is behind it or not, only that the path is blocked.",
            "Why this matters: three identical-looking SYN packets, three completely different, specific pieces of intelligence — and you never completed a real connection or authenticated to anything.",
          ],
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: assuming 'no reply' means the port is closed. Silence means filtered (or packet loss) — it specifically does NOT tell you whether a service exists behind the firewall.",
            "Mistake: assuming an open port is itself a vulnerability. An open port only tells you a service is listening; whether that service is outdated, misconfigured or exploitable is a completely separate question answered in later units (service/version enumeration).",
            "Mistake: confusing UDP's lack of a handshake with 'open ports don't exist in UDP'. UDP scanning is just harder to interpret, because there is no SYN-ACK equivalent — typically you infer 'closed' from an ICMP port-unreachable reply, and 'maybe open' from silence, which is the opposite pattern from TCP.",
          ],
        },
        {
          title: "Practice: interpret a scan result",
          kind: "practice",
          body: [
            "You scan 203.0.113.9 and get: port 22 → SYN-ACK; port 23 → RST; port 445 → no reply after retries.",
          ],
          check: {
            type: "match",
            q: "Match each port's observed result to its correct state.",
            pairs: [
              ["Port 22 (SYN-ACK)", "Open"],
              ["Port 23 (RST)", "Closed"],
              ["Port 445 (no reply)", "Filtered"],
            ],
            explain: "SYN-ACK confirms a listening service (open). RST confirms the host is up but nothing is listening (closed). Silence after retries indicates a firewall is dropping the probe (filtered) — the true state behind it is unknown.",
            hints: ["Which result involves the host actively responding, versus never responding at all?"],
          },
        },
        {
          title: "Practical relevance",
          kind: "relevance",
          body: [
            "This single packet-level distinction — open vs closed vs filtered — is the foundation of every port scanner (Nmap and similar) covered in the scanning unit, and of reading raw packet captures in Wireshark.",
            "What a handshake outcome proves: whether a TCP service is listening and reachable from your vantage point. What it does NOT prove: what that service is, what version it runs, or whether it has any vulnerability — those require the banner-grabbing and enumeration techniques taught later. Never report 'open port' alone as a finding.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "order",
          q: "Order the three-way handshake.",
          items: ["Client sends SYN", "Server replies SYN,ACK", "Client sends ACK"],
          explain: "SYN, SYN-ACK, ACK. Memorise it; half of network scanning techniques are shaped around skipping or breaking a step.",
          hints: ["Who speaks first: the side that wants the connection, or the side waiting for one?"],
          ref: "The three-way handshake",
        },
        {
          type: "mc",
          q: "A host replies RST to your SYN. What do you learn?",
          options: ["The port is open", "The port is closed but the host is up", "The host is down", "A firewall dropped the packet"],
          answer: 1,
          why: [
            "Open ports reply with SYN-ACK, not RST.",
            "",
            "A down host generally produces no reply, not an active RST.",
            "A dropped packet produces silence, not an active RST reply.",
          ],
          explain: "A reset means nothing is listening on that port. Silence (no reply) is what usually indicates a filtering firewall instead.",
          hints: ["RST requires the host's TCP stack to actively process and respond to your packet."],
          ref: "What silence vs reset tells you",
        },
        {
          type: "fill",
          q: "Which single TCP flag letter marks the very first packet of a connection?",
          answers: ["S", "SYN"],
          explain: "SYN — it synchronises the client's initial sequence number with the server.",
          hints: ["It's the first word in 'three-way handshake': SYN, SYN-ACK, ACK."],
          ref: "The three-way handshake",
        },
        {
          type: "mc",
          q: "Why does TCP need three messages to open a connection instead of two?",
          options: [
            "To slow down attackers",
            "Because both sides must prove they can send AND receive, and agree on initial sequence numbers in both directions",
            "Because UDP requires it",
            "It's an arbitrary historical choice with no technical reason",
          ],
          answer: 1,
          why: [
            "The handshake's design has a concrete technical purpose, not a security slowdown goal.",
            "",
            "UDP has no handshake at all, so it cannot require anything about TCP's design.",
            "The three-step design directly solves the two-direction confirmation problem — it is not arbitrary.",
          ],
          explain: "A two-way exchange only confirms one direction works. The third message confirms the server's sequence number was received, proving both directions are functional.",
          hints: ["Think about what each of the two directions (client→server, server→client) needs to prove."],
          ref: "The three-way handshake",
        },
        {
          type: "fill",
          q: "Name the transport protocol that sends data with no connection setup and no delivery guarantee, commonly used by DNS.",
          answers: ["udp", "user datagram protocol"],
          explain: "UDP (User Datagram Protocol) — a 'postcard' protocol with no handshake and no retransmission built in.",
          hints: ["It's the opposite philosophy from TCP's 'conversation' model."],
          ref: "Two transports, two philosophies",
        },
        {
          type: "mc",
          q: "A UDP probe to a port gets no reply at all. What is the most accurate conclusion?",
          options: [
            "The port is definitely open, since UDP never sends SYN-ACK anyway",
            "The port is definitely closed",
            "The result is ambiguous: it could be open (and the app just didn't reply) or filtered — UDP gives no equivalent of a SYN-ACK to confirm 'open'",
            "The host is definitely down",
          ],
          answer: 2,
          why: [
            "UDP does sometimes reply, but silence specifically does not confirm anything is listening.",
            "A closed UDP port typically produces an ICMP port-unreachable reply, not silence — so silence does not confirm closed either.",
            "",
            "A down host is only one of several possible explanations for silence; it cannot be concluded from this alone.",
          ],
          explain: "Unlike TCP, UDP gives no SYN-ACK equivalent, so silence is genuinely ambiguous between 'open and quiet' and 'filtered'. This is why UDP scanning is considered much less reliable than TCP scanning.",
          hints: ["Compare this to the TCP case: what made TCP's three outcomes each unambiguous?"],
          ref: "Common mistakes",
        },
      ],
    },
    {
      id: "dns-http",
      title: "DNS and HTTP in the wild",
      summary: "How a name becomes an address, and how the request/response model you will exploit most works.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you will be able to: explain, step by step, how a domain name is resolved to an IP address; read an HTTP request and response and identify each part; explain what a status code family means; and explain, at a high level, what TLS protects and does not protect.",
          ],
        },
        {
          title: "Why you can't just remember IP addresses",
          kind: "intuition",
          body: [
            "You don't memorise '198.51.100.50' to visit a shop's website — you type shop.example. DNS (Domain Name System) is the phonebook that converts a name humans can remember into the IP address machines actually route traffic to.",
            "Where this gets interesting for security: unlike a paper phonebook, DNS is a distributed, queryable system, and querying it (without ever 'hacking' anything) reveals a surprising amount about an organisation's infrastructure — which is why reconnaissance (next unit) starts here.",
          ],
        },
        {
          title: "How a DNS lookup actually works",
          kind: "explain",
          body: [
            "When you ask for shop.example, your machine first asks a recursive resolver (often run by your ISP or a public service like 1.1.1.1) to do the work for you. If that resolver doesn't already have the answer cached, it walks down a hierarchy on your behalf.",
            "Step 1: the resolver asks a root server 'who handles .example?' and gets back the address of the .example TLD (top-level domain) server. Step 2: it asks that TLD server 'who handles shop.example?' and gets back the address of shop.example's authoritative name server — the one the domain's owner actually configured. Step 3: it asks that authoritative server directly for the A record (IPv4 address) of shop.example, and gets the final answer, which it also caches for a while (the TTL on the DNS record, a different TTL from the IP header one, though the same underlying 'how long is this valid' idea).",
            "A query is normally carried over UDP port 53 (fits in one small packet, no handshake needed, matching what you learned about UDP's tradeoffs). TCP port 53 is used when the answer is too large for one UDP packet, and historically for zone transfers (AXFR) — a bulk copy of every record in a zone, meant only for secondary name servers, but a misconfiguration that still occasionally allows anyone to dump a domain's entire subdomain list.",
          ],
          code: `$ dig +short shop.example
93.184.216.34

$ dig AXFR @ns1.old-vendor.net example.com   # zone transfer attempt
; often blocked; on a bad config, dumps every subdomain.

$ dig +short txt example.com                 # TXT records leak more than people think:
"v=spf1 include:_spf.google.com include:mail.staging-corp.net ~all"`,
          check: {
            type: "order",
            q: "Order the steps a recursive resolver takes to resolve shop.example from nothing cached.",
            items: ["Ask a root server which server handles .example", "Ask the .example TLD server which server is authoritative for shop.example", "Ask the authoritative server for shop.example's A record"],
            explain: "Resolution walks down the DNS hierarchy: root → TLD → authoritative, each step narrowing down who to ask next, finishing with the actual answer.",
            hints: ["Which server would know the least specific information, and which would know the most specific?"],
          },
        },
        {
          title: "HTTP: a plain-text request/response conversation",
          kind: "explain",
          body: [
            "Once DNS has provided an IP address and a TCP connection is established (handshake, previous lesson), HTTP is the plain-text protocol browsers and APIs use to ask for and receive resources. An HTTP request names a method (what action), a path (which resource), and headers (metadata); the server replies with a status code and its own headers, plus an optional body.",
            "Because it is literally editable text sent over a connection you control, every field of a request — method, path, query string, headers, cookies, body — can be modified by whoever is sending it. That is the foundation of nearly all web application testing: send a request the server did not expect, and see how it reacts.",
          ],
          code: `GET /account?id=42 HTTP/1.1
Host: shop.example
Cookie: session=abc123
User-Agent: Mozilla/5.0

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 512

<html>...account #42...</html>`,
        },
        {
          title: "Status code families",
          kind: "explain",
          body: [
            "Status codes are grouped by their first digit, each meaning a different category of outcome: 2xx = success (the request was understood and fulfilled). 3xx = redirection (go look somewhere else, e.g. 302 Found). 4xx = client error (something about *your* request was wrong, e.g. 403 Forbidden, 404 Not Found). 5xx = server error (the server itself failed while handling an apparently valid request).",
            "For testing, each family tells you something different: 200 OK with content you shouldn't be seeing is often the actual vulnerability (an access-control failure). A 302 redirecting away from an admin page is worth following — the response body sent alongside the redirect sometimes leaks the page anyway. A 500 with a stack trace can leak framework/version info or even a raw SQL fragment. A 403 on `/admin` but 200 on `/admin/` or `/ADMIN` often reveals an access-control rule that only matched one exact string.",
          ],
          tone: "offense",
          check: {
            type: "mc",
            q: "You see `/admin` returns 403 and `/admin/` returns 200. What does that most likely indicate?",
            options: [
              "Just a URL alias — same page, no issue",
              "An access-control rule that only matched the exact string `/admin`, bypassed by adding a trailing slash",
              "A DNS problem",
              "A TLS mismatch",
            ],
            answer: 1,
            why: [
              "If it were a harmless alias, both forms would return the same status, not opposite ones.",
              "",
              "DNS resolves names to IPs; it has no concept of paths like /admin, so it cannot explain this.",
              "TLS secures the connection; it does not evaluate application-level authorisation rules on specific paths.",
            ],
            explain: "This is a textbook authorisation bypass. Many frameworks route both forms to the same handler but check access rules using exact string matching, which a trailing slash defeats.",
            hints: ["Both URLs likely reach the same underlying page — so what differs between the two checks?"],
          },
        },
        {
          title: "Worked example: reading a leaking error page",
          kind: "example",
          body: [
            "You submit a slightly malformed value to a parameter and get back:",
            "`HTTP/1.1 500 Internal Server Error` with headers including `X-Powered-By: PHP/5.6.40`, and body text containing `File: /var/www/html/pay.php on line 72` and `Query: SELECT * FROM users WHERE email='x\\'' AND status=1`.",
            "Step 1 — status family: 5xx means the server itself failed while processing your input, not merely rejected it — meaning your input reached deep into the application logic.",
            "Step 2 — the X-Powered-By header: discloses the exact language/runtime version (PHP 5.6.40), which you can now check against known end-of-life dates and vulnerabilities.",
            "Step 3 — the file path and line number: confirms this is a debug/verbose error mode that should not be enabled in production, and tells you exactly which file handles this request.",
            "Step 4 — the raw SQL query, with your injected character (`'`) visible unescaped inside it: this is strong evidence the application builds SQL queries by directly concatenating user input, a likely SQL injection point (fully explored in a later unit) — but at this stage it is evidence to investigate further, not yet a confirmed, exploitable vulnerability.",
          ],
        },
        {
          title: "A note on TLS: what HTTPS actually protects",
          kind: "explain",
          body: [
            "HTTPS is HTTP sent over a TLS-encrypted connection. Before any HTTP bytes are exchanged, the client and server perform a TLS handshake: they agree on encryption algorithms, the server proves its identity using a certificate (verified against a trusted certificate authority), and both sides derive a shared encryption key.",
            "TLS protects the confidentiality and integrity of the data in transit between client and server — an eavesdropper on the network cannot read or silently modify the HTTP request/response. It does NOT protect against anything happening after decryption: a vulnerable application behind HTTPS is exactly as vulnerable as it would be over plain HTTP, because TLS says nothing about what the application does with the data once received.",
            "One detail worth knowing now (expanded in a dedicated TLS lesson): the handshake's SNI (Server Name Indication) field sends the requested hostname in plaintext even over an encrypted connection, so that a server hosting many sites on one IP knows which certificate to present — this is why network observers can often still see *which site* you're visiting, even though they can't read the page content.",
          ],
        },
        {
          title: "Common mistakes",
          kind: "mistakes",
          body: [
            "Mistake: assuming HTTPS means 'the application is secure'. TLS only secures the network transport — application-layer flaws like SQL injection, XSS, or access-control bugs are unaffected by whether the connection uses TLS.",
            "Mistake: treating any 500 error as proof of a vulnerability. A 500 alone only shows the server failed; you still need to inspect the body/headers for actual evidence (like the SQL fragment above) before concluding anything.",
            "Mistake: assuming a DNS A record is permanent. TTLs mean the answer can change, and 'what resolves now' may differ from 'what resolved when a report was written' — always re-verify current resolution before testing.",
          ],
        },
        {
          title: "Practice: diagnose the response",
          kind: "practice",
          body: [
            "You request `/export?format=xml` and receive `HTTP/1.1 200 OK` with `Content-Type: application/xml` and a body containing the exact raw XML value you sent back, reflected inside an error tag, unescaped.",
          ],
          check: {
            type: "fill",
            q: "Which status code family (first digit) indicates the server successfully fulfilled this request?",
            answers: ["2xx", "2"],
            explain: "A 200 response is in the 2xx family, meaning success — the server understood and fulfilled the request, even though the content it fulfilled it with (reflected unescaped input) may itself be worth investigating further.",
            hints: ["200 starts with which digit?"],
          },
        },
        {
          title: "Practical relevance",
          kind: "relevance",
          body: [
            "DNS and HTTP are the two protocols a web-focused hunter reads constantly: DNS to map an organisation's attack surface (subdomains, mail config, leaked internal names), HTTP to interact with and tamper with every application.",
            "What a single interesting response proves: that a particular input produced a particular, perhaps unexpected, output — worth investigating. What it does NOT prove on its own: that a vulnerability is confirmed, reproducible, or exploitable — later units cover how to validate a finding (e.g. proving a SQL injection by extracting real data, not just seeing a quote reflected) before reporting it.",
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
          why: [
            "If it were just an alias, both forms would get the same access-control result.",
            "",
            "DNS has no concept of URL paths.",
            "TLS does not evaluate path-based authorisation.",
          ],
          explain: "This is a textbook authorisation bypass. Many frameworks route both forms to the same handler but check ACLs with string equality.",
          hints: ["Think about what differs between the exact-match check and the actual routing."],
          ref: "Status code families",
        },
        {
          type: "mc",
          exhibit:
            "HTTP/1.1 500 Internal Server Error\nX-Powered-By: PHP/5.6.40\n\n...\nFile: /var/www/html/pay.php on line 72\nQuery: SELECT * FROM users WHERE email='x\\'' AND status=1",
          q: "Which single detail is the strongest lead for further investigation?",
          options: [
            "The 500 status alone",
            "The disclosed PHP version AND the SQL fragment together, revealing an unescaped quote reaching the query",
            "The Host header",
            "Nothing — this is normal",
          ],
          answer: 1,
          why: [
            "The 500 status alone just means something failed; it doesn't say what or why.",
            "",
            "The Host header here is routine and unremarkable.",
            "An unescaped quote reaching a raw SQL string is specifically not normal, safe behaviour.",
          ],
          explain: "500 + stack trace + raw SQL fragment = version info, a likely injection point, and a known-EOL interpreter — three leads in one error page, though still needing validation before calling it a confirmed vulnerability.",
          hints: ["Which detail directly involves your own input reaching the database layer unescaped?"],
          ref: "Worked example: reading a leaking error page",
        },
        {
          type: "fill",
          q: "Name the HTTP header that tells a server which site a request is for.",
          answers: ["host", "host header"],
          explain: "The Host header. It is also how one IP can serve many sites — and tampering it is the basis of host-header injection and virtual-host confusion attacks.",
          hints: ["It's the same header that lets one web server answer for many domains."],
          ref: "HTTP: a plain-text request/response conversation",
        },
        {
          type: "order",
          q: "Order the steps a recursive resolver takes to look up shop.example for the first time (nothing cached).",
          items: ["Ask a root server for the .example TLD server", "Ask the .example TLD server for shop.example's authoritative server", "Ask the authoritative server for the A record"],
          explain: "Resolution always narrows from the most general (root) to the most specific (authoritative) server.",
          hints: ["Which server in the chain actually knows the final IP address?"],
          ref: "How a DNS lookup actually works",
        },
        {
          type: "mc",
          q: "A site is served entirely over HTTPS. What does this tell you about whether its application code is free of SQL injection?",
          options: [
            "Nothing — TLS protects data in transit, not the application's handling of input after decryption",
            "It guarantees no SQL injection is possible",
            "It makes SQL injection less likely but not impossible",
            "HTTPS and SQL injection are unrelated protocol layers that can't be compared",
          ],
          answer: 0,
          why: [
            "",
            "TLS has no awareness of or effect on how the application constructs database queries.",
            "There is no mechanism by which encrypting the transport layer would reduce injection risk at all — not even partially.",
            "They operate at different layers, but that is exactly why the comparison matters: TLS's scope simply does not reach application logic, which is the useful, testable conclusion.",
          ],
          explain: "TLS only protects confidentiality/integrity of data between client and server. It says nothing about how the server processes that data once decrypted, so HTTPS has no bearing on SQL injection risk.",
          hints: ["Where does TLS encryption end — at the network boundary, or inside the application code?"],
          ref: "A note on TLS: what HTTPS actually protects",
        },
        {
          type: "fill",
          q: "Which status code family (2xx/3xx/4xx/5xx) indicates the problem was with the client's request itself, such as requesting a resource that doesn't exist?",
          answers: ["4xx", "4"],
          explain: "4xx = client error. 404 Not Found and 403 Forbidden are both 4xx codes describing a problem with the request as made.",
          hints: ["404 Not Found starts with which digit?"],
          ref: "Status code families",
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
