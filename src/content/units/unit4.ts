import type { Unit } from "../types";
import { tcp, udp, arp, icmp, dns } from "../pkt";

const synFlood = [
  ...Array.from({ length: 40 }, (_, i) =>
    tcp(0.01 * i, `203.0.113.${(i % 200) + 10}`, 40000 + i, "10.0.0.20", 80, "S", { label: "syn-flood", ttl: 50 }),
  ),
  tcp(0.5, "10.0.0.12", 49500, "10.0.0.20", 80, "S"),
  tcp(0.51, "10.0.0.20", 80, "10.0.0.12", 49500, "SA"),
  tcp(0.52, "10.0.0.12", 49500, "10.0.0.20", 80, "A"),
];

const arpSpoof = [
  arp(0.1, "aa:bb:cc:00:00:12", "Who has 10.0.0.1? Tell 10.0.0.12"),
  arp(0.11, "aa:bb:cc:00:00:01", "10.0.0.1 is at aa:bb:cc:00:00:01"),
  arp(1.0, "aa:bb:cc:ff:ff:99", "10.0.0.1 is at aa:bb:cc:ff:ff:99", { label: "arp-spoof" }),
  arp(1.5, "aa:bb:cc:ff:ff:99", "10.0.0.1 is at aa:bb:cc:ff:ff:99", { label: "arp-spoof" }),
  arp(2.0, "aa:bb:cc:ff:ff:99", "10.0.0.1 is at aa:bb:cc:ff:ff:99", { label: "arp-spoof" }),
];

const unit4: Unit = {
  id: "attacks",
  index: 4,
  title: "Network Attacks",
  tagline: "Spoofing, flooding and poisoning — and how each shows up on the wire.",
  tone: "offense",
  lessons: [
    {
      id: "arp-mitm",
      title: "ARP spoofing and MITM",
      summary: "The trust assumption that makes every switched LAN fragile.",
      cards: [
        {
          title: "ARP has no authentication",
          body: [
            "ARP maps IPs to MACs on the local segment. A host asks 'who has 10.0.0.1?' and believes whatever reply arrives first.",
            "An attacker on the same LAN can simply announce 'I am 10.0.0.1' to the victim, and 'I am the victim' to the gateway. Now every packet between them flows through the attacker.",
          ],
          tone: "offense",
          code: `attacker                  victim                  gateway
  "10.0.0.1 is at AA" -->   victim updates its ARP cache
  "10.0.0.12 is at AA" -->                            gateway updates cache
  victim <----- attacker (relay) -----> gateway`,
        },
        {
          title: "Detection on the wire",
          body: [
            "A legitimate ARP reply is almost always triggered by a matching request. Unsolicited ('gratuitous') ARP replies, especially repeated ones for the gateway, are the signature.",
            "A sudden change in the MAC behind a known IP is the strongest indicator.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "What makes ARP spoofing so effective?",
          options: [
            "It encrypts the attacker's traffic",
            "ARP has no authentication, hosts trust the latest reply",
            "It exploits a Windows-only bug",
            "It requires physical access to the switch",
          ],
          answer: 1,
          explain: "The protocol predates security concerns. It will believe anything a nearby device tells it.",
        },
        {
          type: "fill",
          q: "What is the name for an ARP reply nobody asked for?",
          answers: ["gratuitous arp", "gratuitous"],
          explain: "Gratuitous ARP. Normal when a host boots; suspicious when repeated for the gateway.",
        },
      ],
    },
    {
      id: "flood-dos",
      title: "Floods and DoS",
      summary: "SYN flood, UDP amplification, and why volume alone is a signal.",
      cards: [
        {
          title: "SYN flood mechanics",
          body: [
            "Each half-open connection reserves a slot in the server's SYN queue. Flood the queue and legitimate SYNs are dropped.",
            "The attacker spoofs sources so the SYN-ACKs land on uninvolved hosts and the queue entries never clean up.",
          ],
          tone: "offense",
          code: `attacker --- SYN (src=random) ---> server     queue slot held
server --- SYN,ACK ---> random host          dropped
... repeat 10 000 times/second ...`,
        },
        {
          title: "UDP reflection and amplification",
          body: [
            "Send a small spoofed UDP query to a public DNS or NTP server; it sends a much bigger reply to your victim.",
            "A 60-byte DNS query can produce a 3 000-byte response: amplification factor 50.",
          ],
          tone: "offense",
        },
        {
          title: "Defender's view",
          body: [
            "Rate thresholds and SYN cookies defeat basic SYN floods. For amplification, egress filtering (BCP 38) stops your network being used as a reflector.",
            "On the IDS: alert on SYN rate per destination, and on inbound UDP from ports you did not query.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Why do SYN floods usually use spoofed sources?",
          options: [
            "To hide the attacker",
            "So the server's SYN-ACK goes nowhere and the queue slot leaks",
            "To avoid firewall logs",
            "Because TCP requires it",
          ],
          answer: 1,
          explain: "Both — but the queue-leak effect is what makes the DoS actually work.",
        },
        {
          type: "mc",
          q: "A 60-byte query produces a 3 000-byte reply. What is this called?",
          options: ["Encryption overhead", "Amplification", "Fragmentation", "A handshake"],
          answer: 1,
          explain: "Amplification factor is response size divided by query size. DNS, NTP and memcached are classic offenders.",
        },
      ],
    },
    {
      id: "dns-spoof",
      title: "DNS spoofing and poisoning",
      summary: "Lie about an answer and you redirect every subsequent connection.",
      cards: [
        {
          title: "Race the real server",
          body: [
            "If the attacker's forged DNS response arrives before the real one and matches the query ID and source port, the resolver caches it.",
            "Modern resolvers randomise source ports and query IDs, pushing the attack from easy to difficult but not impossible.",
          ],
          tone: "offense",
        },
        {
          title: "Detection",
          body: [
            "Two responses for the same query ID within milliseconds — one of them is a forgery.",
            "A sudden change in the IP a hostname resolves to, especially to a cheap VPS range.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "What stops trivial DNS spoofing today?",
          options: [
            "Longer DNS names",
            "Random source port and random query ID",
            "TCP for all queries",
            "IPv6 only",
          ],
          answer: 1,
          explain: "Source port + query ID randomisation massively increases the guesses the attacker must get right.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-attack-detect",
    title: "Lab: catch the flood",
    tone: "defense",
    briefing: [
      "Phase 1 — look at the capture: a SYN flood is hitting 10.0.0.20:80 while one real client also connects.",
      "Phase 2 — write a threshold rule for the flood that does not alert on the normal connection.",
      "Phase 3 — on the ARP capture, spot the spoof.",
    ],
    packets: [...synFlood, ...arpSpoof],
    ruleChallenge: {
      goal: "Alert on the SYN flood against 10.0.0.20:80 only — not on the completed connection from 10.0.0.12.",
      traffic: synFlood,
      starter:
        '# HOME_NET = 10.0.0.0/24\n# Hint: many SYNs to one destination from many sources.\n# Track by destination this time.\nalert tcp any any -> $HOME_NET 80 (msg:"Possible SYN flood"; flags:S; sid:1000020;)\n',
    },
    tasks: [
      {
        q: "How many unique source IPs are involved in the flood? (approximately)",
        answers: ["40"],
        hint: "Group by source IP in the packet list.",
      },
      {
        q: "What is the destination port under attack?",
        answers: ["80"],
        hint: "All flood packets target the same port on 10.0.0.20.",
      },
      {
        q: "In the ARP capture, which MAC is impersonating the gateway 10.0.0.1?",
        answers: ["aa:bb:cc:ff:ff:99"],
        hint: "The legitimate gateway MAC appears once; the attacker's MAC appears several times unsolicited.",
      },
    ],
  },
  ids: {
    name: "Flood & spoof rules",
    description:
      "Your IDS can now rate-limit SYNs per destination, detect gratuitous ARP floods, and flag inbound RFC1918 spoofing.",
    rules: [
      'alert tcp any any -> $HOME_NET any (msg:"IDS: SYN flood"; flags:S; threshold: type threshold, track by_dst, count 25, seconds 2; sid:9004001;)',
      'alert ip [192.168.0.0/16,172.16.0.0/12] any -> $HOME_NET any (msg:"IDS: Inbound RFC1918 source (spoofed)"; sid:9004002;)',
    ],
  },
};

export { arpSpoof };
export default unit4;
