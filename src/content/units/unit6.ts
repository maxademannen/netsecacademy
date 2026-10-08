import type { Unit } from "../types";

const unit6: Unit = {
  id: "defense",
  index: 6,
  title: "Defensive Architecture",
  tagline: "Firewalls, segmentation, logging — where your IDS fits.",
  tone: "defense",
  lessons: [
    {
      id: "firewalls",
      title: "Stateful firewalls",
      summary: "Why direction and state matter more than ports.",
      cards: [
        {
          title: "Stateless vs stateful",
          body: [
            "A stateless filter inspects each packet alone. It must allow both outbound SYNs and inbound SYN-ACKs explicitly, which is a mess.",
            "A stateful firewall tracks each flow: once an outbound SYN is permitted, the matching inbound reply is allowed automatically.",
          ],
          code: `# Simplified ruleset
allow out tcp any -> any 443  track-state
deny in  tcp any -> any  any
# Replies to the outbound 443 session are allowed by state`,
        },
        {
          title: "Zones and default deny",
          body: [
            "Interfaces are grouped into trust zones (DMZ, internal, management, guest).",
            "The only workable default is deny; every allowed flow should have a documented reason.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Why is default-deny the only sustainable firewall posture?",
          options: [
            "It is faster",
            "You cannot enumerate every bad thing, but you can enumerate what you need to allow",
            "Vendors require it",
            "It uses less memory",
          ],
          answer: 1,
          explain: "Allow-lists are finite; block-lists are infinite.",
        },
      ],
    },
    {
      id: "segmentation",
      title: "Segmentation",
      summary: "Containing a breach with VLANs and microsegments.",
      cards: [
        {
          title: "Blast radius",
          body: [
            "If one workstation is compromised and your network is flat, the attacker can reach every other workstation and server.",
            "Segmentation ensures that the first compromised host can only reach the few things that host actually needs.",
          ],
        },
        {
          title: "East-west vs north-south",
          body: [
            "North-south is traffic crossing the perimeter. North-south detection is where most sensors live.",
            "East-west is traffic between internal hosts. It is where lateral movement happens, and it is historically under-monitored.",
            "Your IDS should see both.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Match direction to purpose.",
          pairs: [
            ["North-south", "Perimeter: outside-in and inside-out"],
            ["East-west", "Lateral movement between internal hosts"],
          ],
          explain: "Lateral movement is the step that turns a foothold into a breach.",
        },
      ],
    },
    {
      id: "logging",
      title: "Logging and alerting",
      summary: "An alert nobody reads is just a disk cost.",
      cards: [
        {
          title: "The alert pyramid",
          body: [
            "Thousands of events → hundreds of correlated events → tens of alerts → one or two incidents per shift.",
            "Each layer collapses by at least 10x, or your analysts drown.",
          ],
        },
        {
          title: "What a good alert carries",
          body: [
            "A timestamp. The five-tuple. The rule SID and message. The matched payload snippet. A link to the raw capture.",
            "Without context, the on-call engineer has to redo your work from scratch at 02:00.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "The quickest way to kill a SOC is to:",
          options: [
            "Buy a bigger SIEM",
            "Deliver 100 000 raw alerts a day with no correlation or priority",
            "Enable TLS inspection",
            "Hire too many analysts",
          ],
          answer: 1,
          explain: "Alert fatigue is the actual root cause of most 'the alert was there, nobody noticed' postmortems.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-firewall",
    title: "Lab: write a default-deny policy",
    tone: "defense",
    briefing: [
      "You are protecting the shop server 10.0.0.20. It must expose HTTP (80) and HTTPS (443) to the internet, and SSH (22) only to admin workstation 10.0.0.9.",
      "Nothing else. Everything your IDS sees that the firewall should have stopped is a potential incident.",
      "This lab is a thought exercise — answer the questions below from the policy.",
    ],
    tasks: [
      {
        q: "Which inbound TCP ports to 10.0.0.20 should be permitted from the internet?",
        answers: ["80,443", "80, 443", "80 and 443", "http,https"],
        hint: "Only the web ports.",
      },
      {
        q: "Which single internal IP should reach 10.0.0.20 on port 22?",
        answers: ["10.0.0.9"],
        hint: "The admin workstation.",
      },
      {
        q: "What default action should the policy end with?",
        answers: ["deny", "drop", "deny all", "default deny"],
        hint: "If no rule matches, what happens?",
      },
    ],
  },
  ids: {
    name: "Alerting & logs",
    description:
      "Your IDS now writes structured alerts (timestamp, 5-tuple, SID, message, snippet) and feeds a dashboard.",
    rules: [],
  },
};

export default unit6;
