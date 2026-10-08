import type { Unit } from "../types";
import { webTraffic } from "./unit5";

const unit7: Unit = {
  id: "signatures",
  index: 7,
  title: "Signature Detection",
  tagline: "The rule syntax your IDS speaks.",
  tone: "defense",
  lessons: [
    {
      id: "rule-anatomy",
      title: "Anatomy of a rule",
      summary: "Header, options, SID — the three things every rule has.",
      cards: [
        {
          title: "The header",
          body: ["action proto src sport -> dst dport. This decides which packets even reach the options stage."],
          code: `alert tcp $EXTERNAL_NET any -> $HOME_NET 80
  action: alert | drop | log | pass
  proto : tcp | udp | icmp | ip
  dir   : -> (one way)  <> (either way)`,
        },
        {
          title: "The options",
          body: ["Everything inside the parentheses. Order matters for performance (fast matches first) but not for correctness."],
          code: `(msg:"Readable name";
 content:"UNION SELECT"; nocase;
 flags:S;
 dsize:>500;
 threshold: type threshold, track by_src, count 10, seconds 5;
 sid:1000050; rev:1;)`,
        },
        {
          title: "SIDs and revisions",
          body: [
            "Every rule needs a unique sid. Local rules conventionally use sid >= 1000000.",
            "rev goes up every time you edit the rule; SIEMs join on sid+rev to show which version fired.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Which option limits an alert to large packets only?",
          options: ["dsize", "flags", "nocase", "threshold"],
          answer: 0,
          explain: "dsize:>500 matches payloads larger than 500 bytes. Useful for data-exfiltration rules.",
        },
        {
          type: "fill",
          q: "What direction operator means 'either direction'?",
          answers: ["<>"],
          explain: "<>, as opposed to -> for one-way.",
        },
      ],
    },
    {
      id: "tuning",
      title: "Tuning",
      summary: "Making rules fire on attacks and nothing else.",
      cards: [
        {
          title: "False positives are the enemy",
          body: [
            "A noisy rule gets disabled; a disabled rule catches nothing. Precision beats recall at scale.",
            "Measure every new rule on a week of normal traffic before trusting it.",
          ],
          tone: "defense",
        },
        {
          title: "Techniques",
          body: [
            "Narrow the destination (specific server, not any).",
            "Add dsize to exclude the empty keepalives that trigger generic content rules.",
            "Use threshold/detection_filter to require repetition.",
            "Pair with a `pass` rule to exempt a known-noisy source you cannot change.",
          ],
          code: `pass tcp 10.0.0.50 any -> $HOME_NET any (msg:"backup server, ignore"; sid:999999;)`,
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A rule fires 400 times a day on a known-safe backup job you cannot change. What is the right fix?",
          options: ["Delete the rule", "Add a `pass` rule for that source", "Mute the alert in the SIEM", "Lower the threshold"],
          answer: 1,
          explain: "A pass rule keeps the detection logic in one place and documents the exception.",
        },
        {
          type: "rule",
          q: "Tune the brute-force rule from the web lab so it only alerts on at least 10 attempts in 10 seconds.",
          traffic: webTraffic,
          starter:
            'alert tcp any any -> $HOME_NET 80 (msg:"Brute /login"; content:"POST /login"; threshold: type threshold, track by_src, count 10, seconds 10; sid:1000060;)\n',
          explain: "count 10 / seconds 10 matches the burst in the capture while a single real POST would not.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-rules",
    title: "Lab: write a rule pack",
    tone: "defense",
    briefing: [
      "Here is the mixed traffic from the web lab again — SQLi, XSS, brute force, beacon.",
      "Write a complete rule pack. Zero misses, zero false positives.",
    ],
    ruleChallenge: {
      goal: "Catch sqli, xss, brute and c2. Zero false positives on the two normal page views.",
      traffic: webTraffic,
      starter:
        'alert tcp any any -> $HOME_NET 80 (msg:"SQLi"; content:"UNION SELECT"; nocase; sid:1000070;)\nalert tcp any any -> $HOME_NET 80 (msg:"XSS"; content:"<script"; nocase; sid:1000071;)\nalert tcp any any -> $HOME_NET 80 (msg:"Brute"; content:"POST /login"; threshold: type threshold, track by_src, count 10, seconds 10; sid:1000072;)\nalert tcp $HOME_NET any -> any 80 (msg:"Beacon"; content:"Host: cdn.evil.io"; sid:1000073;)\n',
    },
    packets: webTraffic,
    tasks: [
      { q: "How many distinct attack incidents must your rule pack catch?", answers: ["4", "four"], hint: "sqli, xss, brute, c2." },
      { q: "What is the maximum acceptable false-positive count?", answers: ["0", "zero", "none"], hint: "Discipline." },
    ],
  },
  ids: {
    name: "Rule engine",
    description: "Your IDS now runs a full signature engine with content, flags, dsize, pcre and threshold options.",
    rules: [],
  },
};

export default unit7;
