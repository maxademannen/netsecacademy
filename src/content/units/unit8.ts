import type { Unit } from "../types";

const baseline = Array.from({ length: 60 }, (_, i) => 20 + Math.round(5 * Math.sin(i / 4)));
const anomalySeries = [...baseline];
[30, 31, 32, 33, 34].forEach((i) => (anomalySeries[i] = 180 + i));

const unit8: Unit = {
  id: "anomaly",
  index: 8,
  title: "Anomaly Detection",
  tagline: "When the attacker's packets look fine, but their behaviour does not.",
  tone: "defense",
  lessons: [
    {
      id: "baselines",
      title: "Baselines",
      summary: "You cannot detect 'unusual' without defining 'usual' first.",
      cards: [
        {
          title: "What to baseline",
          body: [
            "Flow volume per hour. Unique destinations per host per day. DNS query count per client. Login failure rate per account.",
            "Baselines are per-entity and per-time-of-day. 'A lot of traffic at 03:00' is not the same signal as 'a lot of traffic at 10:00'.",
          ],
        },
        {
          title: "The simplest useful statistic",
          body: [
            "Mean + k * standard deviation, computed over a rolling window. Anything above that threshold is an anomaly to investigate.",
            "k = 3 catches the obvious. k = 6 catches almost nothing but is close to false-positive-free.",
          ],
          tone: "defense",
          code: `window = last 24 hours of request counts per minute
mean   = average
stdev  = population standard deviation
threshold = mean + 3 * stdev
alert when current > threshold for 5 consecutive minutes`,
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Why 'for 5 consecutive minutes'?",
          options: ["Analysts need coffee time", "To suppress single-minute spikes that are usually noise", "To conserve CPU", "SIEMs require it"],
          answer: 1,
          explain: "Persistence is cheap evidence that the deviation is real, not a one-off blip.",
        },
      ],
    },
    {
      id: "flow-features",
      title: "Flow features",
      summary: "What machine learning for IDS actually uses.",
      cards: [
        {
          title: "Features, not packets",
          body: [
            "ML in detection almost never looks at raw bytes. It looks at engineered features per flow or per host-pair over a window:",
            "duration, packet count, byte count, mean packet size, SYN:ACK ratio, entropy of destination ports, periodicity, time-of-day.",
            "A classifier trained on normal vs known-bad flows learns what 'suspicious shape' means for your network.",
          ],
          tone: "defense",
        },
        {
          title: "When ML helps and when it does not",
          body: [
            "Helps: periodic beacons, data exfiltration volumes, DGA domain names, unusual peer sets.",
            "Does not help: zero-day exploits with no behavioural footprint. There rules + patching still win.",
          ],
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Match the attack to the feature that reveals it.",
          pairs: [
            ["C2 beacon", "Low variance of inter-arrival time"],
            ["Data exfil", "Large outbound bytes to a new destination"],
            ["DGA domains", "High character-level entropy of queried names"],
            ["Port scan", "Many distinct destination ports per source"],
          ],
          explain: "Pick the feature so a chart would show a human the same anomaly a model learns.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-anomaly",
    title: "Lab: find the spike",
    tone: "defense",
    briefing: [
      "60 minutes of request-rate samples from the shop server. Normal volume is around 20/minute with mild cyclical variation.",
      "A short burst in the middle looks nothing like the baseline. Compute mean + 3*stdev over the whole series and flag any minute above it.",
      "The chart on the right is live. Numbers you type are checked against the series above.",
    ],
    anomaly: {
      goal: "Flag the attack window using a 3-sigma rule.",
      series: anomalySeries,
      attackIdx: [30, 31, 32, 33, 34],
      unit: "req/min",
    },
    tasks: [
      {
        q: "At which minute index does the burst START? (first anomalous sample)",
        answers: ["30"],
        hint: "Scroll the chart until the line jumps.",
      },
      {
        q: "How many consecutive minutes exceed the baseline?",
        answers: ["5"],
        hint: "The burst is contiguous.",
      },
      {
        q: "Approximate normal baseline in req/min (round to nearest 5)?",
        answers: ["20"],
        hint: "The quiet band hovers around twenty.",
      },
    ],
  },
  ids: {
    name: "Anomaly module",
    description:
      "Your IDS now computes rolling mean + 3*stdev per host, extracts flow features and flags beacons and volume spikes.",
    rules: [
      'alert udp $HOME_NET any -> any 53 (msg:"IDS: High-entropy DNS label (tunnel/DGA)"; pcre:"/QUERY A [a-z0-9]{18,}\\./"; sid:9008001;)',
      'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"IDS: Periodic beacon"; content:"GET /checkin"; threshold: type threshold, track by_src, count 3, seconds 100; sid:9008002;)',
    ],
  },
};

export default unit8;
