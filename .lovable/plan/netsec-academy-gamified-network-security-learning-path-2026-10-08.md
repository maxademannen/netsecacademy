# NetSec Academy — gamified network security learning path

A Duolingo-style site that takes learners from networking basics to building their own Intrusion Detection System (IDS). Offensive topics are included throughout ("break it, then defend it").

## Curriculum (complete, 8 units, about 40 lessons)

Each unit has: theory lessons, a quiz, a simulated lab, an offense-then-defense pair, a unit test, and a **capstone step** that adds a piece to the learner's own IDS.

```text
1 Networking Foundations   OSI/TCP-IP, IP/subnets, TCP/UDP, DNS, HTTP      -> IDS: packet model
2 Packet Analysis          capture, headers, Wireshark-style reading       -> IDS: packet parser
3 Recon & Scanning (off.)  nmap concepts, port scans, fingerprinting       -> IDS: scan detector
4 Network Attacks (off.)   ARP spoofing, MITM, DoS/SYN flood, DNS spoof    -> IDS: flood/spoof rules
5 Web & App Attacks (off.) SQLi, XSS, brute force, C2 traffic patterns     -> IDS: payload signatures
6 Defensive Architecture   firewalls, segmentation, VPN/TLS, logging       -> IDS: alerting + logs
7 Signature Detection      Snort/Suricata rule syntax, tuning, FPs         -> IDS: rule engine
8 Anomaly Detection        baselines, statistics, flow features, basic ML  -> IDS: anomaly module
Final: assemble and test your IDS against a mixed attack traffic replay
```

## Learner experience

- **Skill tree home** with locked/unlocked nodes, progress rings per unit.
- **Lessons** as short swipeable cards with diagrams, then inline checks.
- **Exercise types:** multiple choice, fill-the-blank, order-the-steps (e.g. TCP handshake), match pairs, packet-field identification, write-a-rule.
- **Simulated labs (in browser, safe):**
  - Fake terminal with scripted commands (scan, ping, dig, tcpdump-like output).
  - Packet viewer: list + header breakdown + hex, on sample captures.
  - Rule sandbox: write Snort-style rules, run them against sample traffic, see hits/misses/false positives.
  - Attack scenario replays: watch an attack happen, then detect it.
- **IDS Workbench:** the capstone page showing the learner's IDS as modules that light up as units are completed, with a test run against traffic.
- **Gamification:** XP, daily streak, hearts (lose on mistakes, refill over time), levels, badges, weekly leaderboard.
- **Unit tests** gate unlocking the next unit (pass mark 80%).

## Accounts

Email sign-in with a profile (username, avatar, XP, streak). Progress, quiz results, lab completions and badges save to the account.

## Visual direction

Before building, I will show 3 rendered design directions to choose from.

## Technical details

- Lovable Cloud: auth (email/password), tables `profiles`, `lesson_progress`, `quiz_attempts`, `lab_completions`, `badges`, `user_badges`, `user_roles`; RLS scoped to `auth.uid()`; leaderboard via a security-definer view exposing only username + weekly XP.
- Course content lives as typed TS data files (`src/content/units/*.ts`) — versioned with code, no CMS needed. Labs are data-driven: scripted terminal responses, sample packet JSON, and a small rule-matching engine (subset of Snort syntax: action, proto, ports, `content`, `flags`, `threshold`).
- Routes: `/` landing, `/auth`, `/_authenticated/learn` (skill tree), `/learn/$unit/$lesson`, `/lab/$labId`, `/test/$unit`, `/ids` (workbench), `/leaderboard`, `/profile`.
- XP/streak/hearts updated through authenticated server functions so values can't be edited client-side.
- Build order: design pick, Cloud + auth + schema, engine (exercise types, labs), then write all 8 units of content, then gamification + leaderboard.
