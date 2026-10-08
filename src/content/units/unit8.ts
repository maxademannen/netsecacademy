import type { Unit } from "../types";

const unit8: Unit = {
  id: "bounty-craft",
  index: 8,
  title: "Bug Bounty Craft",
  tagline: "Turn findings into paid reports — and don't get banned.",
  tone: "defense",
  lessons: [
    {
      id: "picking-programs",
      title: "Picking programs",
      summary: "Where to hunt and how to not waste a weekend.",
      cards: [
        {
          title: "The platforms",
          body: [
            "HackerOne, Bugcrowd, Intigriti, YesWeHack — managed platforms with triage, payouts and reputation.",
            "Independent programs (direct on company websites) — often less competition, slower payouts, policies vary.",
            "Government disclosure programs (US VDP, UK NCSC, EU) — no money, but useful CVEs and recognition.",
          ],
        },
        {
          title: "Signals of a good program",
          body: [
            "- Wide scope (`*.example.com`) and recent additions = less picked-over.",
            "- Mean response time under a week = active triage team.",
            "- Public hall-of-fame or published bounty amounts = real payouts.",
            "- Clear safe-harbour clause.",
            "- Few 'everyone found this already' known-issues.",
          ],
        },
        {
          title: "Signals of a trap",
          body: [
            "- 'Thanks letter only' with 500+ hunters already registered — your effort funds their security for free.",
            "- Scope that excludes everything interesting ('out of scope: all subdomains').",
            "- Triage times measured in months.",
            "- Public reviews on Twitter / disclose.io say 'they always downgrade severity'.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A program says 'automated scanners are strictly forbidden'. Running nuclei with 50 templates against the whole scope is…",
          options: ["Fine", "A policy violation; expect a ban and a rejected report", "A certification requirement", "Encouraged"],
          answer: 1,
          explain: "Read the policy word-for-word. 'Automated scanners' includes nuclei, dastardly, sqlmap bursts, feroxbuster at high threads.",
        },
      ],
    },
    {
      id: "cvss",
      title: "Severity: CVSS, briefly",
      summary: "Enough to argue your rating without faking it.",
      cards: [
        {
          title: "The vectors that move the number",
          body: [
            "Attack Vector — Network (0.85) > Adjacent > Local > Physical.",
            "Attack Complexity — Low vs High. 'Needs victim to click, during office hours, with cookies set' = High.",
            "Privileges Required — None > Low > High. 'No login required' is the big multiplier.",
            "User Interaction — None > Required.",
            "Scope — Changed (bug impacts things beyond its own component) is a huge boost.",
            "Confidentiality / Integrity / Availability — High > Low > None.",
          ],
        },
        {
          title: "Mapping bug classes to typical scores",
          body: [
            "Reflected XSS: 6.1 Medium (needs victim click).",
            "Stored XSS visible to admins: 8.0+ High.",
            "IDOR to read own-tenant: 4-5 Medium.",
            "IDOR to read other tenants: 7-8 High.",
            "SQLi (any): 9+ Critical.",
            "SSRF to IMDS with role: 9+ Critical.",
            "RCE (unauthenticated): 10 Critical.",
          ],
        },
        {
          title: "Don't fight impossible fights",
          body: [
            "Programs have in-house SLAs. If they rate stored XSS as 6.5 Medium always, writing 'this should be 9' never works — the policy is the policy.",
            "What works: provide extra impact (cookie stealing, admin takeover demo on a test account) that justifies the next tier.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A reflected XSS on a logged-out marketing page. Realistic severity?",
          options: ["Critical", "Low to Medium (6.1 is the usual ceiling)", "Informational", "High always"],
          answer: 1,
          explain: "No session to steal, no sensitive data, needs the victim to click. 6.1 is CVSS's default for reflected XSS.",
        },
      ],
    },
    {
      id: "report-writing",
      title: "Writing the report",
      summary: "The single skill that separates $100 and $5 000 for the same bug.",
      cards: [
        {
          title: "Structure that triagers love",
          body: [
            "1. Title — exact bug class + endpoint. 'Reflected XSS in /search q parameter'.",
            "2. Summary — two sentences a manager can read.",
            "3. Steps to Reproduce — numbered, copy-paste exact. Full requests. Everything a triager needs with no questions.",
            "4. Proof of Concept — screenshots, cURL, short video for complex flows.",
            "5. Impact — what an attacker can achieve, in plain English.",
            "6. Suggested fix — one short paragraph. Even a wrong suggestion shows you understand the bug.",
            "7. Timeline — when you found it.",
          ],
        },
        {
          title: "Example skeleton",
          body: ["Save it, reuse it, fill it in."],
          code: `# Reflected XSS in /search \`q\` parameter

## Summary
The /search endpoint reflects the \`q\` parameter into the HTML response without
HTML encoding. Any attacker-controlled URL with a crafted payload runs JavaScript
in the context of https://shop.example.

## Steps to reproduce
1. Open https://shop.example/search?q=<svg%20onload=alert(1)>
2. Observe the alert fire.

## Full request
GET /search?q=<svg%20onload=alert(1)> HTTP/1.1
Host: shop.example
...

## Impact
Attacker-controlled JavaScript executes under shop.example. With the current
cookie flags (session is NOT HttpOnly on this origin), the attacker can read
the victim's session cookie, perform state-changing actions as the victim,
and persist the attack via /comments where the input is also stored (separate
report filed).

## Suggested fix
HTML-encode user input before echoing (<code>htmlspecialchars($q, ENT_QUOTES)</code>
for PHP). Set HttpOnly, Secure and SameSite=Lax on the session cookie.

## Timeline
2026-10-08  Found and reported.`,
          tone: "defense",
        },
        {
          title: "The 10 things triagers hate",
          body: [
            "- 'theoretical' bugs with no PoC.",
            "- 'I think there might be XSS somewhere' without a URL.",
            "- massive dumps of real user data.",
            "- out-of-scope reports.",
            "- duplicate reports (search their disclosure history first).",
            "- 'self-XSS' reported as critical.",
            "- CSRF on logout.",
            "- missing security headers in isolation (unless chained).",
            "- rate limiting absence 'alone'.",
            "- raw tool output pasted as a report.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "order",
          q: "Order the sections of a good report, top to bottom.",
          items: ["Title", "Summary", "Steps to reproduce", "Proof of concept", "Impact", "Suggested fix"],
          explain: "Title → summary → reproduce → PoC → impact → fix. Any triager can scan this in 60 seconds.",
        },
        {
          type: "mc",
          q: "Which of these is almost always reported-as-informational / closed?",
          options: [
            "SQLi on a login form",
            "'Missing X-Content-Type-Options header' on a static site, alone",
            "Stored XSS in profile bio",
            "SSRF with IMDS response",
          ],
          answer: 1,
          explain: "Missing security headers on their own aren't impactful. Chain them into something or skip.",
        },
      ],
    },
    {
      id: "ethics",
      title: "Ethics, pacing, and the long game",
      summary: "A career in bounty is years long; act accordingly.",
      cards: [
        {
          title: "The two commandments",
          body: [
            "1. Stay in scope. Always.",
            "2. Prove impact with the minimum necessary data. Always.",
            "Everything else — ratings, triage disputes, duplicates — is forgivable. These two are not.",
          ],
          tone: "defense",
        },
        {
          title: "On consent",
          body: [
            "If a bug would let you read someone else's data (IDOR, SSRF, SQLi), prove it with your own second account or with harmless probes (version(), hostname).",
            "Do NOT iterate 1..10000 to find real victims. Do NOT read other users' chat messages, invoices, or health records. That is a crime, bounty or no bounty.",
          ],
        },
        {
          title: "Health, pacing, duplicates",
          body: [
            "The hunters who last don't marathon — they build a repeatable 2–4 hour daily rhythm: recon pass, review notes, pick one target, write one report.",
            "Duplicates sting. Shake them off; keep hunting. The win rate smooths out over months, not days.",
            "Celebrate small wins. A clean $150 bug today beats a mythical $10 000 that never materialises.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You find an IDOR that lets you read other users' private messages. You test it on your two accounts. For the report, you should include:",
          options: [
            "A dump of 500 real users' messages as 'proof'",
            "Only the two-account PoC — never read real user data",
            "A video of a real user's inbox",
            "Nothing, just a description",
          ],
          answer: 1,
          explain: "Two-account PoC is sufficient proof. Reading real users' private data turns a legal bounty into unauthorised access.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-report",
    title: "Report-writing drill",
    tone: "defense",
    briefing: [
      "You found a stored XSS in /comments (unit 5). Walk through the report checklist.",
      "This lab is a thought exercise — the questions test that you know what belongs in a good report.",
    ],
    tasks: [
      {
        q: "What should the title of the report say? (template: <bug class> in <endpoint>)",
        answers: ["stored xss in /comments", "stored xss in comments", "stored xss in /comments post", "stored xss in /comments endpoint"],
        hint: "Bug class + endpoint. No fluff.",
      },
      {
        q: "What CVSS vector pushes a stored XSS higher than reflected XSS? (one word)",
        answers: ["persistence", "stored", "no interaction", "ui-none", "ui:n"],
        hint: "Stored XSS fires without the victim clicking a crafted link.",
      },
      {
        q: "What is the minimum necessary PoC payload? (one HTML tag; e.g. &lt;svg...&gt; or similar)",
        answers: ["<svg onload=alert(1)>", "svg onload=alert(1)", "<img src=x onerror=alert(1)>", "<script>alert(1)</script>", "alert(1)"],
        hint: "Just enough to prove execution.",
      },
      {
        q: "Which section of the report explains what an attacker could achieve beyond `alert(1)`?",
        answers: ["impact", "impact section"],
        hint: "The 'Impact' section — think account takeover, session theft via document.cookie.",
      },
    ],
  },
  ids: {
    name: "Report craft",
    description:
      "You can pick programs, score severity realistically, write triager-friendly reports, and hunt sustainably without crossing legal lines.",
    rules: [],
  },
};

export default unit8;
