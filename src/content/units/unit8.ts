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
      summary: "Where to hunt, how to read the rules, and how to not waste a weekend.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can read a bug bounty program's policy end-to-end, correctly classify any given asset as in-scope or out-of-scope, and decide in under five minutes whether the program is worth your limited hunting time.",
          ],
        },
        {
          title: "A map someone else drew",
          kind: "intuition",
          body: [
            "A bug bounty program is permission to search a specific, bounded area for a reward — like a treasure hunt where the landowner has drawn the search boundary on a map and published the rules of engagement.",
            "The map is the 'scope': the exact list of domains, apps and IP ranges you're allowed to touch. The rulebook is the 'policy': what methods are allowed (manual testing? automated scanners? social engineering?) and what you get paid for.",
            "Where the analogy breaks: a real map is visual and forgiving — being one metre off the boundary line is usually fine. A scope list is not forgiving. `shop.example.com` and `dev.shop.example.com` look almost identical, but one may be in-scope and the other explicitly excluded. Programs treat exact strings, not vibes.",
          ],
        },
        {
          title: "Refresher: domains, subdomains, wildcards",
          kind: "prereq",
          body: [
            "A domain is a name like `example.com`. A subdomain adds a label in front of it, separated by a dot: `shop.example.com`, `dev.shop.example.com`, `api.example.com` are all subdomains of `example.com`.",
            "A wildcard scope entry like `*.example.com` means 'every direct subdomain of example.com' — `shop.example.com` matches, but by itself it does NOT automatically include `dev.shop.example.com` (that's a subdomain of a subdomain) unless the policy says so explicitly.",
            "If you haven't done DNS recon yet, the short version: subdomains are usually separate servers, sometimes run by different teams with different security postures. That's exactly why programs scope them individually instead of trusting 'it's the same company so it must be fine'.",
          ],
        },
        {
          title: "The platforms",
          kind: "explain",
          body: [
            "HackerOne, Bugcrowd, Intigriti, YesWeHack — managed platforms that provide triage, payouts and a public reputation score.",
            "Independent programs (hosted directly on a company's own website) — often less competition, but slower payouts and policies that vary wildly in clarity.",
            "Government and public-interest disclosure programs (US VDP, UK NCSC, EU programs) — usually no money, but recognition and sometimes a CVE credit.",
          ],
        },
        {
          title: "Reading a scope table",
          kind: "explain",
          body: [
            "Most policies publish scope as a table: asset, asset type, and eligibility. Read every row — do not skim.",
            "Key terms: 'In scope' = you may test it and it is bounty-eligible. 'Out of scope' = do not test it at all (some programs mean 'no permission', others mean 'permission but no money' — the policy text tells you which). 'Eligible for triage only' = you can report it but it won't pay.",
          ],
          code: `Example scope table (documentation domain used for teaching)

Asset                        Type        Eligibility
----------------------------------------------------
*.example.com                Wildcard    In scope, bounty eligible
api.example.com              Domain      In scope, bounty eligible
dev.example.com              Domain      OUT OF SCOPE (explicitly excluded)
203.0.113.0/24                IP range    In scope, bounty eligible
blog.example.com              Domain      In scope, triage only (no bounty)
Third-party services (Stripe, Google Analytics)   OUT OF SCOPE`,
          check: {
            type: "mc",
            q: "Using the scope table above, is `dev.example.com` covered by the `*.example.com` wildcard entry?",
            options: [
              "Yes — wildcards always cover every subdomain, no exceptions",
              "No — it is listed as a separate row and explicitly excluded, which overrides the wildcard",
              "Only if you find a critical bug there",
              "Only during business hours",
            ],
            answer: 1,
            why: [
              "A more specific, explicit row always overrides a general wildcard — that's the whole reason programs list exclusions separately.",
              "Correct — explicit exclusions win over wildcards. Read every row, not just the wildcard line.",
              "Severity never changes whether an asset is in scope.",
              "Scope isn't time-based; it's asset-based.",
            ],
            explain: "Specific exclusions always override a wildcard. If a program wanted `dev.example.com` included, it wouldn't need its own row at all — the fact that it has one, marked OUT OF SCOPE, is the program telling you explicitly: skip this one.",
            hints: ["Look for the most specific rule that mentions the asset by name.", "Why would the policy list `dev.example.com` separately if the wildcard already covered it?"],
          },
        },
        {
          title: "Signals of a good program vs. a trap",
          kind: "explain",
          body: [
            "Good signs: wide, recently-updated scope (less picked-over); mean triage response under a week; a public hall-of-fame or published bounty table; a clear safe-harbour clause protecting good-faith researchers.",
            "Trap signs: 'thank-you-letter only' rewards with hundreds of hunters already registered (your work secures them for free); a scope that excludes everything interesting ('all subdomains out of scope'); multi-month triage times; public reviews saying severities always get downgraded.",
          ],
          tone: "defense",
        },
        {
          title: "Worked example: classifying five assets",
          kind: "example",
          body: [
            "Policy excerpt: In scope — `*.example.com` (web apps only), `203.0.113.0/24`. Out of scope — `dev.example.com`, any subdomain hosted on third-party SaaS (e.g. `status.example.com` on StatusPage), denial-of-service testing, automated scanners without prior approval.",
            "Asset 1: `shop.example.com` — matches the `*.example.com` wildcard, is a web app, not separately excluded. → IN SCOPE.",
            "Asset 2: `dev.example.com` — matches the wildcard textually, but has its own exclusion row. Explicit exclusion wins. → OUT OF SCOPE.",
            "Asset 3: `status.example.com`, hosted on StatusPage (third-party SaaS) — matches the wildcard textually, but the policy excludes third-party-hosted subdomains regardless of naming. → OUT OF SCOPE.",
            "Asset 4: `203.0.113.42` — falls inside `203.0.113.0/24` (this is exactly the subnet-membership check from the networking unit: the address's first 24 bits match the range's first 24 bits). → IN SCOPE.",
            "Asset 5: running `nuclei -t cves/ -u shop.example.com` with 300 templates — shop.example.com is in scope, but the *method* (unapproved automated scanning) is explicitly banned by the policy. Scope covers the target; the policy covers what you're allowed to do to it. Both must be satisfied. → POLICY VIOLATION even though the asset is in scope.",
          ],
          check: {
            type: "fill",
            q: "Using the same policy excerpt, is testing `203.0.113.200` in scope? Answer 'yes' or 'no'.",
            answers: ["yes"],
            explain: "203.0.113.200 falls inside 203.0.113.0/24 (addresses .0–.255 all share the first three octets), and that range is explicitly listed as in scope.",
            hints: ["Check whether .200 falls within the /24 range listed in scope.", "A /24 covers all 256 addresses sharing the first three octets."],
          },
        },
        {
          title: "Common scope-reading mistakes",
          kind: "mistakes",
          body: [
            "Assuming a wildcard overrides a listed exclusion — it never does; specific rules beat general ones.",
            "Assuming 'in scope' for a domain means every testing *method* is allowed — scope (where) and policy (how) are separate checks, and both must pass.",
            "Testing a look-alike asset because it 'should probably be the same team' — if it's not listed, it's not covered, and you have no authorisation.",
            "Skipping the policy's prose sections and only reading the scope table — exclusions like 'no automated scanning' or 'no social engineering' are often written as paragraphs, not table rows.",
          ],
        },
        {
          title: "Practice: is this in scope?",
          kind: "practice",
          body: [
            "Policy: In scope — `*.api.example.net`. Out of scope — any endpoint requiring a paid enterprise account, load/stress testing, subdomains not directly under api.example.net.",
            "Asset under test: `billing.api.example.net`, reachable with a free-tier test account you created yourself.",
          ],
          check: {
            type: "mc",
            q: "Is testing `billing.api.example.net` with your free-tier test account in scope?",
            options: [
              "No, because billing-related endpoints are always excluded",
              "Yes — it matches the wildcard, is a direct subdomain, and you're not using a paid account",
              "No, because wildcards never include anything",
              "Only if you ask on Twitter first",
            ],
            answer: 1,
            why: [
              "The policy doesn't exclude billing by name — only paid-account-gated endpoints and load testing are excluded.",
              "Correct: `billing.api.example.net` is a direct subdomain of `api.example.net`, matches the wildcard, and you're using a free-tier account, which the exclusion doesn't apply to.",
              "Wildcards do cover direct subdomains; that's their purpose.",
              "Social posting has no bearing on scope.",
            ],
            explain: "Matching the wildcard is necessary but check every exclusion individually too — here, none apply to your situation, so the asset is in scope.",
            hints: ["Check the wildcard first: is it a direct subdomain?", "Now check each exclusion one by one against your actual test setup."],
          },
        },
        {
          title: "Relevance: what scope literacy buys you",
          kind: "relevance",
          body: [
            "Reading scope and policy carefully proves one thing: that your testing was authorised, and your report will be considered. It does NOT prove you'll find a bug, and it does NOT guarantee a payout — that still depends on finding real impact and writing it up well (next lessons).",
            "Always re-check scope on your testing day. Programs update scope frequently; an asset in scope last month can be removed.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A program says 'automated scanners are strictly forbidden'. Running nuclei with 50 templates against the whole in-scope wildcard is…",
          options: ["Fine, since the target is in scope", "A policy violation — expect a rejected report, possibly a ban", "Required for a thorough test", "Allowed once per week"],
          answer: 1,
          why: [
            "In-scope target does not override an explicit method restriction — scope and policy are two separate checks.",
            "Correct. 'Automated scanners' includes nuclei, sqlmap bulk runs, feroxbuster at high thread counts — read the policy word for word.",
            "The opposite: it's explicitly banned by this policy.",
            "No policy grants a weekly automated-scanning allowance by default.",
          ],
          explain: "Being in scope only answers 'where'. The policy's prose answers 'how'. Both must be satisfied; this policy forbids the method regardless of target.",
          hints: ["Scope answers 'where'; policy prose answers 'how'.", "Does the ban on scanners mention any exception for in-scope targets?"],
          ref: "Worked example: classifying five assets",
        },
        {
          type: "fill",
          q: "Policy: in scope `*.shop.example`, out of scope `legacy.shop.example`. Is `legacy.shop.example` in scope? Answer 'yes' or 'no'.",
          answers: ["no"],
          explain: "An explicit exclusion always overrides a wildcard, even though `legacy.shop.example` textually matches `*.shop.example`.",
          hints: ["Compare the wildcard rule to the exclusion rule — which is more specific?", "Specific rules win over general ones."],
          ref: "Reading a scope table",
        },
        {
          type: "order",
          q: "Put these checks in the order you should actually perform them before testing a new target.",
          items: [
            "Read the full scope table, row by row",
            "Read the policy prose for method restrictions (scanners, DoS, social engineering)",
            "Confirm your specific target isn't covered by any exclusion",
            "Begin testing only the confirmed in-scope asset, using only allowed methods",
          ],
          explain: "Scope table first (where), then policy prose (how), then cross-check your specific target against exclusions, only then test.",
          hints: ["Where comes before how.", "Cross-checking your exact target is the last gate before you start."],
          ref: "Reading a scope table",
        },
        {
          type: "mc",
          q: "A program has a wide wildcard scope, a mean response time of 3 months, and public reviews saying 'critical bugs always get downgraded to low'. What should you conclude?",
          options: [
            "It's a great program because the scope is wide",
            "It's probably a trap: slow triage plus a reputation for downgrading severity means poor payouts regardless of bug quality",
            "You should report everything as critical to force a fair rating",
            "Scope width is the only signal that matters",
          ],
          answer: 1,
          why: [
            "Wide scope alone doesn't offset bad triage practices.",
            "Correct — a slow, severity-downgrading program wastes your time even on good findings.",
            "Triage teams set the final severity regardless of how you label it.",
            "Scope is one signal among several; triage speed and reputation matter just as much.",
          ],
          explain: "Multiple negative signals (slow response, downgrade reputation) outweigh a single positive one (wide scope). This is exactly the 'trap' pattern described in the lesson.",
          hints: ["Weigh all the signals together, not just one.", "What does a severity-downgrading reputation tell you about payout quality?"],
          ref: "Signals of a good program vs. a trap",
        },
      ],
    },
    {
      id: "cvss",
      title: "Severity: CVSS, with worked scoring",
      summary: "Understand the real formula well enough to argue a rating — without faking it.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can list the CVSS v3.1 base metrics, explain what each one measures, and compute a base score by hand for a given vulnerability description.",
          ],
        },
        {
          title: "Triage, like an emergency room",
          kind: "intuition",
          body: [
            "CVSS (Common Vulnerability Scoring System) is a standard way to answer: 'out of everything reported today, what do we fix first?' It's the same problem an ER does with patients — not everyone can be treated first, so you need a consistent scale.",
            "Where the analogy breaks: an ER nurse uses judgement and vitals. CVSS instead uses a fixed formula with fixed numeric weights for named metrics — the same inputs always produce the same output. That's the point: it removes 'but I feel like this is bad' from severity arguments.",
          ],
        },
        {
          title: "Prerequisite: what a 'vector' means here",
          kind: "prereq",
          body: [
            "A CVSS vector string looks like `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` — each letter pair is a metric and its chosen value. You'll build one of these for every bug you report.",
            "Think of it as filling in a multiple-choice form about the bug: how is it reached, how hard is it to pull off, does it need an account, does it need a victim to click, and what does it break (confidentiality/integrity/availability)?",
          ],
        },
        {
          title: "The metrics that move the number",
          kind: "explain",
          body: [
            "Attack Vector (AV) — how the attacker reaches the vulnerable component. Network (0.85, reachable over the internet) > Adjacent (0.62, same LAN) > Local (0.55, needs local access) > Physical (0.2, needs physical access to the device).",
            "Attack Complexity (AC) — how much the attacker depends on conditions outside their control. Low (0.77, reliably exploitable) vs High (0.44, needs a race condition, specific victim config, etc.).",
            "Privileges Required (PR) — does the attacker need an account first? None (0.85) > Low (0.62, a normal user account) > High (0.27, admin-level account already).",
            "User Interaction (UI) — does a victim have to do something (click a link, open a file)? None (0.85) vs Required (0.62).",
            "Scope (S) — Unchanged (the bug only affects the vulnerable component itself) vs Changed (the bug lets the attacker impact resources beyond the vulnerable component's own security authority, e.g. a browser sandbox escape). Scope Changed raises the final score noticeably.",
            "Confidentiality / Integrity / Availability (C/I/A) — what the bug breaks, each rated High (0.56, total loss) / Low (0.22, partial) / None (0).",
          ],
        },
        {
          title: "How the metrics combine into a score",
          kind: "explain",
          body: [
            "CVSS v3.1 combines the metrics in two groups, then adds them together.",
            "Exploitability = 8.22 × AV × AC × PR × UI — this captures 'how easy is this to pull off'.",
            "Impact Sub-Score (ISC) = 1 − [(1 − C)(1 − I)(1 − A)] — this captures 'how bad is it once it works'. (If Scope is Unchanged: Impact = 6.42 × ISC.)",
            "Base Score = round up to 1 decimal place of (Exploitability + Impact), capped at 10. If the impact sub-score is 0 (no C/I/A loss at all), the score is forced to 0 regardless of exploitability — an unexploitable-but-harmless bug, or a harmless-but-easy bug, both still score 0 if there's genuinely zero impact.",
            "You rarely need to compute this from scratch (calculators exist), but understanding the shape of the formula tells you WHY, e.g., removing the need for a victim click (UI:N vs UI:R) or removing the need for an account (PR:N vs PR:L) moves the score more than you'd guess from 'just one factor changing'.",
          ],
          check: {
            type: "mc",
            q: "Two otherwise identical bugs differ only in Privileges Required: Bug A is PR:N (no account needed), Bug B is PR:L (needs a logged-in user account). Which has the higher CVSS score?",
            options: ["Bug B, because having an account gives the attacker more power", "Bug A, because PR:N has a higher multiplier (0.85) feeding directly into Exploitability", "They're always equal", "It depends only on the Impact metrics, not PR"],
            answer: 1,
            why: [
              "PR measures a barrier to the attacker, not a power boost — lowering the barrier (PR:N) increases ease of exploitation, hence the score.",
              "Correct: PR:N (0.85) multiplies into Exploitability more favourably for the attacker than PR:L (0.62), so Bug A scores higher, all else equal.",
              "PR materially changes Exploitability, so scores differ.",
              "PR is one of the four metrics that make up Exploitability, so it does matter even with identical Impact.",
            ],
            explain: "Higher PR value = less privilege needed = easier to exploit = higher Exploitability sub-score = higher overall base score, holding everything else constant.",
            hints: ["PR:N means 'no account needed'; check which PR value is numerically larger.", "A larger multiplier feeding into Exploitability raises the final score."],
          },
        },
        {
          title: "Worked example: scoring a cross-tenant IDOR",
          kind: "example",
          body: [
            "Bug: an authenticated API endpoint `/invoices/{id}` returns any tenant's invoice if you guess their numeric ID — no authorisation check compares the invoice's owner to the logged-in user. You need a normal (non-admin) account to reach it; no victim interaction; it only leaks data (read), not writes, and doesn't crash anything.",
            "Step 1 — pick metrics: AV:N (reachable over the internet) = 0.85. AC:L (reliable, no race condition) = 0.77. PR:L (needs a normal account) = 0.62. UI:N (no victim click needed) = 0.85. Scope: Unchanged (the bug doesn't escalate beyond this API's own authority). C:H (any tenant's full invoice data exposed) = 0.56. I:N (no data is modified) = 0. A:N (nothing is taken down) = 0.",
            "Step 2 — Exploitability = 8.22 × 0.85 × 0.77 × 0.62 × 0.85 ≈ 2.84.",
            "Step 3 — Impact Sub-Score (ISC) = 1 − [(1−0.56)(1−0)(1−0)] = 1 − 0.44 = 0.56. Scope Unchanged, so Impact = 6.42 × 0.56 ≈ 3.60.",
            "Step 4 — Base Score = roundUp(Exploitability + Impact) = roundUp(2.84 + 3.60) = roundUp(6.43) = 6.5.",
            "Result: vector `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`, base score 6.5 — Medium, bordering High. That number is defensible because every input is traceable to a fact about the bug, not a feeling.",
          ],
          tone: "offense",
          code: `Score bands (CVSS v3.1):
0.0        None
0.1 - 3.9  Low
4.0 - 6.9  Medium
7.0 - 8.9  High
9.0 - 10.0 Critical`,
        },
        {
          title: "Mapping bug classes to typical scores — and the limits of doing so",
          kind: "explain",
          body: [
            "Reflected XSS: ~6.1 Medium (needs UI:R, a victim click). Stored XSS visible to all users or admins: 8.0+ High (UI:N, often Scope Changed if it pivots to admin takeover). SQL injection: usually 9+ Critical (data of every user, often writeable). SSRF reaching cloud metadata with a usable role: 9+ Critical. Unauthenticated RCE: 10 Critical.",
            "These are starting points from the typical shape of the bug, not guarantees — the same bug class scores differently depending on what it actually touches. Always compute the vector from the specific finding, not from the bug's name.",
          ],
        },
        {
          title: "Don't fight a program's fixed SLA",
          kind: "mistakes",
          body: [
            "Many programs have an internal severity table they apply uniformly (e.g. 'all reflected XSS = Medium, no exceptions'). Arguing 'this should be a 9' against a fixed policy almost never works — the policy is the policy, and the triager isn't personally deciding against you.",
            "What actually works: find and document extra impact that changes the *inputs* to the formula — e.g., showing the session cookie lacks HttpOnly (raises realistic Confidentiality impact), or chaining the bug into something with Scope Changed. New evidence moves the score; a complaint about the number doesn't.",
            "A separate, common mistake: treating CVSS score as equal to payout. CVSS measures technical severity only. The next lesson covers how business impact can push a payout up or down independently of the CVSS number.",
          ],
          tone: "defense",
        },
        {
          title: "Practice: score this bug",
          kind: "practice",
          body: [
            "Bug: a password-reset endpoint accepts any email address and, in the HTTP response, echoes back the newly-generated reset token in plaintext (meant only to be emailed). No login needed to hit the endpoint. No victim interaction required. An attacker can fully take over any account by requesting a reset for that account's email and reading the token straight from the response.",
          ],
          check: {
            type: "mc",
            q: "What is the most defensible Confidentiality/Integrity/Availability rating for this bug? (full account takeover of any user, no login needed)",
            options: ["C:N/I:N/A:N — nothing is actually broken", "C:H/I:H/A:N — attacker fully reads and modifies the victim's account data, but nothing is taken offline", "C:N/I:N/A:H — it only affects availability", "C:L/I:L/A:L — a little bit of everything"],
            answer: 1,
            why: [
              "Full account takeover is a severe confidentiality and integrity loss — this rating understates it badly.",
              "Correct: account takeover means the attacker can read all of the victim's data (C:H) and perform any action the victim could, including changing their data (I:H); nothing here crashes the service, so A:N.",
              "Availability isn't impacted at all here — no denial of service.",
              "This understates the severity; full takeover is High, not Low, on both axes.",
            ],
            explain: "Full account takeover means total loss of confidentiality (attacker reads everything the victim could) and integrity (attacker can perform any action the victim could, including destructive ones) with no impact on availability. Combined with AV:N/PR:N/UI:N (no account, no click needed), this scores in the Critical range.",
            hints: ["Account takeover means the attacker can both read AND act as the victim — which two metrics does that touch?", "Does anything here crash or take down the service? That's the Availability metric."],
          },
        },
        {
          title: "Relevance: what a CVSS score proves and what it doesn't",
          kind: "relevance",
          body: [
            "A correctly computed CVSS vector proves your severity claim is reproducible and defensible from stated facts — any other researcher plugging in the same facts gets the same number.",
            "It does NOT prove the program will pay that amount (many override with a fixed internal table), and it does NOT capture business impact (a Medium-CVSS bug on the payment system can matter more to a company than a High-CVSS bug on a marketing page) — that distinction is the subject of the next lesson on impact vs. severity.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "A reflected XSS fires only on a logged-out marketing page with no sensitive cookies in scope. Realistic severity band?",
          options: ["Critical (9.0+)", "Low to Medium (around 6.1, the common ceiling for reflected XSS)", "Informational, always 0", "High (7.0+), always"],
          answer: 1,
          why: [
            "Critical requires severe, easily-triggered impact (e.g. unauthenticated RCE); a logged-out marketing page XSS doesn't reach that.",
            "Correct — needs UI:R (victim must click a crafted link) and there's no sensitive session to steal, which caps it around 6.1.",
            "It's not zero-impact: JavaScript does execute in the victim's browser.",
            "High usually requires something like UI:N or a juicier target (e.g. an authenticated admin session).",
          ],
          explain: "Reflected XSS almost always needs UI:R (the victim must click a crafted link), which caps Exploitability. Without a sensitive cookie or admin session to target, Impact is also limited — together these land around 6.1.",
          hints: ["Does this XSS need the victim to click something?", "Is there anything valuable (like a session cookie) for the attacker to steal here?"],
          ref: "Mapping bug classes to typical scores — and the limits of doing so",
        },
        {
          type: "fill",
          q: "Using the CVSS v3.1 vector abbreviations, what two-letter code represents 'no privileges required'?",
          answers: ["pr:n", "prn", "pr n"],
          explain: "PR:N means Privileges Required: None — the attacker needs no account at all, which is the most favourable value for the attacker and raises Exploitability.",
          hints: ["It's the Privileges Required metric.", "'None' is abbreviated with a single letter."],
          ref: "The metrics that move the number",
        },
        {
          type: "mc",
          q: "Vector `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` describes a bug. What does the UI:R tell you about exploitation?",
          options: [
            "The attacker needs admin privileges",
            "A victim must perform some action (e.g. click a link) for the exploit to succeed",
            "The bug can only be exploited locally",
            "The bug has no impact on confidentiality",
          ],
          answer: 1,
          why: [
            "That's what PR, not UI, describes — and here PR:N means no privileges at all.",
            "Correct: UI:R = User Interaction Required, meaning the exploit depends on a victim taking some action.",
            "That's what Attack Vector (here AV:N, network) describes.",
            "C:H in the same vector shows a high confidentiality impact, so this option contradicts the vector.",
          ],
          explain: "UI (User Interaction) is independent of the other metrics — it specifically answers whether a victim must do something (click, open, visit) for the attack to work. Here PR:N already shows no privileges are needed, so UI:R is the only thing standing between the attacker and the victim.",
          hints: ["UI is short for User Interaction — think about what that phrase means literally.", "Compare UI to PR: they answer different questions."],
          ref: "Prerequisite: what a 'vector' means here",
        },
        {
          type: "fill",
          q: "Compute, to one decimal place: Exploitability = 8.22 × AV(0.85) × AC(0.77) × PR(0.85) × UI(0.85), for an unauthenticated network bug with no interaction.",
          answers: ["3.9", "3.90"],
          explain: "8.22 × 0.85 = 6.987; × 0.77 = 5.380; × 0.85 = 4.573; × 0.85 = 3.887 ≈ 3.9. (Note PR:N for Scope Unchanged is 0.85, same as AV:N here — coincidence of the chosen example, not a rule.)",
          hints: ["Multiply the four numbers in sequence, rounding only at the very end.", "8.22 × 0.85 × 0.77 × 0.85 × 0.85 — work left to right."],
          ref: "How the metrics combine into a score",
        },
        {
          type: "mc",
          q: "You reported a bug you scored as High (7.5), but the program's triager rates it Medium (5.3) citing their fixed internal severity table for this bug class. What's the most productive response?",
          options: [
            "Insist your number is right and refuse to accept the rating",
            "Find and submit new evidence that changes an actual metric (e.g. show the session cookie is stealable), rather than just repeating your score",
            "Publicly disclose the bug immediately to force a higher rating",
            "Withdraw the report entirely",
          ],
          answer: 1,
          why: [
            "Repeating your number without new facts rarely changes a fixed internal policy.",
            "Correct — new evidence that changes a metric's actual value (e.g. upgrading Confidentiality impact) is the only thing that moves a fixed-table rating.",
            "Public disclosure outside the program's rules is a policy violation and can get you banned, independent of whether you're technically right.",
            "Withdrawing loses you a valid, paid (even if lower-paid) finding for no reason.",
          ],
          explain: "Fixed internal severity tables don't move because you disagree; they move when you supply a new fact that genuinely changes a metric value. This is the 'don't fight the SLA, bring evidence instead' lesson.",
          hints: ["What actually changes a CVSS number — opinions or facts?", "Is there a concrete, demonstrable fact you could add to the report?"],
          ref: "Don't fight a program's fixed SLA",
        },
      ],
    },
    {
      id: "report-writing",
      title: "Writing the report",
      summary: "The single skill that separates $100 and $5,000 for the same bug.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can write a complete, triager-ready report for a web vulnerability: title, summary, exact reproduction steps, proof of concept, impact statement, suggested fix and timeline — and you can judge whether someone else's report is missing something critical.",
          ],
        },
        {
          title: "Handing over a case file, not a rumour",
          kind: "intuition",
          body: [
            "A triager reads dozens of reports a day and has never seen your target the way you have. Your report is the entire case file they get — if it's missing a step, they can't convict the bug, no matter how real it is.",
            "Where this differs from everyday bug reports at a job: there's no shared Slack channel to clarify. A vague report just sits in a queue, or gets closed as 'unable to reproduce' — a verdict that reads as 'guilty of nothing' even if the bug is very real.",
          ],
        },
        {
          title: "Prerequisite: reproducibility and evidence",
          kind: "prereq",
          body: [
            "'Reproducible' means: if a stranger follows your exact steps, on the exact in-scope target, they get the exact same result, every time. That's the single bar every section of a report exists to clear.",
            "'Evidence' means something a triager can verify without trusting your word: an exact HTTP request they can replay, a screenshot showing the actual response, a short video for multi-step flows. 'I think it's vulnerable' is not evidence; a request/response pair is.",
          ],
        },
        {
          title: "Structure that triagers love",
          kind: "explain",
          body: [
            "1. Title — exact bug class + endpoint, e.g. 'Reflected XSS in /search q parameter'. A triager should know roughly what you found before reading further.",
            "2. Summary — two or three sentences a non-technical manager could read and understand what's wrong.",
            "3. Steps to reproduce — numbered, copy-pasteable, with the exact request(s). No step should require the reader to guess or infer.",
            "4. Proof of concept — screenshot, cURL command, or short video for anything involving multiple steps or timing.",
            "5. Impact — what an attacker can actually achieve, grounded in facts about this specific app (not a generic description of the bug class).",
            "6. Suggested fix — a short, concrete paragraph. Even an imperfect suggestion shows you understand the root cause, which speeds up triage trust.",
            "7. Timeline — the date you found and reported it (useful for programs tracking SLA, and for you if a dispute arises later).",
          ],
        },
        {
          title: "Full worked example: a complete, realistic report",
          kind: "example",
          body: [
            "This is a complete report for a cross-tenant IDOR, written the way you'd actually submit it. Notice every section answers a specific question a triager has, and nothing requires them to guess.",
          ],
          tone: "defense",
          code: `# Title
IDOR in GET /api/v2/invoices/{id} exposes other tenants' invoices

## Summary
The /api/v2/invoices/{id} endpoint returns a full invoice object for any
numeric {id}, without checking that the invoice belongs to the
authenticated user's tenant. Any logged-in user can enumerate IDs and
read other customers' billing data (company name, line items, totals,
billing address).

## Affected asset
https://api.shop.example (listed in-scope under "*.shop.example")

## Steps to reproduce
1. Register two separate test accounts under two separate (test) tenants:
   Tenant A (attacker-controlled) and Tenant B (attacker-controlled, used
   only to simulate a "victim").
2. Log in as Tenant A. Create one invoice. Note its ID, e.g. 10452.
3. Log in as Tenant B. Create one invoice. Note its ID, e.g. 10453.
4. While authenticated as Tenant A, send:

   GET /api/v2/invoices/10453 HTTP/1.1
   Host: api.shop.example
   Authorization: Bearer <Tenant A's own token>

5. Observe: the response returns Tenant B's full invoice (HTTP 200),
   despite the request being authenticated as Tenant A. Expected
   behaviour is HTTP 403/404, matching the behaviour already seen for
   other tenants' resources elsewhere in the API (e.g.
   /api/v2/customers/{id} correctly returns 403 cross-tenant).

## Proof of concept
Request (Tenant A's token, requesting Tenant B's invoice ID):

GET /api/v2/invoices/10453 HTTP/1.1
Host: api.shop.example
Authorization: Bearer eyJhbGciOiJIUzI1NiIs... (Tenant A)

Response (200 OK, Tenant B's real data returned to Tenant A):

HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 10453,
  "tenant": "Tenant B test co",
  "total": "1,204.00",
  "line_items": [ ... ],
  "billing_address": "..."
}

Screenshot attached: invoice-idor-poc.png (Burp Repeater, both requests
side by side).

## Impact
Invoice IDs are sequential and unauthenticated-adjacent (any logged-in
user, not just privileged roles, can reach this endpoint). An attacker
with a free account can enumerate IDs sequentially and harvest every
customer's billing data platform-wide, including company names and
addresses — a full tenant data breach requiring only a standard account
and no interaction from victims.

Suggested CVSS v3.1 vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
(base score 6.5). Given the platform-wide enumeration path described
above, we believe the real business impact (mass data exposure across
all tenants, not a single record) supports a higher priority than the
base score alone implies — happy to discuss during triage.

## Suggested fix
Add an authorization check in the invoice lookup handler that verifies
the invoice's tenant_id matches the authenticated user's tenant_id
before returning data (the same check already correctly applied in
/api/v2/customers/{id}). Reject non-matching requests with 403/404
rather than 200.

## Timeline
2026-03-11  Discovered during authorised testing.
2026-03-11  Report submitted.`,
          check: {
            type: "mc",
            q: "In the example report above, why does the 'Impact' section mention that the endpoint is reachable with 'only a standard account and no interaction from victims', instead of just saying 'this leaks data'?",
            options: [
              "It's padding to make the report look longer",
              "It ties the impact directly back to the CVSS inputs (PR:L, UI:N) and shows the bug is easy to mass-exploit, which is exactly what a triager needs to judge real-world risk",
              "It's irrelevant detail that should be removed",
              "It's only there to repeat the steps to reproduce",
            ],
            answer: 1,
            why: [
              "Every sentence here maps to a severity-relevant fact; it's not filler.",
              "Correct — connecting the technical facts (account level needed, no victim action required) to the resulting risk (mass enumeration) is exactly what turns a report into a convincing severity argument.",
              "It's directly relevant: it explains WHY this is high impact, not just THAT it is.",
              "It's new information about scale, not a repeat of steps 1-5.",
            ],
            explain: "A good Impact section doesn't just restate the bug — it explains, using facts already established in Steps to Reproduce, why the impact is as large as claimed. Here, 'standard account, no interaction' directly explains why this isn't a one-off leak but a mass-enumerable one.",
            hints: ["Look at which CVSS metrics 'standard account' and 'no interaction' correspond to.", "Why would a triager care how easy it is to repeat this attack at scale?"],
          },
        },
        {
          title: "The things triagers reject on sight",
          kind: "mistakes",
          body: [
            "'Theoretical' bugs with no proof of concept at all.",
            "'I think there might be XSS somewhere' with no specific URL or parameter.",
            "Massive dumps of real (non-test-account) user data as 'evidence' — this itself can violate the policy's data-minimisation rules.",
            "Out-of-scope reports (see the scope-reading lesson — always re-check before submitting).",
            "Duplicate reports — search the program's public disclosure history before reporting.",
            "Self-XSS (only exploitable against your own browser, with no way to deliver it to a victim) reported as high severity.",
            "Missing security headers reported alone, with no chained impact.",
            "Raw tool output (e.g. a nuclei JSON dump) pasted in place of a written report.",
          ],
          tone: "defense",
        },
        {
          title: "Practice: spot what's missing",
          kind: "practice",
          body: [
            "A learner submits this report: Title: 'XSS found'. Body: 'I found XSS on the search page. It executes alert(1). Please fix. Severity should be Critical.'",
          ],
          check: {
            type: "mc",
            q: "What is the single biggest problem with this report, the kind that would get it closed as 'needs more info' rather than triaged?",
            options: [
              "It doesn't mention a suggested fix",
              "It has no exact URL, parameter, or request — a triager cannot reproduce it at all",
              "It claims Critical severity, which is sometimes wrong for XSS",
              "It's too short",
            ],
            answer: 1,
            why: [
              "A missing fix suggestion is a minor ding, not a blocker — reports without one still get triaged if they're reproducible.",
              "Correct: without the exact URL/parameter/request, there is nothing for a triager to replay. This fails the reproducibility bar entirely, before severity is even relevant.",
              "An inflated severity claim is a problem, but a triager would still be able to investigate and correct it if the bug were reproducible — the missing reproduction steps block investigation altogether.",
              "Length isn't the issue — a short report with exact steps can still be excellent; this one is short AND missing the steps.",
            ],
            explain: "Reproducibility comes before everything else. A triager who can't replay the bug can't confirm it, can't rate its severity, and can't pay it — regardless of what else is right or wrong in the report.",
            hints: ["What's the very first thing a triager needs in order to even start investigating?", "Compare this to the full worked example — what section is entirely missing here?"],
          },
        },
        {
          title: "Relevance: what a well-written report proves",
          kind: "relevance",
          body: [
            "A complete report proves the bug is real, reproducible by a stranger, and scoped to the right asset — that's what gets it out of the 'needs more info' queue and into triage quickly.",
            "It does NOT, by itself, guarantee the severity or payout you hope for — that's still subject to the program's policy and the real business impact, which the next lesson covers in more depth. Writing well gets you heard; it doesn't override the program's judgement.",
          ],
        },
      ],
      exercises: [
        {
          type: "order",
          q: "Order the sections of a good report, top to bottom.",
          items: ["Title", "Summary", "Steps to reproduce", "Proof of concept", "Impact", "Suggested fix"],
          explain: "Title → summary → reproduce → proof of concept → impact → fix. A triager should be able to scan this top-to-bottom in about 60 seconds and know exactly what's being claimed and how to verify it.",
          hints: ["What should a triager see before they even open the details?", "Evidence (PoC) should come right after the steps that produce it, before you argue about impact."],
          ref: "Structure that triagers love",
        },
        {
          type: "mc",
          q: "Which of these is almost always closed as informational, even when technically true?",
          options: [
            "SQL injection on a login form, with a working PoC",
            "'Missing X-Content-Type-Options header' on a static marketing page, reported alone with no chained impact",
            "Stored XSS in a user's public profile bio, viewable by other users",
            "SSRF with a confirmed cloud-metadata response",
          ],
          answer: 1,
          why: [
            "A working SQLi PoC on a login form is high-impact and gets triaged seriously.",
            "Correct — a missing header, on its own, with no demonstrated chained impact, isn't actionable risk by itself.",
            "Stored XSS reachable by other users is a real, often high-severity finding.",
            "Confirmed cloud metadata access is strong, concrete evidence of serious impact.",
          ],
          explain: "Missing headers are a 'best practice' finding, not a vulnerability on their own, unless you demonstrate a concrete attack they enable (e.g. chaining a missing CSP into XSS impact). Report them chained to real impact, or not at all.",
          hints: ["Which of these has zero demonstrated impact on its own?", "Compare this to the 'things triagers reject' list."],
          ref: "The things triagers reject on sight",
        },
        {
          type: "fill",
          q: "In the worked IDOR report, what two accounts were created purely to produce a safe, verifiable proof of concept without touching real user data?",
          answers: ["tenant a and tenant b", "two test accounts", "tenant a, tenant b"],
          explain: "Two separate test tenant accounts (A and B), both controlled by the researcher, let the report prove cross-tenant access without ever touching a real customer's data.",
          hints: ["Look at the 'Steps to reproduce' section of the worked example.", "The researcher never touches a real customer account — what do they use instead?"],
          ref: "Full worked example: a complete, realistic report",
        },
        {
          type: "mc",
          q: "A report says 'Severity should be Critical' but provides no CVSS vector or justification. Compared to the worked example's Impact section, what is missing?",
          options: [
            "Nothing — severity claims don't need justification",
            "A traceable vector and facts connecting the vulnerability's mechanics to the claimed severity",
            "A screenshot",
            "The researcher's real name",
          ],
          answer: 1,
          why: [
            "Severity claims without justification are exactly the weakness the worked example avoids.",
            "Correct — the worked example gives an explicit vector and ties specific facts (standard account, no interaction) to the severity claim, so the triager can verify or dispute it on the merits.",
            "A screenshot supports reproduction, not severity justification specifically.",
            "Report attribution isn't what's being tested here.",
          ],
          explain: "An unsupported severity claim is just an opinion. The worked example shows the alternative: state the vector, and explain in one or two sentences which specific facts justify each metric value.",
          hints: ["Compare to how the worked example justified its severity claim.", "What lets a triager check your severity claim instead of just trusting it?"],
          ref: "Full worked example: a complete, realistic report",
        },
      ],
    },
    {
      id: "ethics",
      title: "Ethics, pacing, and the long game",
      summary: "A career in bounty hunting is years long; act accordingly.",
      cards: [
        {
          title: "Objective",
          kind: "objective",
          body: [
            "By the end of this lesson you can explain the two non-negotiable rules of ethical bug hunting, design a proof of concept that proves impact without touching real user data, and describe a sustainable hunting routine.",
          ],
        },
        {
          title: "Authorisation is the whole deal, not a technicality",
          kind: "intuition",
          body: [
            "Everything in this unit — scope-reading, severity scoring, report writing — only matters because you stayed inside a boundary someone else gave you permission to test. Step outside it, even briefly, and you're no longer a researcher; legally, you're indistinguishable from an attacker.",
            "Unlike a lab exercise, there's no 'undo' in production. A proof of concept that reads real strangers' private data can't be taken back once you've seen it, even if you report it responsibly afterwards.",
          ],
        },
        {
          title: "Refresher: what you already know about scope and evidence",
          kind: "prereq",
          body: [
            "From earlier lessons: scope defines where you're authorised, policy defines how; evidence should be something a triager can verify, like a request/response pair, not a claim.",
            "This lesson adds one more constraint on top of both: even when an action is technically possible and even in-scope, you must use the minimum necessary data to prove it — you do not need to see a real victim's data to prove a bug exists.",
          ],
        },
        {
          title: "The two commandments",
          kind: "explain",
          body: [
            "1. Stay in scope, always — reconfirm before every session, since scope changes over time.",
            "2. Prove impact with the minimum necessary data, always — a controlled PoC using your own test accounts beats a PoC using real victims' data, every single time, even when the latter would be 'more convincing'.",
            "Everything else in this craft — rating disputes, duplicates, slow triagers — is a professional annoyance. These two commandments are the line between 'security researcher' and 'unauthorised intrusion'.",
          ],
          tone: "defense",
        },
        {
          title: "Worked example: proving an IDOR without a real victim",
          kind: "example",
          body: [
            "Suppose you suspect `/api/v2/invoices/{id}` is vulnerable (the same bug as the previous lesson's worked report). You have two options to prove it.",
            "Option A (wrong): pick a real, low invoice ID at random, fetch it, and see whose data comes back. This reads a real stranger's private billing data without their consent — a crime, independent of your good intentions, and independent of whether you report it afterwards.",
            "Option B (correct): create two throwaway test accounts you control (Tenant A and Tenant B), create one invoice under each, and show that Tenant A's session can fetch Tenant B's invoice. This proves the exact same vulnerability — the authorisation check is missing — without ever touching a real user's data.",
            "Both PoCs demonstrate the bug exists. Only Option B is evidence a triager can accept without you having committed an actual intrusion on your way to writing the report.",
          ],
          check: {
            type: "mc",
            q: "Why is Option B just as convincing as Option A to a triager, despite using no real user data?",
            options: [
              "It isn't as convincing — real data is always better proof",
              "Because the vulnerability is the missing authorization check itself; demonstrating it on any two accounts (real or test) proves the same underlying flaw",
              "Because triagers prefer shorter reports",
              "Because test accounts have higher privileges than real accounts",
            ],
            answer: 1,
            why: [
              "A triager doesn't need real data to confirm a missing authorization check — the flaw is in the code path, not the specific data returned.",
              "Correct: the bug is 'tenant A can read tenant B's record regardless of identity' — two test tenants prove that exact mechanism just as validly as two real ones.",
              "Report length isn't the deciding factor here.",
              "Test accounts have no special privileges; that's precisely why this PoC is valid evidence.",
            ],
            explain: "The vulnerability is a missing authorization check — a structural flaw in the code, not something specific to any one user's data. Demonstrating it between two accounts you fully control proves the flaw exists for any two accounts, including real ones, without you needing to victimise a real user to say so.",
            hints: ["What is actually broken here — a specific user's data, or a check in the code?", "Would the same demo work with any two accounts, or does it need to be real ones specifically?"],
          },
        },
        {
          title: "Mistakes that turn research into a crime",
          kind: "mistakes",
          body: [
            "Iterating through IDs (1, 2, 3, ... 10000) 'to see how bad it is' once you've already proven the bug with a controlled test — every additional real record you view is unnecessary and unauthorised.",
            "Reading other users' private messages, invoices, or health records 'for the report' — a two-account demo already proves the flaw; viewing real content adds legal risk with zero evidentiary benefit.",
            "Assuming 'it's in scope, so anything goes' — scope grants permission to test for vulnerabilities, not permission to exfiltrate real data at will.",
            "Confusing 'I could do more damage' with 'I should demonstrate more damage' in a report — describing potential impact in words is enough; you rarely need to actually execute the worst-case action on real data.",
          ],
        },
        {
          title: "Practice: choosing the ethical PoC",
          kind: "practice",
          body: [
            "You find a bug that lets any authenticated user delete any other user's account by ID, with no ownership check. You want to prove it works.",
          ],
          check: {
            type: "mc",
            q: "What is the ethical way to demonstrate this account-deletion bug?",
            options: [
              "Delete a real, active user's account to show it works",
              "Create two throwaway test accounts, delete one from the other's session, and clearly describe that this proves the missing check for any account",
              "Describe the bug in words only, with no PoC at all",
              "Ask a friend if you can delete their real account",
            ],
            answer: 1,
            why: [
              "Deleting a real user's account causes real, irreversible harm and is unauthorised regardless of your intent.",
              "Correct — two test accounts you fully control prove the exact same missing check without harming anyone, and the report can explain that this generalises to any account.",
              "A words-only description is weaker evidence than a safe, controlled PoC; triagers expect reproducible proof when it's this easy to provide safely.",
              "A friend's real account is still a real person's account and real, if consented, data — but this isn't necessary when two throwaway accounts give equally valid proof, and consent doesn't make it in-scope.",
            ],
            explain: "The minimum-necessary-data principle again: two accounts you created and control prove the vulnerability's mechanism (no ownership check) exactly as well as using a real victim, with zero real-world harm.",
            hints: ["What's the smallest possible demonstration that still proves the flaw?", "Does proving 'this works on any account' require using someone else's real account?"],
          },
        },
        {
          title: "Pacing: the hunters who last",
          kind: "relevance",
          body: [
            "The researchers who stay in this field for years, not months, don't marathon — they build a repeatable 2-4 hour rhythm: a recon pass, review of notes, one target picked, one report written.",
            "Duplicates and rejections sting; they're also a routine part of the job, not a sign you're bad at it. Win rate smooths out over months, not days.",
            "What this lesson proves: following the two commandments keeps you legally and professionally safe for the long haul. It does NOT guarantee a steady payout — that's a function of program quality (lesson 1), real severity (lesson 2) and report quality (lesson 3) compounding over many attempts.",
          ],
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "You find an IDOR that lets you read other users' private messages. For the report's proof of concept, you should include:",
          options: [
            "A dump of 500 real users' messages as 'thorough proof'",
            "Only a two-account PoC between accounts you created — never read real users' data",
            "A video of a real stranger's inbox",
            "Nothing — don't include any PoC at all for sensitive bugs",
          ],
          answer: 1,
          why: [
            "Reading real users' messages is unnecessary once a two-account PoC proves the same flaw, and it causes real privacy harm.",
            "Correct — the two-account PoC is sufficient proof and keeps the demonstration legal and minimal.",
            "A real stranger's inbox is still someone's private data accessed without consent, regardless of format (screenshot vs. video).",
            "Sensitive bugs still need reproducible evidence; omitting PoC entirely just makes the report harder to triage.",
          ],
          explain: "A controlled two-account PoC proves the exact same missing-authorization flaw as reading a stranger's real inbox, with none of the legal or ethical risk. Reading real private data turns a legitimate bounty submission into unauthorised access.",
          hints: ["Does proving the flaw require seeing a real person's actual messages?", "Compare to the invoice IDOR worked example earlier in this lesson."],
          ref: "The two commandments",
        },
        {
          type: "fill",
          q: "Fill in the missing word: 'Prove impact with the ___ necessary data, always.'",
          answers: ["minimum"],
          explain: "The second commandment: use the minimum necessary data to prove a bug, never more than that, regardless of how 'convincing' extra real data might seem.",
          hints: ["It's the opposite of 'maximum'.", "Think about how little data is actually required to prove a flaw exists."],
          ref: "The two commandments",
        },
        {
          type: "mc",
          q: "A triager closes your report as a duplicate. What's the most sustainable response, in the context of a multi-year hunting career?",
          options: [
            "Argue that your write-up was better and deserves partial credit",
            "Accept it, note it in your tracking journal, and move on to the next target — duplicates are routine, not a reflection of skill",
            "Stop hunting on that program forever out of frustration",
            "Publicly complain about the program on social media",
          ],
          answer: 1,
          why: [
            "Report quality doesn't earn partial credit for a duplicate under the standard first-to-report rule most programs use.",
            "Correct — treating duplicates as routine, logging them, and continuing is exactly the sustainable pacing this lesson describes.",
            "Quitting a program entirely over one duplicate throws away future opportunities for no benefit.",
            "Public complaints about policy decisions can violate program rules and damage your reputation without changing the outcome.",
          ],
          explain: "Duplicates are an expected, frequent part of bug hunting, not a signal to escalate or quit. The hunters who last treat them as routine and keep a steady rhythm instead.",
          hints: ["Is a duplicate rejection a sign you did something wrong?", "What does the lesson say about hunters who 'last' in this field?"],
          ref: "Pacing: the hunters who last",
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
      "You can pick programs, score severity realistically with a real CVSS calculation, write triager-friendly reports, and hunt sustainably without crossing legal lines.",
    rules: [],
  },
};

export default unit8;
