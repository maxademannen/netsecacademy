import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "scope-reading",
    title: "Mastering the Scope",
    summary: "Read program policies precisely so your hard work results in a bounty, not a rejection.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: ["By the end of this lesson you can classify any asset or testing method against a real program policy, and explain why a specific exclusion applies."],
      },
      {
        title: "Why a single line can cost you everything",
        kind: "intuition",
        body: [
          "A policy is a contract: it grants you legal permission to test, in exchange for you respecting its exact boundaries. Break one line — even unknowingly — and the contract doesn't cover you anymore.",
          "This is unlike most terms-of-service, which are rarely enforced to the letter. Bug bounty policies are enforced precisely, because triagers use them to decide whether to pay you at all.",
        ],
      },
      {
        title: "Refresher: In-Scope vs Out-of-Scope",
        kind: "prereq",
        body: [
          "'In-Scope' assets are bounty-eligible and you have permission to test them, within the allowed methods.",
          "'Out-of-Scope' assets may mean 'no permission at all' or 'permission but no bounty' — the exact wording of the policy tells you which; when in doubt, treat it as no permission.",
        ],
      },
      {
        title: "Exclusions by method, not just by asset",
        kind: "explain",
        body: [
          "Scope isn't only about *which* domains you can touch — policies also exclude specific *methods* regardless of asset: Denial of Service (DoS), social engineering of employees, and aggressive automated scanning are almost universally forbidden even on in-scope targets.",
          "Bug-class exclusions are also common: 'Self-XSS' (exploitable only against your own browser, with no way to deliver it to a victim) and 'best-practice' findings like a missing SPF record are usually excluded from reward, even if technically true.",
        ],
        tone: "defense",
      },
      {
        title: "Reward tiers and duplicates",
        kind: "explain",
        body: [
          "Some programs pay different amounts for the same bug class depending on which asset it's found on — a critical bug on the payment gateway might pay $5,000, the identical bug class on a marketing blog might pay $500 or nothing. Always check the published reward table, not just the scope table.",
          "Most programs pay only the first valid report of a given bug ('first-to-report'). This is why fast, accurate triage of your own findings (lesson: severity) matters as much as finding the bug at all.",
        ],
        tone: "offense",
      },
      {
        title: "Worked example: applying the full policy",
        kind: "example",
        body: [
          "Policy: In scope — `*.example.com` (standard tier), `payments.example.com` (premium tier, 3x reward). Out of scope — `api.example.com` (explicitly excluded, run by a third party), DoS testing, social engineering, Self-XSS.",
          "You find: (1) a reflected XSS on `shop.example.com` that only fires in your own browser with no way to send it to anyone else — this matches the Self-XSS exclusion, so it's not reward-eligible even though the asset is in scope.",
          "(2) A stored XSS on `payments.example.com`, reachable by any user viewing a shared order page — this is in scope AND on the premium tier, so it's eligible for the 3x reward multiplier if confirmed.",
          "(3) An IDOR on `api.example.com` — the asset itself is explicitly excluded (run by a third party), so even a serious, well-written report here is not eligible, no matter how good the finding is.",
        ],
        check: {
          type: "mc",
          q: "Using the policy above, which of the three findings is the best use of your remaining time to write up?",
          options: [
            "The Self-XSS on shop.example.com, because XSS always pays",
            "The stored XSS on payments.example.com — in scope, reachable by other users, and on the premium reward tier",
            "The IDOR on api.example.com, because IDORs are usually high severity",
            "All three are equally worth writing up",
          ],
          answer: 1,
          why: [
            "Self-XSS is specifically excluded from reward regardless of bug class.",
            "Correct: it clears both the scope check (asset) and the policy check (not excluded by method or class), and it's on the higher-reward tier.",
            "A serious bug on an excluded asset still isn't eligible — severity doesn't override scope.",
            "They are not equal: one is reward-excluded, one is asset-excluded, one is eligible and premium-tier.",
          ],
          explain: "Finding (2) is the only one that clears both scope (correct asset) and policy (not an excluded bug class), and it's on the premium reward tier — the clear best use of write-up time.",
          hints: ["Check each finding against both the scope table and the exclusion list separately.", "Which finding has no exclusion attached to either its asset or its bug class?"],
        },
      },
      {
        title: "Common scope mistakes",
        kind: "mistakes",
        body: [
          "Assuming a wildcard scope overrides a named exclusion — it never does.",
          "Reporting a Self-XSS as a normal XSS without checking whether it's deliverable to a victim.",
          "Testing an excluded asset because 'it's probably run by the same team' — if it's explicitly excluded, it isn't your call to make.",
          "Ignoring the reward table and assuming all in-scope assets pay the same.",
        ],
      },
      {
        title: "Practice: classify this finding",
        kind: "practice",
        body: [
          "Policy: In scope — `*.target.com`. Out of scope — subdomains not directly under target.com, Denial of Service testing.",
          "Finding: a stored XSS on `dev.api.target.com`, discovered after 30 minutes of load-testing with 200 concurrent requests per second to find a race condition.",
        ],
        check: {
          type: "mc",
          q: "Is this finding eligible for a reward?",
          options: [
            "Yes, the XSS itself is on an excluded subdomain and the testing method also violates the DoS exclusion — doubly ineligible",
            "Yes, because stored XSS is always high severity",
            "No, but only because of the subdomain depth issue",
            "No, but only because of the load-testing method",
          ],
          answer: 0,
          why: [
            "Correct — `dev.api.target.com` is a subdomain of a subdomain (not directly under target.com) so it's excluded, AND the 200 req/s testing method matches the DoS exclusion. Both problems apply independently.",
            "Severity never overrides an exclusion.",
            "This understates the problem — the testing method is also excluded.",
            "This understates the problem — the asset itself is also excluded.",
          ],
          explain: "`dev.api.target.com` has two labels in front of `target.com`, so it isn't 'directly under' target.com per the stated exclusion. Separately, 200 requests/second as part of testing risks tripping the DoS exclusion. Either issue alone would disqualify the report; here both apply.",
          hints: ["Count the labels between 'dev' and 'target.com' — is this directly under target.com or a subdomain of a subdomain?", "Does the testing method itself violate a separate rule, regardless of the asset?"],
        },
      },
      {
        title: "Relevance: what careful scope-reading earns you",
        kind: "relevance",
        body: [
          "Careful scope-reading proves your testing was authorised and reward-eligible under this specific policy. It does not predict the exact payout amount (reward tables and triager judgement still apply) and it does not substitute for finding a real, well-documented bug.",
        ],
      },
    ],
    exercises: [
      {
        type: "mc",
        q: "If a program lists `*.example.com` as In-Scope, but explicitly lists `api.example.com` as Out-of-Scope, what happens if you report a bug on `api.example.com`?",
        options: [
          "You get a bonus for finding a bug in a restricted area",
          "The report is likely marked N/A or Out-of-Scope with no payout",
          "You get the standard bounty because it's still a subdomain",
          "The program will immediately add it to the scope",
        ],
        answer: 1,
        why: [
          "There's no bonus for testing excluded assets — the opposite is true.",
          "Correct — an explicit exclusion overrides the wildcard, regardless of bug quality.",
          "Being 'still a subdomain' doesn't matter once it's named as an explicit exclusion.",
          "Programs don't auto-add excluded assets just because a bug was found there.",
        ],
        explain: "Testing explicitly excluded assets is a violation of the program's policy and usually results in no reward, since the exclusion is a deliberate, specific override of the general wildcard.",
        hints: ["Check the specific exclusions mentioned.", "Does 'explicitly out-of-scope' sound like something they'd want to pay for?"],
        ref: "Worked example: applying the full policy",
      },
      {
        type: "match",
        q: "Match the policy term to its impact on your testing.",
        pairs: [
          ["Out-of-Scope", "No testing permitted / no bounty"],
          ["Self-XSS", "Excluded bug class — can't be delivered to a victim"],
          ["Safe Harbor", "Legal protection for researchers following the rules"],
          ["Wildcard Scope", "Covers direct subdomains of a primary domain"],
        ],
        explain: "These four terms cover the main axes of a policy: which assets, which bug classes, your legal protection, and how broad the wildcard reaches.",
        hints: ["Think about what 'Safe' might mean legally.", "A wildcard usually covers direct subdomains, not subdomains of subdomains."],
        ref: "Exclusions by method, not just by asset",
      },
      {
        type: "fill",
        q: "A researcher finds a bug on `dev.api.target.com`. If the scope is only `target.com` and `www.target.com`, this asset is considered ___ ___.",
        answers: ["out of scope", "out-of-scope"],
        explain: "If an asset isn't listed in the In-Scope section and isn't covered by a matching wildcard, it's out of scope — even if it's related to an in-scope domain.",
        hints: ["It's a two or three-word phrase.", "It means 'outside the allowed testing area'."],
        ref: "Refresher: In-Scope vs Out-of-Scope",
      },
      {
        type: "mc",
        q: "A program's reward table pays 3x for bugs on `payments.example.com` versus the standard tier for `*.example.com`. You find an identical bug class on both assets. What determines the actual payout difference?",
        options: [
          "Nothing — identical bug classes always pay identically",
          "The published reward table ties payout to the specific asset, not just the bug class",
          "Whichever report is written more elegantly",
          "The order in which you submit them",
        ],
        answer: 1,
        why: [
          "Reward tables routinely differentiate payout by asset tier, not just bug class.",
          "Correct — the policy explicitly ties payout tier to the asset, which is exactly why checking the reward table (not just the scope table) matters.",
          "Report quality affects whether it's accepted at all, not the tier multiplier itself.",
          "Submission order matters for duplicates, not for tier-based payout differences.",
        ],
        explain: "Reward tables commonly assign different payout multipliers to different assets for the same bug class, reflecting the business value of each asset. Always check it separately from the scope table.",
        hints: ["Re-read the 'Reward tiers and duplicates' explanation.", "Is payout always uniform across all in-scope assets?"],
        ref: "Reward tiers and duplicates",
      },
    ],
  },
  {
    id: "impact-vs-severity",
    title: "Impact vs. Severity",
    summary: "Technical severity (CVSS) and real-world business impact are related but different — payouts follow impact.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: ["By the end of this lesson you can explain the difference between CVSS severity and business impact, and build a proof of concept that demonstrates impact safely."],
      },
      {
        title: "Two different questions",
        kind: "intuition",
        body: [
          "Severity (CVSS, from the previous lesson) answers 'how technically broken is this?' using a fixed formula. Impact answers 'how much does this actually hurt the business and its users?' — a question the formula can't fully capture.",
          "Example: a 9.8 Critical RCE on a server that was decommissioned yesterday and holds no data has almost zero real impact. A 6.5 Medium IDOR on the production payment database that leaks every customer's billing data can matter enormously to the business, even though its CVSS number is lower.",
        ],
      },
      {
        title: "Refresher: what the CVSS score already tells you",
        kind: "prereq",
        body: [
          "From the previous lesson: CVSS combines Exploitability (how easy) and Impact Sub-Score (how bad the C/I/A loss is) into one number, purely from the technical mechanics of the bug.",
          "What CVSS does not know: which specific database the bug touches, whether that asset is production or staging, or how the company's business depends on it. That context is what turns a CVSS number into a payout decision.",
        ],
      },
      {
        title: "How business context changes the payout, not the CVSS score",
        kind: "explain",
        body: [
          "Triage teams routinely pay more than the CVSS number alone suggests when the affected asset is production-critical or user-data-heavy, and less when the asset is a deprecated staging server about to be deleted.",
          "This is why the Impact section of a report (previous lesson) should state concrete facts: which data, how many users, whether it's production — not just restate the bug mechanically.",
        ],
      },
      {
        title: "The art of a safe, convincing PoC",
        kind: "explain",
        body: [
          "A proof of concept must demonstrate impact without causing the damage it demonstrates. Never delete real data, access real PII beyond the minimum, or interrupt a real service.",
          "Instead of 'I can delete any user', show 'I deleted my own second test account using the same request that targets arbitrary IDs' — the mechanism generalises; you don't need to execute it on a real victim.",
          "Attack prerequisites matter to triagers too: does the bug need a specific role? Does it need the victim to click five times over two minutes? Document the exact prerequisites honestly — understating them (implying it's easier than it is) damages your credibility when discovered.",
        ],
        tone: "defense",
      },
      {
        title: "Worked example: same CVSS vector, different payout",
        kind: "example",
        body: [
          "Both bugs below score identically: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (base score 6.5), because both are read-only IDORs reachable by a logged-in user.",
          "Bug 1: IDOR on `/staging-reports/{id}` — the staging endpoint is explicitly flagged in the program's asset notes as 'decommissioning in 2 weeks, no production data'. Business impact: minimal; likely paid at or near the Medium CVSS floor, or even informational if staging turns out to be fully out of scope.",
          "Bug 2: IDOR on `/invoices/{id}` on the production billing system, exposing every customer's real financial records at scale. Business impact: severe, platform-wide data exposure. Many programs pay a 'bonus' above the base-score-implied range for this kind of mass, production, financial-data exposure, even though the CVSS vector is numerically identical to Bug 1.",
          "The lesson: the Impact section of your report is where you argue the business-context difference between these two scenarios — CVSS alone cannot distinguish them.",
        ],
        check: {
          type: "mc",
          q: "Both bugs above share the exact same CVSS vector and base score (6.5). Why might Bug 2 receive a much higher real-world payout?",
          options: [
            "It shouldn't — identical CVSS vectors must always pay identically",
            "Because Bug 2 affects production financial data at scale, which is business impact that CVSS's fixed formula doesn't capture",
            "Because Bug 2's report is probably longer",
            "Because staging servers are always out of scope",
          ],
          answer: 1,
          why: [
            "CVSS is a technical severity measure; it doesn't account for which specific asset or data is affected, which is exactly why identical vectors can have very different real-world payouts.",
            "Correct — production, high-value, mass-exposure data is a business-impact factor CVSS doesn't model, and triagers routinely adjust payout for it.",
            "Report length isn't the deciding factor; the underlying business context is.",
            "Staging servers can be in scope; the point here is that even an in-scope staging bug carries less real business risk than a production one.",
          ],
          explain: "CVSS captures technical mechanics only. Two bugs with identical mechanics can have wildly different real-world consequences depending on what data or system they actually touch — that's business impact, and it's argued in the report's Impact section, not computed by the CVSS formula.",
          hints: ["Does CVSS know anything about which specific database or environment is affected?", "What's different about the two bugs besides their CVSS vector?"],
        },
      },
      {
        title: "Mistakes: confusing severity with impact",
        kind: "mistakes",
        body: [
          "Assuming a high CVSS score guarantees a high payout — a technically severe bug on a decommissioned or data-free asset can still pay little.",
          "Assuming a 'Medium' CVSS bug isn't worth a detailed report — a Medium-severity bug on a production, high-value asset, with a clearly argued business impact, can outperform a higher-CVSS bug elsewhere.",
          "Writing an Impact section that just restates the bug mechanically ('this allows reading other users' data') instead of connecting it to business-specific facts ('at scale, across all 50,000 tenants, including production billing records').",
          "Exaggerating prerequisites to look more impressive, or hiding them to look easier — both damage trust when a triager actually reproduces the bug.",
        ],
      },
      {
        title: "Practice: writing the impact argument",
        kind: "practice",
        body: [
          "You find a stored XSS (CVSS base 8.2, Scope Changed because it can target an admin session) in a comment field that only admins ever view, on a platform where the admin panel manages all customer refunds and account suspensions.",
        ],
        check: {
          type: "mc",
          q: "Which sentence best demonstrates business impact, beyond the CVSS number, for this report's Impact section?",
          options: [
            "\"This is stored XSS, which is generally considered a high-severity bug class.\"",
            "\"Because only admins view this field, any attacker can target the admin session directly; combined with the admin panel's ability to issue refunds and suspend accounts, a successful hit could let an attacker silently drain refunds or lock out arbitrary customers.\"",
            "\"XSS bugs are common and should always be fixed quickly.\"",
            "\"This bug has a CVSS score of 8.2.\"",
          ],
          answer: 1,
          why: [
            "This restates the bug class generically without touching this specific application's consequences.",
            "Correct — it ties the specific mechanism (admin-only field, admin session) to the specific business capability at risk (refunds, account suspension), which is exactly what a CVSS number can't express.",
            "This is a generic statement about XSS bugs in general, not this platform's specific risk.",
            "Restating the CVSS score adds no new information beyond what's already in the report's severity section.",
          ],
          explain: "A strong Impact section always ties the technical mechanism to a concrete, specific business consequence for this exact application — here, refund fraud and account lockout via a hijacked admin session, not a generic description of XSS.",
          hints: ["Which option mentions something specific to THIS platform's admin panel, rather than XSS in general?", "Business impact statements name a concrete consequence, not a bug-class generalisation."],
        },
      },
      {
        title: "Relevance: what impact arguments can and can't do",
        kind: "relevance",
        body: [
          "A well-argued Impact section can justify a payout above the CVSS-implied range, or convince a triager not to downgrade severity. It proves you understand the real-world consequences, not just the mechanism.",
          "It cannot invent impact that doesn't exist — claiming mass data exposure you haven't actually demonstrated is fabrication, not argument, and will damage your credibility once checked.",
        ],
      },
    ],
    exercises: [
      {
        type: "order",
        q: "Order these steps for creating a safe and effective proof of concept.",
        items: [
          "Identify the vulnerability and its potential impact",
          "Create two controlled test accounts",
          "Perform the exploit from Account A against Account B",
          "Document the result with screenshots, avoiding real user data",
          "Submit the report with a clear, specific impact statement",
        ],
        explain: "This workflow proves the bug's impact without violating privacy or causing real damage — identify first, build a safe test environment, demonstrate, document, then argue impact in the write-up.",
        hints: ["You need test accounts before you can exploit them.", "The report is always the final step, after you have evidence in hand."],
        ref: "The art of a safe, convincing PoC",
      },
      {
        type: "mc",
        q: "Why might a 'Critical' technical vulnerability be paid less than expected, or closed as informational, by a triage team?",
        options: [
          "The researcher used the wrong operating system",
          "The vulnerability is only exploitable on a deprecated, soon-to-be-decommissioned asset with no real data",
          "The report was too detailed",
          "Triage teams dislike thorough researchers",
        ],
        answer: 1,
        why: [
          "Tooling choice has no bearing on payout.",
          "Correct — technical severity doesn't matter if the real-world business risk is near zero, as with a soon-to-be-removed asset holding no data.",
          "Thoroughness is rewarded, not penalised.",
          "This isn't how triage teams actually operate; payout tracks risk, not researcher likability.",
        ],
        explain: "Even a technically Critical bug can have minimal real business impact if the affected asset carries no real data or is about to be removed — this is exactly the severity-vs-impact gap this lesson covers.",
        hints: ["Think about what 'business impact' depends on, beyond the bug mechanics.", "Does the company care much about a server they're about to delete?"],
        ref: "Worked example: same CVSS vector, different payout",
      },
      {
        type: "match",
        q: "Match the CVSS metric to its real-world meaning.",
        pairs: [
          ["User Interaction", "Does a victim need to click something?"],
          ["Privileges Required", "Does the attacker need an account first?"],
          ["Confidentiality", "Can the attacker read private data?"],
          ["Availability", "Can the attacker crash the service?"],
        ],
        explain: "These metrics standardise how severity is discussed, but notice none of them ask 'how much does this data matter to the business' — that's impact, argued separately in the report.",
        hints: ["Interaction involves a person's action.", "Availability is about whether the service stays 'up'."],
        ref: "Refresher: what the CVSS score already tells you",
      },
    ],
  },
  {
    id: "triage-handling",
    title: "Navigating Triage & Burnout",
    summary: "The report is just the beginning — learn to communicate with triagers and keep a sustainable pace.",
    cards: [
      {
        title: "Objective",
        kind: "objective",
        body: ["By the end of this lesson you can describe the triage lifecycle, respond professionally to a disputed severity rating, and describe a sustainable hunting routine."],
      },
      {
        title: "A report is a conversation, not a verdict",
        kind: "intuition",
        body: [
          "Submitting a report isn't the end of the process — it's the opening move in a conversation with a human triager who may ask questions, request more evidence, or disagree with your severity claim.",
          "Unlike a customer-support ticket, there's often no guaranteed response time, and the triager has no obligation to agree with you. Your only lever is evidence and professionalism — not persistence or frustration.",
        ],
      },
      {
        title: "Refresher: reproducibility and severity arguments",
        kind: "prereq",
        body: [
          "From earlier lessons: a report must be reproducible (exact steps a stranger can replay) and any severity claim should be backed by a specific, checkable CVSS vector and impact statement, not just an assertion.",
          "Everything in this lesson about disputing a triage decision builds on that: you can only push back productively if you have new, concrete evidence to add.",
        ],
      },
      {
        title: "The triage lifecycle",
        kind: "explain",
        body: [
          "New (unread) → Triaged (confirmed and forwarded to the company's engineering team) → Resolved (fixed and paid) — or, at any point, Informative/N/A (closed without reward, often for valid-but-low-impact findings or policy violations).",
          "Triage time varies hugely by program, from a few hours to several weeks. Checking status obsessively doesn't speed it up; a patient, well-written original report does.",
        ],
      },
      {
        title: "Professional communication, including pushback",
        kind: "explain",
        body: [
          "If a triager requests more information, respond promptly and specifically — answer exactly what was asked, don't resubmit the whole report.",
          "If they mark your report Informative and you disagree, don't argue your original claim louder. Instead, do two things in order: first, carefully reread their stated reasoning; second, provide NEW evidence or a stronger impact scenario that addresses that reasoning directly. 'You're wrong' doesn't move anyone; 'here's a request that chains this into an MFA bypass' does.",
          "Your platform reputation ('signal') is built from report quality and professionalism over time — a single heated dispute can cost you more than the one bounty you're fighting for.",
        ],
        tone: "defense",
      },
      {
        title: "Worked example: a good pushback message",
        kind: "example",
        body: [
          "Scenario: you reported a reflected XSS and rated it High (7.1), citing session-cookie theft. The triager marks it Medium (6.1), noting 'the session cookie is HttpOnly on this domain, so document.cookie can't read it — standard reflected XSS rating applies'.",
          "Weak pushback: 'I still think this should be High, XSS is always dangerous.' — This repeats the original claim and ignores their specific, correct technical reasoning. It will not change the outcome.",
          "Strong pushback: 'You're right that the session cookie is HttpOnly. I retested and found the same XSS can instead perform a fetch() call to /api/v2/account/email using the victim's existing session, silently changing their account email to one I control, which enables a full account-takeover via password reset. Updated PoC attached.' — This accepts their correct point, and supplies new evidence that changes an actual impact fact (now it's an account-takeover primitive, not just cookie theft).",
        ],
        check: {
          type: "mc",
          q: "What makes the 'strong pushback' message effective, according to the lesson?",
          options: [
            "It repeats the original severity claim more firmly",
            "It acknowledges the triager's correct technical point and adds new, concrete evidence that changes the actual impact",
            "It is longer than the weak message",
            "It threatens to disclose the bug publicly",
          ],
          answer: 1,
          why: [
            "Repetition is exactly the weak approach described, and it doesn't work.",
            "Correct — accepting a correct correction and supplying new evidence (the account-takeover chain) is what actually moves a triage decision.",
            "Length alone isn't the factor; substance is.",
            "No disclosure threat is used or recommended — that would itself be a policy violation.",
          ],
          explain: "Productive pushback requires two things: acknowledging what the triager got right, and providing genuinely new evidence that changes the facts of the case — not simply repeating the original claim with more conviction.",
          hints: ["Compare exactly what differs between the weak and strong messages.", "Does the strong message argue the same fact again, or add a new one?"],
        },
      },
      {
        title: "Mistakes that burn reputation or you",
        kind: "mistakes",
        body: [
          "Arguing with emotion ('this is ridiculous', 'you clearly don't understand security') instead of with new evidence — this damages your signal score and rarely changes the outcome.",
          "Treating every duplicate as an injustice worth fighting — duplicates are normal; contest them only if you have clear, dated proof you reported first through the proper channel.",
          "Hunting in long, unbroken binges until burnout, then disappearing for months — this produces worse report quality over time and no income stability.",
          "Never reviewing your own past 'misses' — researchers who keep a testing journal of what they tried (even failures) improve faster than those who don't.",
        ],
      },
      {
        title: "Practice: responding to a decision",
        kind: "practice",
        body: [
          "Your report is marked 'Duplicate' — another researcher reported the same bug four hours before you, and the program's policy is first-to-report.",
        ],
        check: {
          type: "mc",
          q: "What is the most sustainable, professional response?",
          options: [
            "Demand to see the other report to verify it was really earlier",
            "Accept the decision gracefully, log it in your tracking journal, and move to a new target",
            "Post the vulnerability details online since you don't get credit anyway",
            "Stop submitting reports to this program",
          ],
          answer: 1,
          why: [
            "Most programs won't share another researcher's private report, and demanding it damages your professional standing for no benefit.",
            "Correct — duplicates are a normal, expected outcome under a first-to-report policy; logging it and moving on is both professional and sustainable.",
            "Public disclosure violates the program's policy and can get you permanently banned, independent of this one duplicate.",
            "One duplicate doesn't justify abandoning a program that may otherwise be worth your time.",
          ],
          explain: "Under a standard first-to-report policy, a duplicate is nobody's fault — it's simply how the system works. Accepting it, recording the lesson learned, and continuing is exactly the sustainable pacing this lesson teaches.",
          hints: ["Is a duplicate decision usually something a triager can or will reverse?", "What response keeps your reputation intact for future reports?"],
        },
      },
      {
        title: "Relevance: sustainability is a skill, not a personality trait",
        kind: "relevance",
        body: [
          "A calm, evidence-based response to triage decisions proves you're someone programs want to keep working with — which compounds over a career into faster triage and benefit-of-the-doubt on borderline calls.",
          "It does not guarantee any single dispute will be won, and it does not replace the earlier skills in this unit (scope-reading, severity scoring, report writing) — professionalism amplifies good work; it can't substitute for it.",
        ],
      },
    ],
    exercises: [
      {
        type: "fill",
        q: "When a report is acknowledged as a valid finding but doesn't meet the threshold for a bounty, it is often marked as ___.",
        answers: ["informative"],
        explain: "Informative reports are valid findings that are nonetheless not eligible for a financial reward, often due to low business impact or an excluded bug class.",
        hints: ["It starts with 'I'.", "It means 'providing information' without necessarily meriting payment."],
        ref: "The triage lifecycle",
      },
      {
        type: "mc",
        q: "What is the best way to handle a report being marked 'Duplicate'?",
        options: [
          "Argue that your write-up is better written",
          "Ask for the other researcher's contact information",
          "Accept it gracefully and move on to a new target or asset",
          "Post the vulnerability on social media out of frustration",
        ],
        answer: 2,
        why: [
          "Write-up quality doesn't change the first-to-report outcome.",
          "Programs don't share other researchers' identities, and asking damages trust.",
          "Correct — duplicates are routine; accepting them and moving forward is both professional and time-efficient.",
          "Public disclosure out of frustration is a policy violation that can get you banned.",
        ],
        explain: "Duplicates are a natural, frequent part of bug bounty hunting under first-to-report rules. Being professional and moving on protects your reputation and your time.",
        hints: ["Which option keeps your account in good standing?", "Time spent arguing a duplicate is time not spent finding the next bug."],
        ref: "Mistakes that burn reputation or you",
      },
      {
        type: "order",
        q: "Sequence the professional way to push back on a triage decision.",
        items: [
          "Carefully read the triager's stated reasoning for the decision",
          "Research or retest for a stronger, more concrete impact scenario",
          "Draft a polite response that acknowledges their point and presents the new evidence",
          "Wait for the triager to review the additional information",
          "If the decision stands after that, thank them for their time and move on",
        ],
        explain: "Effective pushback always starts by understanding their reasoning, then supplies genuinely new evidence — not emotion — and gracefully accepts a final decision if it still stands.",
        hints: ["Understand their reasoning before you respond to it.", "New evidence should come before you draft the message, not after."],
        ref: "Worked example: a good pushback message",
      },
    ],
  },
];
