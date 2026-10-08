import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "scope-reading",
    title: "Mastering the Scope",
    summary: "Learn how to read program policies to ensure your hard work results in a bounty rather than a rejection.",
    cards: [
      {
        title: "The Golden Rule of Scope",
        body: [
          "In bug bounty, 'Scope' defines the boundaries of your testing. Anything inside the scope is fair game; anything outside is strictly off-limits.",
          "Programs often divide scope into 'In-Scope' (bounty eligible) and 'Out-of-Scope' (no bounty, sometimes no permission to test).",
          "One common mistake is testing a subdomain like 'dev.example.com' when only 'example.com' is listed. Even if you find a critical bug, testing an out-of-scope asset can lead to a $0 payout and a warning."
        ],
        tone: "info"
      },
      {
        title: "Permitted Methods & Exclusions",
        body: [
          "Policies don't just list *where* you can test, but *how*. Most programs strictly forbid Denial of Service (DoS), Social Engineering, and aggressive automated scanning.",
          "Exclusions often include 'Self-XSS' (where you can only attack yourself) or 'Best Practice' findings like missing SPF records.",
          "Ignoring these exclusions is the fastest way to get a 'Not Applicable' (N/A) status and damage your reputation on the platform."
        ],
        tone: "defense"
      },
      {
        title: "The 'Fine Print' Financials",
        body: [
          "Some programs have different payout tiers for different assets. A 'Critical' bug on the main payment gateway might pay $5,000, while the same bug on a marketing blog might pay $500.",
          "Always check the 'Reward Table'. A single line in the policy—such as 'Subdomains are eligible for points only'—can change a four-figure payout into a simple 'Thank You'.",
          "Duplicates are also handled here. Usually, only the first person to report a bug gets the bounty."
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "If a program lists '*.example.com' as In-Scope, but explicitly lists 'api.example.com' as Out-of-Scope, what happens if you report a bug on 'api.example.com'?",
        options: [
          "You get a bonus for finding a bug in a restricted area.",
          "The report is likely marked N/A or Out-of-Scope with no payout.",
          "You get the standard bounty because it's still a subdomain.",
          "The program will immediately add it to the scope."
        ],
        answer: 1,
        explain: "Testing explicitly excluded assets is a violation of the program's policy and usually results in no reward.",
        hints: [
          "Check the specific exclusions mentioned.",
          "Does 'Explicitly Out-of-Scope' sound like something they want to pay for?",
          "Rules are strict in bug bounty."
        ]
      },
      {
        type: "match",
        q: "Match the policy term to its impact on your testing.",
        pairs: [
          ["Out-of-Scope", "No testing permitted / No bounty"],
          ["Exclusions", "Specific bug types not eligible for rewards"],
          ["Safe Harbor", "Legal protection for researchers following rules"],
          ["Wildcard Scope", "Includes all subdomains of a primary domain"]
        ],
        explain: "Understanding these terms ensures you stay legal and eligible for rewards.",
        hints: [
          "Think about what 'Safe' might mean legally.",
          "A wildcard (*) usually covers everything underneath.",
          "Exclusions are things they don't want to hear about."
        ]
      },
      {
        type: "fill",
        q: "A researcher finds a bug on 'dev.api.target.com'. If the scope is only 'target.com' and 'www.target.com', this asset is considered ___ ___ ___.",
        answers: ["out of scope", "out-of-scope"],
        explain: "If an asset is not listed in the 'In-Scope' section, or is not covered by a wildcard, it is out of scope.",
        hints: [
          "It's a three-word phrase (or hyphenated).",
          "It means 'outside the allowed area'.",
          "It starts with 'O'."
        ]
      }
    ]
  },
  {
    id: "impact-vs-severity",
    title: "Impact vs. Severity",
    summary: "Technical bugs are great, but business impact is what pays. Learn to demonstrate real-world risk.",
    cards: [
      {
        title: "Technical Severity vs. Business Impact",
        body: [
          "Severity (like CVSS) measures how 'broken' the code is. Impact measures how much that 'brokenness' hurts the company.",
          "An 'Informational' bug might have high technical complexity but zero impact on user data. Conversely, a simple logic flaw that allows a user to see another's private profile has massive impact.",
          "Bounty programs pay for **Impact**. If you can't show how the bug harms the business or its users, your payout will suffer."
        ],
        tone: "info"
      },
      {
        title: "The Art of the PoC",
        body: [
          "A Proof of Concept (PoC) must prove the impact without causing actual damage. Never delete real user data or access PII (Personally Identifiable Information) beyond what is necessary.",
          "Instead of 'I can delete any user', show 'I can delete my own second test account'.",
          "Clear, concise steps and a video or screenshots of the 'money shot' (the point of impact) are essential for a high-severity rating."
        ],
        tone: "defense"
      },
      {
        title: "Attack Prerequisites",
        body: [
          "Triage teams look at how hard a bug is to exploit. Does it require a specific admin role? Does it need the victim to click five times and stay on a page for 2 minutes?",
          "Bugs with 'Zero Interaction' and 'High Privilege' impact are the 'P1' (Priority 1) holy grails.",
          "Always document the exact requirements (Prerequisites) needed for the attack to succeed."
        ],
        tone: "offense"
      }
    ],
    exercises: [
      {
        type: "order",
        q: "Rank these steps for creating a safe and effective Proof of Concept (PoC):",
        items: [
          "Identify the vulnerability and its potential impact.",
          "Create two controlled test accounts.",
          "Perform the exploit from Account A against Account B.",
          "Document the result with screenshots, avoiding real user data.",
          "Submit the report with a clear impact statement."
        ],
        explain: "This workflow ensures you prove the bug's impact without violating privacy or causing damage.",
        hints: [
          "You need test accounts before you can exploit them.",
          "Impact should be identified before you start the PoC.",
          "The report is the final step."
        ]
      },
      {
        type: "mc",
        q: "Why might a 'Critical' technical vulnerability be downgraded to 'Informative' by a triage team?",
        options: [
          "The researcher used a Mac instead of Linux.",
          "The vulnerability is only exploitable on a deprecated, out-of-scope staging server.",
          "The report was too long and detailed.",
          "The triage team doesn't like the researcher."
        ],
        answer: 1,
        explain: "Technical severity doesn't matter if the asset is not in scope or the risk to the business is non-existent.",
        hints: [
          "Think about the importance of 'Scope'.",
          "Does the company care about a server they were about to delete?",
          "Payouts are tied to risk."
        ]
      },
      {
        type: "match",
        q: "Match the CVSS metric to its real-world meaning.",
        pairs: [
          ["User Interaction", "Does a victim need to click something?"],
          ["Privileges Required", "Does the attacker need an account first?"],
          ["Confidentiality", "Can the attacker read private data?"],
          ["Availability", "Can the attacker crash the service?"]
        ],
        explain: "These metrics help standardize how we talk about severity and impact.",
        hints: [
          "Interaction involves a person.",
          "Privileges involve permissions.",
          "Availability is about the service being 'up'."
        ]
      }
    ]
  },
  {
    id: "triage-handling",
    title: "Navigating Triage & Burnout",
    summary: "The report is just the beginning. Learn how to communicate with triagers and keep your sanity.",
    cards: [
      {
        title: "The Triage Lifecycle",
        body: [
          "Once submitted, your report goes to 'Triage'. A human (or team) will verify your findings.",
          "Common statuses: 'New' (unread), 'Triaged' (confirmed and sent to the company), 'Resolved' (fixed and paid), or 'Informative/N/A' (closed without reward).",
          "Be patient. Triage can take anywhere from a few hours to several weeks depending on the program."
        ],
        tone: "info"
      },
      {
        title: "Professional Communication",
        body: [
          "If a triager asks for more info, respond promptly and politely. If they mark it 'Informative' and you disagree, don't get angry.",
          "Provide **new evidence** or a **better impact scenario** to push back. Statements like 'You're wrong' don't work; 'I found a way to use this to bypass MFA' does.",
          "Your reputation score (Signal) depends on your professionalism and the quality of your reports."
        ],
        tone: "defense"
      },
      {
        title: "Pacing & Sustainability",
        body: [
          "Bug bounty is a marathon, not a sprint. The 'High' of a payout is followed by 'Dry Spells' where you find nothing for weeks.",
          "Maintain a testing journal. Document what you tried, even if it failed. This helps you learn and prevents repeating the same mistakes.",
          "Avoid burnout: set specific hours for hunting and step away when you feel frustrated. Your brain needs rest to spot subtle flaws."
        ],
        tone: "info"
      }
    ],
    exercises: [
      {
        type: "fill",
        q: "When a report is closed because it provides value but doesn't meet the threshold for a bounty, it is often marked as ___.",
        answers: ["informative"],
        explain: "Informative reports are acknowledged as valid findings but are usually not eligible for financial rewards.",
        hints: [
          "It starts with 'I'.",
          "It means 'providing information'.",
          "It's a common status for low-impact bugs."
        ]
      },
      {
        type: "mc",
        q: "What is the best way to handle a report being marked as a 'Duplicate'?",
        options: [
          "Argue that your report is better written.",
          "Ask for the original researcher's contact info.",
          "Accept it gracefully and move on to a new target or asset.",
          "Post the vulnerability on Twitter out of frustration."
        ],
        answer: 2,
        explain: "Duplicates are a natural part of bug bounty. The first reporter gets the reward. Being professional helps maintain your reputation.",
        hints: [
          "Which option keeps your account from being banned?",
          "Time is money; don't waste it on lost causes.",
          "Professionalism is key."
        ]
      },
      {
        type: "order",
        q: "Sequence the professional way to 'push back' on a triage decision:",
        items: [
          "Carefully read the triager's reasoning for the closure.",
          "Research a more severe impact scenario or bypass for their fix.",
          "Draft a polite response providing the new evidence.",
          "Wait for the triager to review the additional information.",
          "If the decision stands, thank them for their time and move on."
        ],
        explain: "Pushing back should always be based on new technical evidence, not emotion.",
        hints: [
          "Understand their side first.",
          "Evidence is more powerful than opinions.",
          "Moving on is the final step if it fails."
        ]
      }
    ]
  }
];
