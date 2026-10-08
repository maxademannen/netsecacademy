import type { Lesson } from "../types";

export const extraLessons: Lesson[] = [
  {
    id: "password-reset",
    title: "Password Reset Vulnerabilities",
    summary: "Explore how flawed recovery mechanisms like predictable tokens and Host Header injection lead to account takeover.",
    cards: [
      {
        title: "Predictable Tokens & Timing",
        body: [
          "Password reset tokens must be cryptographically secure and unpredictable. Using sequential IDs, timestamps, or low-entropy random numbers allows attackers to guess valid tokens.",
          "Response-timing attacks occur when the server takes longer to process an existing email than a non-existent one. This allows attackers to enumerate valid usernames or emails.",
          "Always ensure that the response time is consistent, regardless of whether the user exists, and use a cryptographically secure PRNG for tokens."
        ],
        tone: "info"
      },
      {
        title: "Host Header Injection",
        body: [
          "Many applications generate reset links using the `Host` header from the user's request: `https://[Host]/reset?token=...`.",
          "If an attacker provides a malicious `Host` header, the application might send the reset email containing a link to the attacker's domain.",
          "When the victim clicks the link, the secret token is sent to the attacker's server logs, enabling account takeover."
        ],
        code: "GET /password-reset?email=victim@example.com HTTP/1.1\nHost: attacker-controlled.com\n...",
        tone: "offense"
      },
      {
        title: "Token Leakage & Referer",
        body: [
          "If the password reset page loads external resources (like analytics or fonts) without a proper `Referrer-Policy`, the reset token may be leaked via the `Referer` header.",
          "Additionally, if the token is not invalidated immediately after use or if the `SameSite` attribute on session cookies is misconfigured, CSRF attacks might be possible against the reset process.",
          "Defense: Use `Referrer-Policy: no-referrer` and ensure tokens are single-use and short-lived."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "Why is using `base64(timestamp)` as a reset token dangerous?",
        options: [
          "It is too long for most database fields",
          "It can be easily predicted or brute-forced by an attacker",
          "Base64 is an encryption method that is easily cracked",
          "It forces the user to remember the timestamp"
        ],
        answer: 1,
        explain: "Timestamps are predictable. If an attacker knows approximately when a reset was requested, they can generate tokens for that time range and hijack the account.",
        hints: [
          "Think about how much 'entropy' or randomness a timestamp provides.",
          "If I know you requested a reset 5 minutes ago, how many possibilities are there?"
        ]
      },
      {
        type: "fill",
        q: "To perform a Host Header injection to steal a reset token, which header would you modify in the password reset request?",
        answers: ["Host"],
        explain: "By modifying the 'Host' header, you trick the server into generating a link pointing to your own domain, capturing the token when the user clicks.",
        hints: [
          "It's the standard HTTP header that specifies the domain name of the server.",
          "The name is literally in the description of the attack."
        ]
      },
      {
        type: "order",
        q: "Sequence the steps for a Host Header Injection attack:",
        items: [
          "Attacker sends reset request with Host: evil.com",
          "Server generates token and sends email to victim",
          "Victim clicks link: evil.com/reset?token=xyz",
          "Attacker captures token in evil.com logs",
          "Attacker uses token on real site to change password"
        ],
        explain: "The attack relies on the server trusting the Host header to build the absolute URL sent to the victim.",
        hints: [
          "The attacker starts the process, the victim interacts with the poisoned link.",
          "The capture happens before the final takeover."
        ]
      }
    ]
  },
  {
    id: "oauth-mfa",
    title: "OAuth & MFA Integration Mistakes",
    summary: "Identify common pitfalls in modern authentication flows, from OAuth redirect leaks to MFA logic bypasses.",
    cards: [
      {
        title: "OAuth Redirect URI Validation",
        body: [
          "The `redirect_uri` parameter tells the OAuth provider where to send the authorization code. If validation is weak (e.g., using regex that only checks for a prefix), attackers can redirect codes to their own sites.",
          "Example: `https://app.com/callback` could be bypassed with `https://app.com.attacker.com/` or `https://app.com/logout?redirect=attacker.com`.",
          "Always use strict allow-listing for redirect URIs."
        ],
        tone: "offense"
      },
      {
        title: "The 'state' Parameter & CSRF",
        body: [
          "OAuth flows are vulnerable to CSRF if they don't use the `state` parameter. An attacker can start a flow and trick a victim into completing it, linking the victim's account to the attacker's identity.",
          "The `state` parameter should be a high-entropy, non-guessable value generated by the client and verified upon callback.",
          "Without `state`, an attacker can force a user to log into the attacker's account on a site, potentially capturing sensitive info the user then inputs."
        ],
        tone: "defense"
      },
      {
        title: "MFA Bypass via Logic Flaws",
        body: [
          "MFA is often implemented as a 'second step' after primary login. If the application doesn't verify the MFA status on every sensitive request, an attacker might bypass it.",
          "Common flaws: Reusing a `/verify` endpoint from a different context, or the application setting a 'logged_in' cookie before the MFA is completed.",
          "Check for 'leakage' where API endpoints return sensitive data before the MFA challenge is finished."
        ],
        tone: "info"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "What is the primary purpose of the 'state' parameter in an OAuth 2.0 flow?",
        options: [
          "To remember the user's password",
          "To prevent Cross-Site Request Forgery (CSRF)",
          "To specify the user's permissions (scopes)",
          "To encrypt the authorization code"
        ],
        answer: 1,
        explain: "The 'state' parameter links the initial request to the callback, ensuring that the person who started the login is the one finishing it.",
        hints: [
          "It prevents an attacker from 'injecting' their own authorization code into your session.",
          "It's a common defense against session-linking attacks."
        ]
      },
      {
        type: "match",
        q: "Match the OAuth/MFA flaw to its consequence:",
        pairs: [
          ["Weak redirect_uri validation", "Authorization code theft"],
          ["Missing 'state' parameter", "Account linking CSRF"],
          ["Premature session cookie", "MFA bypass"],
          ["Implicit Flow usage", "Token leakage in URL"]
        ],
        explain: "Each misconfiguration in the auth flow opens a specific vector: URI validation leads to theft, missing state leads to CSRF, and timing leads to MFA bypass.",
        hints: [
          "Think about where the token or code is 'sent' when validation fails.",
          "MFA is a multi-step process; what happens if step 2 is skipped?"
        ]
      },
      {
        type: "fill",
        q: "In an OAuth flow, if an attacker uses 'https://victim-app.com/logout?redirect=evil.com' as a redirect_uri, they are exploiting an ______ redirect.",
        answers: ["open"],
        explain: "Open redirects in allowed subfolders or parameters can be used to bypass redirect_uri allow-lists and steal tokens.",
        hints: [
          "It's a vulnerability where a site redirects to any arbitrary URL.",
          "Starts with 'o'."
        ]
      }
    ]
  },
  {
    id: "mass-assignment",
    title: "Mass Assignment & API Authorization",
    summary: "Learn how improper mapping of user input to objects and lack of granular checks lead to BOLA and BFLA.",
    cards: [
      {
        title: "Mass Assignment (Overposting)",
        body: [
          "Mass assignment occurs when an application takes user-provided input and automatically binds it to an internal object or database model without filtering.",
          "An attacker can add extra fields to a JSON request, such as `\"role\": \"admin\"` or `\"is_premium\": true`, which the server then saves to the database.",
          "Defense: Use Data Transfer Objects (DTOs) or explicit allow-lists for allowed fields in update operations."
        ],
        code: "PATCH /api/user/profile\n{\n  \"display_name\": \"Attacker\",\n  \"role\": \"admin\" \n}",
        tone: "offense"
      },
      {
        title: "BOLA (IDOR) vs BFLA",
        body: [
          "**BOLA (Broken Object Level Authorization):** Attacker accesses a specific resource (e.g., `/api/orders/123`) that doesn't belong to them by changing the ID. Formerly known as IDOR.",
          "**BFLA (Broken Function Level Authorization):** Attacker accesses a function they shouldn't (e.g., `/api/admin/deleteUser`) because the server only checks if they are logged in, not if they are an admin.",
          "Both represent failures in the authorization logic, just at different granularities."
        ],
        tone: "info"
      },
      {
        title: "Securing Property-Level Access",
        body: [
          "Authorization must be checked at the property level, not just the object level. A user might be allowed to view their profile, but not change their 'balance' or 'subscription_tier'.",
          "Ensure that every API endpoint validates that the currently authenticated user has the right to modify the specific properties being sent in the request.",
          "Audit your ORM/Framework settings to disable 'auto-mapping' for sensitive models."
        ],
        tone: "defense"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "Which of the following is an example of BFLA (Broken Function Level Authorization)?",
        options: [
          "A user viewing another user's private photo by changing the ID in the URL",
          "A regular user successfully calling the '/api/v1/admin/export_all_users' endpoint",
          "An attacker guessing a password reset token",
          "A user changing their own display name to 'Admin'"
        ],
        answer: 1,
        explain: "BFLA occurs when a user accesses a restricted function (like an admin export) because the server failed to check their role for that specific action.",
        hints: [
          "BOLA is about 'objects' (data), BFLA is about 'functions' (actions).",
          "Which option involves an administrative action?"
        ]
      },
      {
        type: "fill",
        q: "An attacker sends a request to update their profile and includes '\"isAdmin\": true'. This attack is known as ______ assignment.",
        answers: ["mass"],
        explain: "Mass assignment (or overposting) happens when the application blindly maps all input keys to the underlying data model.",
        hints: [
          "It refers to assigning many values at once.",
          "It starts with 'm'."
        ]
      },
      {
        type: "match",
        q: "Match the vulnerability to the check that would have prevented it:",
        pairs: [
          ["BOLA", "Verify user owns resource ID 555"],
          ["BFLA", "Verify user has 'Admin' role"],
          ["Mass Assignment", "Only allow 'bio' and 'email' fields"],
          ["Authentication Bypass", "Ensure session cookie is valid"]
        ],
        explain: "Prevention requires specific checks: ownership for BOLA, roles for BFLA, and allow-lists for mass assignment.",
        hints: [
          "BOLA is about specific instances of data.",
          "Mass assignment is about which fields are updated."
        ]
      }
    ]
  },
  {
    id: "logic-flaws",
    title: "Business Logic Flaws",
    summary: "Identify vulnerabilities in application logic that allow users to bypass workflows or manipulate business rules.",
    cards: [
      {
        title: "Input Validation vs. Logic",
        body: [
          "Standard input validation checks for types and patterns (e.g., is this an email?). Logic flaws occur when the application accepts technically valid input that breaks business rules.",
          "Examples: Entering a negative quantity (`-1`) to subtract from a total price, or using a discount code intended for new users multiple times.",
          "Crucial question: 'What is this feature intended to prevent, and how can I subvert that intent?'"
        ],
        tone: "offense"
      },
      {
        title: "Workflow Bypassing",
        body: [
          "Applications often assume users follow a set sequence (e.g., Step 1 -> Step 2 -> Step 3). Attackers may try to jump directly to the final step.",
          "Example: A checkout process where the 'payment' step is skipped by navigating directly to `/checkout/success` after adding items to the cart.",
          "Defense: Track the state of the user's progress on the server and verify that each step was completed in order."
        ],
        tone: "defense"
      },
      {
        title: "TOCTOU & Race Conditions",
        body: [
          "Time-of-Check to Time-of-Use (TOCTOU) occurs when a condition is checked (e.g., 'Does user have enough balance?') but changes before the action is performed.",
          "In a web context, an attacker can send two simultaneous requests to withdraw money. If the server checks the balance for both before updating it for either, the user could withdraw more than they have.",
          "Use database locks or atomic operations to prevent race conditions in business logic."
        ],
        tone: "info"
      }
    ],
    exercises: [
      {
        type: "mc",
        q: "An attacker adds 100 items to a cart, applies a 10% discount, and then changes the quantity of 99 items to -99. What logic flaw are they likely exploiting?",
        options: [
          "Cross-Site Scripting (XSS)",
          "SQL Injection",
          "Integrity flaw via negative quantities",
          "Buffer Overflow"
        ],
        answer: 2,
        explain: "By using negative quantities, the attacker attempts to manipulate the final price calculation, potentially resulting in a negative total or a very low price.",
        hints: [
          "Think about how the price is calculated: Price * Quantity.",
          "What happens if Quantity is less than zero?"
        ]
      },
      {
        type: "order",
        q: "Order the steps to exploit a simple workflow bypass in a multi-page registration:",
        items: [
          "Start at Step 1: Account Details",
          "Observe URL for Step 3: Success/Confirmation",
          "Complete Step 1 and proceed to Step 2: Payment",
          "Manually navigate to the Step 3 URL",
          "Check if account was created without payment"
        ],
        explain: "Workflow bypasses involve skipping intermediate steps that perform validation or collect payment.",
        hints: [
          "You need to know where the finish line is first.",
          "The 'exploit' is the jump itself."
        ]
      },
      {
        type: "fill",
        q: "The vulnerability where a check and an action are performed separately, allowing the state to change in between, is abbreviated as ______.",
        answers: ["TOCTOU"],
        explain: "TOCTOU stands for Time-of-Check to Time-of-Use. It is a common source of race conditions.",
        hints: [
          "Time-Of-Check To ...",
          "It's a 6-letter acronym."
        ]
      }
    ]
  }
];
