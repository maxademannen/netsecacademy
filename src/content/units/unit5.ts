import type { Unit } from "../types";
import { http, tcp } from "../pkt";

const webTraffic = [
  http(0.1, "10.0.0.12", "10.0.0.20", "GET /products HTTP/1.1\nHost: shop.local\nUser-Agent: Mozilla/5.0"),
  http(0.5, "10.0.0.12", "10.0.0.20", "GET /search?q=router HTTP/1.1\nHost: shop.local\nUser-Agent: Mozilla/5.0"),
  http(
    1.0,
    "203.0.113.55",
    "10.0.0.20",
    "GET /search?q=' UNION SELECT username,password FROM users-- HTTP/1.1\nHost: shop.local\nUser-Agent: sqlmap/1.7",
    { label: "sqli" },
  ),
  http(
    1.5,
    "203.0.113.55",
    "10.0.0.20",
    "POST /comment HTTP/1.1\nHost: shop.local\nContent-Length: 54\n\ntext=<script>fetch('/steal?c='+document.cookie)</script>",
    { label: "xss" },
  ),
  ...Array.from({ length: 25 }, (_, i) =>
    http(2 + i * 0.05, "203.0.113.90", "10.0.0.20", `POST /login HTTP/1.1\nHost: shop.local\nContent-Length: 40\n\nuser=admin&pass=guess${i}`, {
      label: "brute",
    }),
  ),
  http(5.0, "10.0.0.44", "203.0.113.200", "GET /checkin HTTP/1.1\nHost: cdn.evil.io\nUser-Agent: Mozilla/5.0", { label: "c2" }),
  http(35.0, "10.0.0.44", "203.0.113.200", "GET /checkin HTTP/1.1\nHost: cdn.evil.io\nUser-Agent: Mozilla/5.0", { label: "c2" }),
  http(65.0, "10.0.0.44", "203.0.113.200", "GET /checkin HTTP/1.1\nHost: cdn.evil.io\nUser-Agent: Mozilla/5.0", { label: "c2" }),
  http(95.0, "10.0.0.44", "203.0.113.200", "GET /checkin HTTP/1.1\nHost: cdn.evil.io\nUser-Agent: Mozilla/5.0", { label: "c2" }),
];

const unit5: Unit = {
  id: "web",
  index: 5,
  title: "Web & App Attacks",
  tagline: "The payloads that show up in plain text — if you look.",
  tone: "offense",
  lessons: [
    {
      id: "sqli-xss",
      title: "SQLi and XSS, briefly",
      summary: "Enough to recognise and alert on them.",
      cards: [
        {
          title: "SQL injection in one picture",
          body: [
            "The app concatenates user input into a SQL query. The attacker closes the quote and appends their own clause.",
            "Classic markers in the URL or body: a single quote, UNION SELECT, OR 1=1, SQL comment markers (-- or /*).",
          ],
          tone: "offense",
          code: `/search?q=' UNION SELECT username, password FROM users--`,
        },
        {
          title: "Reflected / stored XSS",
          body: [
            "User-supplied HTML is rendered back without escaping. A <script> tag lands in another user's browser and does whatever the attacker wants with that session.",
            "Rule-visible markers: <script, javascript:, onerror=, onload=, document.cookie.",
          ],
          tone: "offense",
        },
        {
          title: "Why signatures still work here",
          body: [
            "Serious attackers obfuscate — but automated scanners (sqlmap, nikto, nuclei) do not, and they are the overwhelming majority of what hits the internet.",
            "A rule that catches sqlmap by its default User-Agent is one of the best cost/value ratios in detection.",
          ],
          tone: "defense",
        },
      ],
      exercises: [
        {
          type: "mc",
          exhibit: "GET /?q=1' OR '1'='1 HTTP/1.1",
          q: "What is this?",
          options: ["Normal search", "A simple SQL injection", "An XSS attempt", "A path traversal"],
          answer: 1,
          explain: "The injected OR condition is always true, bypassing WHERE filtering.",
        },
        {
          type: "fill",
          q: "Name one HTTP header that frequently self-identifies an attack tool.",
          answers: ["user-agent", "user agent"],
          explain: "User-Agent. sqlmap, nmap, nikto, nuclei and masscan all set recognisable defaults.",
        },
      ],
    },
    {
      id: "brute-c2",
      title: "Brute force and C2 beacons",
      summary: "Behaviour-based detection where single packets look fine.",
      cards: [
        {
          title: "Brute force",
          body: [
            "No single login request is malicious. Twenty-five from the same IP in five seconds against /login is.",
            "Threshold rules on failed-login responses are more accurate than on requests, but you need visibility into the response code.",
          ],
          tone: "defense",
        },
        {
          title: "Command & control beacons",
          body: [
            "An implanted host checks in with its operator on a schedule — often every 30 or 60 seconds, sometimes with jitter.",
            "The individual requests look like normal HTTPS. The regularity is what gives it away.",
          ],
          tone: "offense",
          code: `every ~30 s:  10.0.0.44  ->  cdn.evil.io   GET /checkin
no human browses that evenly.`,
        },
      ],
      exercises: [
        {
          type: "mc",
          q: "Which signal most reliably reveals a C2 beacon?",
          options: [
            "The destination port",
            "The TLS cipher",
            "The regular, near-uniform interval between requests",
            "The size of the response",
          ],
          answer: 2,
          explain: "People browse in bursts. Automation produces a flat, periodic rhythm — detectable even over HTTPS.",
        },
        {
          type: "rule",
          q: "Write a brute-force rule for /login on 10.0.0.20.",
          traffic: webTraffic,
          starter:
            'alert tcp any any -> $HOME_NET 80 (msg:"Possible brute force on /login"; content:"POST /login"; threshold: type threshold, track by_src, count 10, seconds 10; sid:1000030;)\n',
          explain: "A content match on 'POST /login' plus a by_src threshold catches the burst while sparing one real login.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-web",
    title: "Lab: web attack hunt",
    tone: "defense",
    briefing: [
      "A capture from the shop web server includes normal browsing, a SQL injection, an XSS attempt, a login brute force and a periodic beacon.",
      "Catch all four with rules, without alerting on the two normal page views.",
    ],
    packets: webTraffic,
    ruleChallenge: {
      goal: "Catch sqli, xss, brute and c2. Zero false positives on the two normal page views.",
      traffic: webTraffic,
      starter:
        '# HOME_NET = 10.0.0.0/24. Four rules, one per incident.\nalert tcp any any -> $HOME_NET 80 (msg:"SQL injection UNION SELECT"; content:"UNION SELECT"; nocase; sid:1000040;)\nalert tcp any any -> $HOME_NET 80 (msg:"XSS <script>"; content:"<script"; nocase; sid:1000041;)\nalert tcp any any -> $HOME_NET 80 (msg:"Brute force /login"; content:"POST /login"; threshold: type threshold, track by_src, count 10, seconds 10; sid:1000042;)\nalert tcp $HOME_NET any -> any 80 (msg:"Beacon to cdn.evil.io"; content:"Host: cdn.evil.io"; sid:1000043;)\n',
    },
    tasks: [
      { q: "Which HTTP method does the SQLi use?", answers: ["get"], hint: "Look at the request line of the sqlmap request." },
      { q: "What JavaScript function does the XSS payload call to send the cookie?", answers: ["fetch"], hint: "Read the POST /comment body." },
      { q: "Approximately how many login attempts in the brute burst?", answers: ["25"], hint: "Count the POSTs to /login." },
      { q: "What is the beacon's approximate interval in seconds?", answers: ["30"], hint: "Subtract adjacent timestamps." },
    ],
  },
  ids: {
    name: "Payload signatures",
    description: "Your IDS now content-matches HTTP payloads and detects classic SQLi, XSS and known-bad hosts.",
    rules: [
      'alert tcp any any -> $HOME_NET 80 (msg:"IDS: SQLi UNION SELECT"; content:"UNION SELECT"; nocase; sid:9005001;)',
      'alert tcp any any -> $HOME_NET 80 (msg:"IDS: XSS script tag"; content:"<script"; nocase; sid:9005002;)',
      'alert tcp any any -> $HOME_NET 80 (msg:"IDS: Known bad UA sqlmap"; content:"User-Agent: sqlmap"; sid:9005003;)',
      'alert tcp any any -> $HOME_NET 80 (msg:"IDS: Brute force POST /login"; content:"POST /login"; threshold: type threshold, track by_src, count 10, seconds 10; sid:9005004;)',
    ],
  },
};

export { webTraffic };
export default unit5;
