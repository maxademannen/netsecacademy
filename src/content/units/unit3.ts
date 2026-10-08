import type { Unit } from "../types";

const unit3: Unit = {
  id: "scanning",
  index: 3,
  title: "Scanning & Enumeration",
  tagline: "Turn 'host is up' into 'here are 14 attack surfaces'.",
  tone: "offense",
  lessons: [
    {
      id: "scan-types",
      title: "Nmap, the proper way",
      summary: "SYN, connect, UDP, version, scripts — and when to use which.",
      cards: [
        {
          title: "The techniques",
          body: ["Every scan is a question asked with a crafted packet. The response — or silence — is the answer."],
          code: `-sS  SYN / half-open  : fast, needs root, default when privileged
-sT  TCP connect     : no root required, loud (full handshake, logs connection)
-sU  UDP scan        : slow; closed replies ICMP port-unreachable, open stays silent
-sV  version detect  : banner-grab + probes; feeds everything downstream
-O   OS detect       : stack-fingerprint
-sC  default scripts : runs nmap NSE scripts — tons of free wins
-A   = -sV -sC -O --traceroute   kitchen sink
--top-ports 1000     : the ports actually worth scanning first
-p-                  : all 65535. slow, but you must do it at least once per target
-T4                  : timing, 0 (paranoid) to 5 (insane). 4 is normal.`,
        },
        {
          title: "A pragmatic workflow",
          body: [
            "Pass 1: `-sS --top-ports 1000 -T4` across the IP range. Finds 95% of services in minutes.",
            "Pass 2: `-sS -p- -T4` on hosts that looked interesting. Catches the services on weird ports.",
            "Pass 3: `-sV -sC -p <found ports>` for versions + scripts. This is where CVEs fall out.",
            "Pass 4: `-sU --top-ports 100` for UDP. SNMP, DNS, NTP and friends.",
          ],
          code: `nmap -sS -T4 --top-ports 1000 -oA quick 198.51.100.0/24
nmap -sS -T4 -p- -oA deep 198.51.100.17 198.51.100.42
nmap -sV -sC -p22,80,443,8080,5984,27017 -oA versions 198.51.100.17`,
          tone: "offense",
        },
        {
          title: "Output you want to keep",
          body: [
            "`-oA basename` saves .nmap (human), .gnmap (grepable), .xml (parseable). Always use it — you will come back.",
            "Pipe gnmap into `grep -w 'open'` to list every open port across the scan.",
          ],
        },
      ],
      exercises: [
        {
          type: "match",
          q: "Match the flag to what it does.",
          pairs: [
            ["-sS", "SYN half-open scan (default when root)"],
            ["-sV", "Service / version detection"],
            ["-sC", "Run default NSE scripts"],
            ["-sU", "UDP scan"],
            ["-p-", "All 65535 TCP ports"],
          ],
          explain: "These are the five flags you'll use most. Memorise them.",
        },
        {
          type: "mc",
          q: "You scanned top-1000 ports, found nothing on a host your recon said was interesting. Next step?",
          options: ["Give up", "Run -p- (all 65535 ports) — admins hide services on weird ports", "Reboot the router", "Switch to IPv6"],
          answer: 1,
          explain: "SSH on 22222, Jenkins on 50000, Elastic on 9200 — never trust the top-1000.",
        },
        {
          type: "mc",
          q: "A UDP port shows 'open|filtered'. What does nmap mean?",
          options: [
            "It is both",
            "No reply came back; could be open and silent, or filtered by a firewall",
            "The host is Windows",
            "The port is encrypted",
          ],
          answer: 1,
          explain: "UDP has no handshake, so silence is ambiguous. `-sV` on the same port often resolves it.",
        },
      ],
    },
    {
      id: "service-enum",
      title: "Service enumeration",
      summary: "Once a port is open, what do you do with it?",
      cards: [
        {
          title: "Per-service checklists",
          body: ["Each service has a short list of 'always try this first' moves. These are the bulk of the easy wins."],
          code: `# SSH 22
nmap --script ssh2-enum-algos,ssh-auth-methods -p22 <ip>
ssh root@<ip>                      # does the banner say 'OpenSSH 7.4'? CVE lookup time.

# HTTP(S) 80/443/8080/8443  — see Unit 4

# FTP 21
nmap --script ftp-anon,ftp-syst -p21 <ip>
ftp <ip>  → USER anonymous / PASS anonymous

# SMB 139/445
smbclient -L //<ip> -N              # null session
enum4linux-ng -A <ip>
nmap --script smb-vuln-* -p445 <ip>

# DNS 53
dig AXFR @<ip> target.example       # zone transfer

# SMTP 25/587
nmap --script smtp-enum-users,smtp-commands -p25 <ip>

# SNMP 161 (UDP)  — "public" community string still wins constantly
onesixtyone -c communities.txt <ip>
snmpwalk -v2c -c public <ip>

# Databases
# 3306 mysql / 5432 postgres / 1433 mssql / 27017 mongo / 6379 redis / 9200 elastic
# default creds + unauthenticated access are shockingly common on cloud VMs.`,
          tone: "offense",
        },
        {
          title: "The pattern",
          body: [
            "Grab the banner → look up the version → check default creds → run an NSE/metasploit module → read the docs for 'disabled by default' auth features that someone forgot to enable.",
          ],
          tone: "offense",
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Which community string is still, in 2026, the single most common SNMP finding?",
          answers: ["public"],
          explain: "Default. snmpwalk -v2c -c public reads MIBs with no auth and often leaks system info and configs.",
        },
        {
          type: "mc",
          q: "You find port 6379 open, no password required. What is it and what is the risk?",
          options: [
            "Redis — if write access, often leads to RCE via config writes to authorized_keys",
            "A game server, harmless",
            "An email port",
            "A time server",
          ],
          answer: 0,
          explain:
            "Unauth Redis is a classic RCE: `CONFIG SET dir /root/.ssh/`, `CONFIG SET dbfilename authorized_keys`, `SET x '<your ssh key>'`, `BGSAVE`. Report, don't exploit.",
        },
      ],
    },
    {
      id: "web-content",
      title: "Content discovery",
      summary: "Finding the endpoints the sitemap doesn't mention.",
      cards: [
        {
          title: "Why wordlists win",
          body: [
            "Half the interesting URLs on any site are not linked from the homepage: /admin, /backup, /api/v2, /debug, /.git, /.env, /old, /api/internal.",
            "A good wordlist run against a host finds them in minutes.",
          ],
          code: `# directory brute force
ffuf -u https://target.example/FUZZ -w /lists/common.txt -mc 200,204,301,302,403 -ac
feroxbuster -u https://target.example -w /lists/raft-medium.txt -x php,bak,old,txt -C 404 -t 50

# virtual hosts (Host header)
ffuf -u https://target.example/ -H "Host: FUZZ.target.example" -w subs.txt -fs 1234

# parameter brute force
arjun -u https://target.example/api/v1/user -m GET
ffuf -u 'https://target.example/api/v1/user?FUZZ=admin' -w params.txt -fs 42`,
          tone: "offense",
        },
        {
          title: "Status-code reading",
          body: [
            "200 — exists and returned content.",
            "301/302 — exists and redirects. Follow it; often lands on an interesting page.",
            "401/403 — exists but auth-required. Try the IDOR/ACL bypasses from Unit 4.",
            "429 — rate-limited. Lower threads, add --delay, or rotate IPs.",
          ],
        },
        {
          title: "Wordlists",
          body: [
            "SecLists is the standard. Within it:",
            "- Discovery/Web-Content/raft-medium-* for directories/files.",
            "- Discovery/DNS/subdomains-top1million-*.txt for subdomains.",
            "- Discovery/Web-Content/burp-parameter-names.txt for params.",
            "Smaller, targeted lists beat a 1-million-word blast every time.",
          ],
        },
      ],
      exercises: [
        {
          type: "fill",
          q: "Name the single most-used wordlist collection in bug bounty.",
          answers: ["seclists", "SecLists"],
          explain: "SecLists on GitHub. Thousands of curated wordlists, maintained for years.",
        },
        {
          type: "mc",
          q: "ffuf keeps returning 200 for every path with the same content length. What do you do?",
          options: [
            "Give up — the server is impenetrable",
            "Add -fs <length> to filter responses of that exact size (a soft 404)",
            "Switch to UDP",
            "Scan a different host",
          ],
          answer: 1,
          explain: "Soft 404s. The server returns 200 with a 'not found' page. -fs or -ac (auto-calibration) solves it.",
        },
      ],
    },
  ],
  lab: {
    id: "lab-scan",
    title: "Lab: scan and enumerate",
    tone: "offense",
    briefing: [
      "Target: 10.0.0.20, the shop server from the previous unit.",
      "Phase 1: scan, find all open ports and identify versions.",
      "Phase 2: enumerate the interesting ones.",
      "The flag is hidden somewhere in the enumeration output. Format: FLAG{...}",
    ],
    terminal: {
      host: "hunter@kali",
      commands: {
        "nmap -sS --top-ports 1000 10.0.0.20":
          "Nmap scan report for 10.0.0.20\nPORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\nNmap done: 1 host up, 3 ports.",
        "nmap -sS -p- 10.0.0.20":
          "PORT      STATE SERVICE\n22/tcp    open  ssh\n80/tcp    open  http\n443/tcp   open  https\n2049/tcp  open  nfs\n8080/tcp  open  http-proxy\n27017/tcp open  mongodb\n50000/tcp open  ibm-db2",
        "nmap -sV -sC -p22,80,443,8080,27017,50000 10.0.0.20":
          "22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)\n|_ssh-hostkey: 2048 ...\n80/tcp    open  http        Apache httpd 2.4.29\n|_http-title: Shop Example\n443/tcp   open  ssl/http    Apache httpd 2.4.29\n8080/tcp  open  http        Jetty 9.4.z-SNAPSHOT\n|_http-title: Jenkins [Jenkins]\n|_http-server-header: Jetty(9.4.z-SNAPSHOT)\n27017/tcp open  mongodb     MongoDB 3.6.3 (no auth)\n|_mongodb-databases: admin, config, local, shopdata\n50000/tcp open  ibm-db2?    DB2 10.5",
        "curl -s http://10.0.0.20:8080/":
          "<html><head><title>Jenkins</title></head><body>Welcome to Jenkins!<br><a href='/script'>Script Console</a> | <a href='/login'>sign in</a></body></html>",
        "mongo --host 10.0.0.20 --eval 'db.getSiblingDB(\"shopdata\").secrets.find().toArray()'":
          '[\n  { "_id": 1, "key": "adminPanelFlag", "value": "FLAG{m0ng0_w1th_n0_auth_1s_a_gift}" },\n  { "_id": 2, "key": "note", "value": "move secrets to Vault, 2019-11" }\n]',
        "ffuf -u http://10.0.0.20/FUZZ -w common.txt -mc 200,301,403 -silent":
          "admin                   [Status: 403, Size: 199]\nbackup                  [Status: 301, Size: 0]\nphpinfo.php             [Status: 200, Size: 72014]\nrobots.txt              [Status: 200, Size: 72]\n.git/HEAD               [Status: 200, Size: 23]",
        "curl -s http://10.0.0.20/robots.txt":
          "User-agent: *\nDisallow: /admin\nDisallow: /old-staff-portal\nDisallow: /api/internal/v1",
        "curl -s http://10.0.0.20/.git/HEAD":
          "ref: refs/heads/main",
        "ssh root@10.0.0.20": "ssh: connect refused by host — key auth only. Enumeration lab, not real exploitation.",
      },
      hints: [
        "nmap -sS --top-ports 1000 10.0.0.20",
        "nmap -sS -p- 10.0.0.20",
        "nmap -sV -sC -p22,80,443,8080,27017,50000 10.0.0.20",
        "ffuf -u http://10.0.0.20/FUZZ -w common.txt -mc 200,301,403 -silent",
        "curl -s http://10.0.0.20/robots.txt",
        "curl -s http://10.0.0.20/.git/HEAD",
        "curl -s http://10.0.0.20:8080/",
        "mongo --host 10.0.0.20 --eval 'db.getSiblingDB(\"shopdata\").secrets.find().toArray()'",
      ],
    },
    tasks: [
      {
        q: "How many TCP ports are open on 10.0.0.20 after a full -p- scan?",
        answers: ["7"],
        hint: "Count the entries in `nmap -sS -p- 10.0.0.20`.",
      },
      {
        q: "Which port runs an unauthenticated MongoDB that leaks the shopdata database?",
        answers: ["27017"],
        hint: "The -sV output names it.",
      },
      {
        q: "Which path discovered by ffuf should be reported as critical by itself (source-code disclosure)?",
        answers: [".git/head", ".git", ".git/HEAD"],
        hint: "An exposed .git directory often leaks the full source tree history.",
      },
      {
        q: "What is the flag? Format FLAG{...}",
        answers: ["FLAG{m0ng0_w1th_n0_auth_1s_a_gift}", "m0ng0_w1th_n0_auth_1s_a_gift"],
        hint: "Query the Mongo secrets collection.",
      },
    ],
  },
  ids: {
    name: "Scanner toolkit",
    description:
      "You can run nmap in the right phases, enumerate per-service, and brute-force content with ffuf — the daily routine of every hunter.",
    rules: [],
  },
};

export default unit3;
