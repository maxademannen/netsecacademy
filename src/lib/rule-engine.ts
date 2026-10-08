import type { Packet } from "@/content/types";

export const HOME_NET = "10.0.0.0/24";

export interface ParsedRule {
  line: number;
  raw: string;
  action: string;
  proto: string;
  src: string;
  sport: string;
  dir: string;
  dst: string;
  dport: string;
  msg: string;
  sid: number;
  contents: string[];
  nocase: boolean;
  flags?: string;
  dsize?: string;
  itype?: number;
  pcre?: RegExp;
  threshold?: { count: number; seconds: number; track: "by_src" | "by_dst" };
}

export interface Alert {
  packetId: number;
  sid: number;
  msg: string;
}

export interface EngineResult {
  rules: ParsedRule[];
  alerts: Alert[];
  errors: { line: number; message: string }[];
}

const HEAD =
  /^\s*(alert|drop|log|pass)\s+(tcp|udp|icmp|ip)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*;?\s*$/i;

function splitOptions(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQ = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"' && s[i - 1] !== "\\") inQ = !inQ;
    if (c === ";" && !inQ) {
      if (cur.trim()) out.push(cur.trim());
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const unq = (v: string) => v.trim().replace(/^"(.*)"$/, "$1").replace(/\\"/g, '"');

export function parseRules(text: string): { rules: ParsedRule[]; errors: { line: number; message: string }[] } {
  const rules: ParsedRule[] = [];
  const errors: { line: number; message: string }[] = [];
  text.split("\n").forEach((raw, i) => {
    const line = i + 1;
    const t = raw.trim();
    if (!t || t.startsWith("#")) return;
    const mm = t.match(HEAD);
    if (!mm) {
      errors.push({ line, message: "Expected: action proto src sport -> dst dport (options;)" });
      return;
    }
    const m = Array.from(mm, (x) => x ?? "");
    const r: ParsedRule = {
      line,
      raw: t,
      action: m[1]!.toLowerCase(),
      proto: m[2]!.toLowerCase(),
      src: m[3]!,
      sport: m[4]!,
      dir: m[5]!,
      dst: m[6]!,
      dport: m[7]!,
      msg: "(no msg)",
      sid: 0,
      contents: [],
      nocase: false,
    };
    for (const opt of splitOptions(m[8]!)) {
      const idx = opt.indexOf(":");
      const key = (idx === -1 ? opt : opt.slice(0, idx)).trim().toLowerCase();
      const val = idx === -1 ? "" : opt.slice(idx + 1).trim();
      switch (key) {
        case "msg":
          r.msg = unq(val);
          break;
        case "sid":
          r.sid = Number(val) || 0;
          break;
        case "rev":
        case "classtype":
        case "reference":
        case "priority":
          break;
        case "content":
          r.contents.push(unq(val));
          break;
        case "nocase":
          r.nocase = true;
          break;
        case "flags":
          r.flags = val.toUpperCase();
          break;
        case "dsize":
          r.dsize = val.replace(/\s/g, "");
          break;
        case "itype":
          r.itype = Number(val);
          break;
        case "pcre": {
          const pm = unq(val).match(/^\/(.*)\/([a-z]*)$/);
          if (!pm) {
            errors.push({ line, message: 'pcre must look like pcre:"/regex/flags"' });
            break;
          }
          try {
            r.pcre = new RegExp(pm[1] ?? "", (pm[2] ?? "").replace(/[^gimsuy]/g, ""));
          } catch {
            errors.push({ line, message: "Invalid regular expression in pcre" });
          }
          break;
        }
        case "threshold":
        case "detection_filter": {
          const parts: Record<string, string> = Object.fromEntries(
            val.split(",").map((p) => {
              const [k, ...v] = p.trim().split(/\s+/);
              return [(k ?? "").toLowerCase(), v.join(" ")];
            }),
          );
          const count = Number(parts["count"]);
          const seconds = Number(parts["seconds"]);
          if (!count || !seconds) {
            errors.push({ line, message: `${key} needs count N, seconds S` });
            break;
          }
          r.threshold = { count, seconds, track: parts["track"] === "by_dst" ? "by_dst" : "by_src" };
          break;
        }
        default:
          errors.push({ line, message: `Unknown option "${key}"` });
      }
    }
    rules.push(r);
  });
  return { rules, errors };
}

function ipToInt(ip: string) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => isNaN(n))) return null;
  const [a = 0, b = 0, c = 0, d = 0] = p;
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}

function matchAddr(spec: string, ip: string): boolean {
  let s = spec.trim();
  if (s.startsWith("!")) return !matchAddr(s.slice(1), ip);
  if (s.startsWith("[") && s.endsWith("]")) return s.slice(1, -1).split(",").some((x) => matchAddr(x, ip));
  if (s.toLowerCase() === "any") return true;
  if (s === "$HOME_NET") s = HOME_NET;
  if (s === "$EXTERNAL_NET") return !matchAddr(HOME_NET, ip);
  const val = ipToInt(ip);
  if (val === null) return false;
  if (s.includes("/")) {
    const [base, bitsS] = s.split("/");
    const b = ipToInt(base ?? "");
    const bits = Number(bitsS);
    if (b === null) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (val & mask) === (b & mask);
  }
  return s === ip;
}

function matchPort(spec: string, port?: number): boolean {
  const s = spec.trim();
  if (s.toLowerCase() === "any") return true;
  if (s.startsWith("!")) return !matchPort(s.slice(1), port);
  if (port === undefined) return false;
  if (s.startsWith("[") && s.endsWith("]")) return s.slice(1, -1).split(",").some((x) => matchPort(x, port));
  if (s.includes(":")) {
    const [a, b] = s.split(":");
    return port >= (a ? Number(a) : 0) && port <= (b ? Number(b) : 65535);
  }
  return Number(s) === port;
}

function matchProto(rule: string, p: Packet) {
  if (rule === "ip") return p.proto !== "ARP";
  return rule === p.proto.toLowerCase();
}

function matchFlags(spec: string, flags = "") {
  if (spec === "0") return flags === "";
  const plus = spec.endsWith("+");
  const want = spec.replace(/[+*!]/g, "").split("");
  const have = flags.toUpperCase().split("");
  if (plus) return want.every((f) => have.includes(f));
  return want.length === have.length && want.every((f) => have.includes(f));
}

function matchDsize(spec: string, len: number) {
  if (spec.startsWith(">")) return len > Number(spec.slice(1));
  if (spec.startsWith("<")) return len < Number(spec.slice(1));
  if (spec.includes("<>")) {
    const [a = 0, b = 0] = spec.split("<>").map(Number);
    return len > a && len < b;
  }
  return len === Number(spec);
}

function ruleMatches(r: ParsedRule, p: Packet): boolean {
  if (!matchProto(r.proto, p)) return false;
  const fwd = matchAddr(r.src, p.src) && matchPort(r.sport, p.sport) && matchAddr(r.dst, p.dst) && matchPort(r.dport, p.dport);
  const rev =
    r.dir === "<>" &&
    matchAddr(r.src, p.dst) &&
    matchPort(r.sport, p.dport) &&
    matchAddr(r.dst, p.src) &&
    matchPort(r.dport, p.sport);
  if (!fwd && !rev) return false;
  if (r.flags && !matchFlags(r.flags, p.flags)) return false;
  if (r.itype !== undefined && p.icmpType !== r.itype) return false;
  const payload = p.payload ?? "";
  if (r.dsize && !matchDsize(r.dsize, payload.length)) return false;
  for (const c of r.contents) {
    if (r.nocase ? !payload.toLowerCase().includes(c.toLowerCase()) : !payload.includes(c)) return false;
  }
  if (r.pcre) {
    r.pcre.lastIndex = 0;
    if (!r.pcre.test(payload)) return false;
  }
  return true;
}

export function runRules(text: string, traffic: Packet[]): EngineResult {
  const { rules, errors } = parseRules(text);
  const alerts: Alert[] = [];
  const sorted = [...traffic].sort((a, b) => a.t - b.t);
  for (const r of rules) {
    if (r.action === "pass") continue;
    const windows = new Map<string, number[]>();
    for (const p of sorted) {
      if (!ruleMatches(r, p)) continue;
      if (!r.threshold) {
        alerts.push({ packetId: p.id, sid: r.sid, msg: r.msg });
        continue;
      }
      const key = r.threshold.track === "by_src" ? p.src : p.dst;
      const w = (windows.get(key) ?? []).filter((t) => p.t - t < r.threshold!.seconds);
      w.push(p.t);
      if (w.length >= r.threshold.count) {
        alerts.push({ packetId: p.id, sid: r.sid, msg: r.msg });
        windows.set(key, []);
      } else windows.set(key, w);
    }
  }
  return { rules, alerts, errors };
}

export interface Grade {
  incidents: string[];
  detected: string[];
  missed: string[];
  falsePositives: number[];
  passed: boolean;
  score: number;
}

export function gradeDetection(traffic: Packet[], alerts: Alert[]): Grade {
  const byId = new Map(traffic.map((p) => [p.id, p]));
  const incidents = [...new Set(traffic.filter((p) => p.label).map((p) => p.label!))];
  const detectedSet = new Set<string>();
  const fps = new Set<number>();
  for (const a of alerts) {
    const p = byId.get(a.packetId);
    if (!p) continue;
    if (p.label) detectedSet.add(p.label);
    else fps.add(p.id);
  }
  const detected = incidents.filter((i) => detectedSet.has(i));
  const missed = incidents.filter((i) => !detectedSet.has(i));
  const base = incidents.length ? detected.length / incidents.length : 1;
  const score = Math.max(0, Math.round(base * 100 - fps.size * 15));
  return { incidents, detected, missed, falsePositives: [...fps], passed: missed.length === 0 && fps.size === 0, score };
}
