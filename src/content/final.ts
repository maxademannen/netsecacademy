import type { Packet } from "./types";
import unit3 from "./units/unit3";
import unit4 from "./units/unit4";
import { webTraffic } from "./units/unit5";
import unit2 from "./units/unit2";
import { tcp } from "./pkt";

let id = 50000;
const shift = (ps: Packet[], dt: number) => ps.map((p) => ({ ...p, id: id++, t: p.t + dt }));

/** Mixed replay used by the IDS workbench final test. */
export const FINAL_TRAFFIC: Packet[] = [
  ...shift(unit2.lab.packets ?? [], 0),
  ...shift(unit3.lab.ruleChallenge!.traffic, 20),
  ...shift(unit4.lab.ruleChallenge!.traffic, 40),
  ...shift(webTraffic, 60),
  { ...tcp(200, "192.168.1.40", 4444, "10.0.0.20", 22, "S", { label: "spoofed-source" }), id: id++ },
].sort((a, b) => a.t - b.t);

export const INCIDENT_NAMES: Record<string, string> = {
  "dns-tunnel": "DNS tunnelling",
  "port-scan": "Port scan",
  "syn-flood": "SYN flood",
  "spoofed-source": "Spoofed RFC1918 source",
  sqli: "SQL injection",
  xss: "Cross-site scripting",
  brute: "Login brute force",
  c2: "C2 beacon",
};
