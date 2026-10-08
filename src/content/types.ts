export type Proto = "TCP" | "UDP" | "ICMP" | "ARP";

export interface Packet {
  id: number;
  /** seconds since capture start */
  t: number;
  src: string;
  dst: string;
  sport?: number;
  dport?: number;
  proto: Proto;
  /** TCP flags, e.g. "S", "SA", "PA", "F", "R" */
  flags?: string;
  icmpType?: number;
  ttl?: number;
  len: number;
  payload?: string;
  /** Human summary, Wireshark-style */
  info: string;
  /** Attack incident tag used for grading detection (undefined = benign) */
  label?: string;
}

export interface Card {
  title: string;
  body: string[];
  code?: string;
  /** "offense" cards get a red treatment, "defense" green */
  tone?: "offense" | "defense" | "info";
}

interface ExBase {
  q: string;
  exhibit?: string;
  explain: string;
}

export type Exercise =
  | (ExBase & { type: "mc"; options: string[]; answer: number })
  | (ExBase & { type: "fill"; answers: string[] })
  | (ExBase & { type: "order"; items: string[] })
  | (ExBase & { type: "match"; pairs: [string, string][] })
  | (ExBase & { type: "rule"; traffic: Packet[]; starter?: string });

export interface Lesson {
  id: string;
  title: string;
  summary: string;
  cards: Card[];
  exercises: Exercise[];
}

export interface LabTask {
  q: string;
  answers: string[];
  hint?: string;
}

export interface Lab {
  id: string;
  title: string;
  briefing: string[];
  tone: "offense" | "defense";
  terminal?: { host: string; commands: Record<string, string>; hints: string[] };
  packets?: Packet[];
  ruleChallenge?: { goal: string; traffic: Packet[]; starter: string };
  anomaly?: { goal: string; series: number[]; attackIdx: number[]; unit: string };
  tasks: LabTask[];
}

export interface IdsModule {
  name: string;
  description: string;
  /** Built-in rules this module contributes to the workbench IDS */
  rules: string[];
}

export interface Unit {
  id: string;
  index: number;
  title: string;
  tagline: string;
  tone: "foundation" | "offense" | "defense";
  lessons: Lesson[];
  lab: Lab;
  ids: IdsModule;
}
