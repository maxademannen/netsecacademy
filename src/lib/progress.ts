import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { UNITS } from "@/content/units";
import type { Unit } from "@/content/types";

export type Kind = "lesson" | "lab" | "test";

export function useProfile() {
  return useQuery({
    queryKey: ["profile"],
    queryFn: async () => {
      const { data, error } = await supabase.rpc("get_my_profile");
      if (error) throw error;
      return data;
    },
  });
}

export function useActivity() {
  return useQuery({
    queryKey: ["activity"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("activity_log")
        .select("kind, ref_id, score, xp, created_at")
        .order("created_at", { ascending: false })
        .limit(1000);
      if (error) throw error;
      return data;
    },
  });
}

export function useComplete() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { kind: Kind; ref: string; score: number }) => {
      const { data, error } = await supabase.rpc("complete_activity", {
        _kind: v.kind,
        _ref: v.ref,
        _score: Math.round(v.score),
      });
      if (error) throw error;
      return data as number;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["profile"] });
      qc.invalidateQueries({ queryKey: ["activity"] });
    },
  });
}

export function useLoseHeart() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data, error } = await supabase.rpc("lose_heart");
      if (error) throw error;
      return data as number;
    },
    onSuccess: (h) => {
      qc.setQueryData(["profile"], (old: Record<string, unknown> | undefined) => (old ? { ...old, hearts: h } : old));
    },
  });
}

export const lessonRef = (u: Unit, lessonId: string) => `${u.id}/${lessonId}`;

export type Best = Map<string, number>;

export function bestScores(rows: { kind: string; ref_id: string; score: number }[] | undefined): Best {
  const m: Best = new Map();
  for (const r of rows ?? []) {
    const k = `${r.kind}:${r.ref_id}`;
    m.set(k, Math.max(m.get(k) ?? 0, r.score));
  }
  return m;
}

export const PASS = { lesson: 0, lab: 60, test: 80 } as const;

export function isDone(best: Best, kind: Kind, ref: string) {
  const s = best.get(`${kind}:${ref}`);
  return s !== undefined && s >= PASS[kind];
}

export type NodeState = "locked" | "open" | "done";
export interface PathNode {
  kind: Kind;
  ref: string;
  label: string;
  state: NodeState;
  to: { type: "lesson"; unitId: string; lessonId: string } | { type: "lab"; labId: string } | { type: "test"; unitId: string };
}

export function unitUnlocked(best: Best, index: number) {
  if (index === 0) return true;
  return isDone(best, "test", UNITS[index - 1].id);
}

export function unitNodes(best: Best, unit: Unit, idx: number): PathNode[] {
  const nodes: PathNode[] = [];
  let prevDone = unitUnlocked(best, idx);
  for (const l of unit.lessons) {
    const ref = lessonRef(unit, l.id);
    const done = isDone(best, "lesson", ref);
    nodes.push({
      kind: "lesson",
      ref,
      label: l.title,
      state: done ? "done" : prevDone ? "open" : "locked",
      to: { type: "lesson", unitId: unit.id, lessonId: l.id },
    });
    prevDone = done;
  }
  const labDone = isDone(best, "lab", unit.lab.id);
  nodes.push({
    kind: "lab",
    ref: unit.lab.id,
    label: unit.lab.title,
    state: labDone ? "done" : prevDone ? "open" : "locked",
    to: { type: "lab", labId: unit.lab.id },
  });
  const testDone = isDone(best, "test", unit.id);
  nodes.push({
    kind: "test",
    ref: unit.id,
    label: "Unit test",
    state: testDone ? "done" : labDone ? "open" : "locked",
    to: { type: "test", unitId: unit.id },
  });
  return nodes;
}

export function levelFromXp(xp: number) {
  const level = Math.floor(Math.sqrt(xp / 50)) + 1;
  const cur = 50 * (level - 1) ** 2;
  const next = 50 * level ** 2;
  return { level, into: xp - cur, span: next - cur };
}

export function findLab(labId: string) {
  for (const u of UNITS) if (u.lab.id === labId) return { unit: u, lab: u.lab };
  return null;
}
