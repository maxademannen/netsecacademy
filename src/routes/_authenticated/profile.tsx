import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { UNITS, totalLessons } from "@/content/units";
import { bestScores, isDone, levelFromXp, useActivity, useProfile, lessonRef } from "@/lib/progress";
import { Btn, Panel } from "@/components/kit";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/profile")({
  head: () => ({
    meta: [
      { title: "Profile — NetSec Academy" },
      { name: "description", content: "Your stats, badges and progress." },
      { property: "og:title", content: "Profile — NetSec Academy" },
      { property: "og:description", content: "Your stats, badges and progress." },
    ],
  }),
  component: Profile,
});

function Profile() {
  const { data: p } = useProfile();
  const { data: activity } = useActivity();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  useEffect(() => setName(p?.username ?? ""), [p?.username]);
  const best = bestScores(activity);
  const lessonsDone = UNITS.reduce((n, u) => n + u.lessons.filter((l) => isDone(best, "lesson", lessonRef(u, l.id))).length, 0);
  const labsDone = UNITS.filter((u) => isDone(best, "lab", u.lab.id)).length;
  const unitsDone = UNITS.filter((u) => isDone(best, "test", u.id)).length;
  const lvl = levelFromXp(p?.xp ?? 0);

  const badges = [
    { icon: "▤", name: "First packet", desc: "Finish a lesson", got: lessonsDone > 0 },
    { icon: "⌨", name: "Hands on keyboard", desc: "Pass a lab", got: labsDone > 0 },
    { icon: "☠", name: "Red team", desc: "Pass Recon & Scanning", got: isDone(best, "test", "recon") },
    { icon: "⛨", name: "Blue team", desc: "Pass Signature Detection", got: isDone(best, "test", "signatures") },
    { icon: "🔥", name: "On fire", desc: "7-day streak", got: (p?.longest_streak ?? 0) >= 7 },
    { icon: "◈", name: "Grinder", desc: "Earn 500 XP", got: (p?.xp ?? 0) >= 500 },
    { icon: "★", name: "IDS architect", desc: "Complete the IDS capstone", got: isDone(best, "lab", "final-ids") },
  ];

  async function save() {
    const v = name.trim();
    if (v.length < 2 || v.length > 24) {
      toast.error("Username must be 2–24 characters.");
      return;
    }
    const { error } = await supabase.from("profiles").update({ username: v }).eq("id", p!.id);
    if (error) {
      toast.error("Couldn't save.");
      return;
    }
    qc.invalidateQueries({ queryKey: ["profile"] });
    toast.success("Saved");
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <h1 className="text-3xl font-bold">{p?.username}</h1>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ["Level", lvl.level],
          ["Total XP", p?.xp ?? 0],
          ["Streak", `${p?.streak ?? 0} 🔥`],
          ["Best streak", p?.longest_streak ?? 0],
        ].map(([k, v]) => (
          <Panel key={k as string} className="p-4">
            <p className="text-xs text-muted-foreground">{k}</p>
            <p className="font-mono text-2xl font-bold">{v}</p>
          </Panel>
        ))}
      </div>
      <Panel>
        <p className="text-sm text-muted-foreground">Level {lvl.level} → {lvl.level + 1}</p>
        <div className="mt-2 h-3 overflow-hidden rounded-full bg-secondary">
          <div className="h-full bg-primary" style={{ width: `${(lvl.into / lvl.span) * 100}%` }} />
        </div>
        <p className="mt-3 font-mono text-xs text-muted-foreground">
          {lessonsDone}/{totalLessons()} lessons · {labsDone}/{UNITS.length} labs · {unitsDone}/{UNITS.length} units
        </p>
      </Panel>
      <Panel>
        <h2 className="mb-3 font-bold">Badges</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {badges.map((b) => (
            <div key={b.name} className={cn("rounded-xl border-2 p-3 text-center", b.got ? "border-accent/60 bg-accent/10" : "border-border opacity-40")}>
              <p className="text-3xl">{b.icon}</p>
              <p className="mt-1 text-sm font-bold">{b.name}</p>
              <p className="text-xs text-muted-foreground">{b.desc}</p>
            </div>
          ))}
        </div>
      </Panel>
      <Panel className="space-y-3">
        <h2 className="font-bold">Username</h2>
        <div className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            aria-label="Username"
            className="flex-1 rounded-xl border-2 border-border bg-terminal px-3 py-2 outline-none focus:border-primary"
          />
          <Btn onClick={save}>Save</Btn>
        </div>
      </Panel>
    </div>
  );
}
