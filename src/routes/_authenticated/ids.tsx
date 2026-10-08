import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { UNITS } from "@/content/units";
import { FINAL_TRAFFIC, INCIDENT_NAMES } from "@/content/final";
import { bestScores, isDone, useActivity, useComplete } from "@/lib/progress";
import { gradeDetection, runRules, type Grade, type Alert } from "@/lib/rule-engine";
import { Btn, Panel } from "@/components/kit";
import { PacketViewer } from "@/components/PacketViewer";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/ids")({
  head: () => ({
    meta: [
      { title: "IDS Workbench — NetSec Academy" },
      { name: "description", content: "Assemble and test the intrusion detection system you built module by module." },
      { property: "og:title", content: "IDS Workbench — NetSec Academy" },
      { property: "og:description", content: "Assemble and test the intrusion detection system you built module by module." },
    ],
  }),
  component: IdsPage,
});

const STORAGE = "netsec.customRules";

function IdsPage() {
  const { data: activity } = useActivity();
  const best = bestScores(activity);
  const complete = useComplete();
  const online = UNITS.map((u) => isDone(best, "test", u.id));
  const engineOnline = online[6];
  const [custom, setCustom] = useState("");
  const [run, setRun] = useState<{ grade: Grade; alerts: Alert[] } | null>(null);
  const finalDone = isDone(best, "lab", "final-ids");

  useEffect(() => {
    setCustom(localStorage.getItem(STORAGE) ?? "# Your own rules (unlocked with the Rule engine module)\n");
  }, []);

  async function replay() {
    localStorage.setItem(STORAGE, custom);
    const rules = UNITS.filter((_, i) => online[i]).flatMap((u) => u.ids.rules);
    const text = rules.join("\n") + (engineOnline ? "\n" + custom : "");
    const res = runRules(text, FINAL_TRAFFIC);
    const grade = gradeDetection(FINAL_TRAFFIC, res.alerts);
    setRun({ grade, alerts: res.alerts });
    if (grade.passed && online.every(Boolean) && !finalDone) {
      try {
        const xp = await complete.mutateAsync({ kind: "lab", ref: "final-ids", score: 100 });
        toast.success(`Your IDS caught everything. +${xp} XP`);
      } catch {
        toast.error("Couldn't save the result.");
      }
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <p className="font-mono text-xs text-muted-foreground">CAPSTONE</p>
        <h1 className="text-3xl font-bold">IDS Workbench</h1>
        <p className="mt-1 max-w-2xl text-muted-foreground">
          Every unit test you pass brings a module of your intrusion detection system online. Replay the mixed attack capture and
          see what your IDS catches — and what slips through.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {UNITS.map((u, i) => (
          <div
            key={u.id}
            className={cn(
              "rounded-2xl border-2 p-4",
              online[i] ? "glow border-primary/60 bg-primary/10" : "border-dashed border-border bg-card/50",
            )}
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] text-muted-foreground">MOD {u.index}</span>
              <span className={cn("font-mono text-[10px] font-bold", online[i] ? "text-primary" : "text-muted-foreground")}>
                {online[i] ? "ONLINE" : "OFFLINE"}
              </span>
            </div>
            <h3 className="mt-1 font-bold">{u.ids.name}</h3>
            <p className="mt-1 text-xs text-muted-foreground">{u.ids.description}</p>
            {u.ids.rules.length > 0 && <p className="mt-2 font-mono text-[10px] text-muted-foreground">{u.ids.rules.length} built-in rules</p>}
          </div>
        ))}
      </div>

      <Panel className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-bold">Custom rules</h2>
          {!engineOnline && <span className="font-mono text-xs text-accent">Unlocks with the Rule engine module (unit 7)</span>}
        </div>
        <textarea
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          disabled={!engineOnline}
          rows={5}
          spellCheck={false}
          aria-label="Custom IDS rules"
          className="w-full rounded-xl border-2 border-border bg-terminal p-3 font-mono text-xs outline-none focus:border-primary disabled:opacity-50"
        />
        <Btn variant="accent" onClick={replay}>
          ▶ Replay attack capture ({FINAL_TRAFFIC.length} packets)
        </Btn>
      </Panel>

      {run && (
        <Panel className="space-y-4">
          <div className="flex flex-wrap items-baseline gap-4">
            <h2 className="text-xl font-bold">Detection report</h2>
            <span className="font-mono text-primary">
              {run.grade.detected.length}/{run.grade.incidents.length} incidents
            </span>
            <span className={cn("font-mono", run.grade.falsePositives.length ? "text-offense" : "text-muted-foreground")}>
              {run.grade.falsePositives.length} false positives
            </span>
            <span className="font-mono text-muted-foreground">{run.alerts.length} alerts</span>
          </div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {run.grade.incidents.map((i) => {
              const hit = run.grade.detected.includes(i);
              return (
                <div key={i} className={cn("rounded-xl border-2 p-3 text-sm", hit ? "border-primary/50 bg-primary/10" : "border-offense/50 bg-offense/10")}>
                  <span className="font-bold">{hit ? "✓ Caught" : "✗ Missed"}</span>
                  <p className="text-muted-foreground">{INCIDENT_NAMES[i] ?? i}</p>
                </div>
              );
            })}
          </div>
          {run.grade.passed && online.every(Boolean) && (
            <p className="rounded-xl border-2 border-accent bg-accent/10 p-4 text-center font-bold text-accent">
              ★ Your IDS is complete. Every attack in the replay was detected with zero false positives.
            </p>
          )}
          <PacketViewer packets={FINAL_TRAFFIC} highlight={new Set(run.alerts.map((a) => a.packetId))} falsePositive={new Set(run.grade.falsePositives)} />
        </Panel>
      )}
    </div>
  );
}
