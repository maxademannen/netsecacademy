import { createFileRoute, Link, notFound, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { findLab, useComplete } from "@/lib/progress";
import { Btn, Panel, ToneTag } from "@/components/kit";
import { Terminal } from "@/components/Terminal";
import { PacketViewer } from "@/components/PacketViewer";
import { RuleEditor } from "@/components/RuleEditor";
import { AnomalyChart, stats } from "@/components/AnomalyChart";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/lab/$labId")({
  loader: ({ params }) => {
    const r = findLab(params.labId);
    if (!r) throw notFound();
    return { title: r.lab.title };
  },
  head: ({ loaderData }) => ({
    meta: [
      { title: loaderData ? `${loaderData.title} — NetSec Academy` : "Lab — NetSec Academy" },
      { name: "description", content: "Hands-on simulated network security lab." },
    ],
  }),
  notFoundComponent: () => <p className="text-muted-foreground">Lab not found.</p>,
  component: LabPage,
});

const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");

function LabPage() {
  const { labId } = Route.useParams();
  const { unit, lab } = findLab(labId)!;
  const navigate = useNavigate();
  const complete = useComplete();
  const [answers, setAnswers] = useState<string[]>(lab.tasks.map(() => ""));
  const [checked, setChecked] = useState<boolean[] | null>(null);
  const [rulePassed, setRulePassed] = useState(false);
  const [k, setK] = useState(1.5);
  const [result, setResult] = useState<{ score: number; xp: number | null } | null>(null);

  const anomalyOk = (() => {
    if (!lab.anomaly) return true;
    const { mean, sd } = stats(lab.anomaly.series);
    const thr = mean + k * sd;
    const flagged = lab.anomaly.series.map((v, i) => (v > thr ? i : -1)).filter((i) => i >= 0);
    return flagged.length === lab.anomaly.attackIdx.length && flagged.every((i) => lab.anomaly!.attackIdx.includes(i));
  })();

  async function submit() {
    const c = lab.tasks.map((t, i) => t.answers.some((a) => norm(a) === norm(answers[i])));
    setChecked(c);
    const parts = [...c];
    if (lab.ruleChallenge) parts.push(rulePassed);
    if (lab.anomaly) parts.push(anomalyOk);
    const score = (parts.filter(Boolean).length / parts.length) * 100;
    setResult({ score, xp: null });
    try {
      const xp = await complete.mutateAsync({ kind: "lab", ref: lab.id, score });
      setResult({ score, xp });
    } catch {
      toast.error("Couldn't save your lab result. Try again.");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <Link to="/learn" className="text-sm text-muted-foreground hover:text-foreground">
          ← Skill tree
        </Link>
        <div className="mt-2 flex items-center gap-2">
          <span className="font-mono text-xs text-muted-foreground">UNIT {unit.index} LAB</span>
          <ToneTag tone={lab.tone} />
        </div>
        <h1 className="text-3xl font-bold">{lab.title}</h1>
      </div>

      <Panel className="space-y-2">
        <h2 className="font-mono text-xs uppercase tracking-wider text-muted-foreground">Briefing</h2>
        {lab.briefing.map((b, i) => (
          <p key={i} className="text-foreground/90">
            {b}
          </p>
        ))}
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        {lab.terminal && (
          <section className="space-y-2">
            <h2 className="font-bold">Terminal</h2>
            <Terminal {...lab.terminal} />
          </section>
        )}
        {lab.packets && !lab.ruleChallenge && (
          <section className={cn("space-y-2", !lab.terminal && "xl:col-span-2")}>
            <h2 className="font-bold">Capture</h2>
            <PacketViewer packets={lab.packets} />
          </section>
        )}
        {lab.packets && lab.ruleChallenge && lab.packets !== lab.ruleChallenge.traffic && (
          <section className={cn("space-y-2", !lab.terminal && "xl:col-span-2")}>
            <h2 className="font-bold">Capture</h2>
            <PacketViewer packets={lab.packets} />
          </section>
        )}
      </div>

      {lab.ruleChallenge && (
        <section className="space-y-2">
          <h2 className="font-bold">Detection challenge</h2>
          <p className="text-sm text-muted-foreground">{lab.ruleChallenge.goal}</p>
          <RuleEditor traffic={lab.ruleChallenge.traffic} starter={lab.ruleChallenge.starter} onResult={(g) => setRulePassed(g.passed)} />
        </section>
      )}

      {lab.anomaly && (
        <section className="space-y-3">
          <h2 className="font-bold">Anomaly threshold</h2>
          <p className="text-sm text-muted-foreground">{lab.anomaly.goal} Adjust k until only the attack window is flagged.</p>
          <AnomalyChart series={lab.anomaly.series} k={k} unit={lab.anomaly.unit} />
          <label className="flex items-center gap-3 font-mono text-sm">
            k = {k.toFixed(1)}
            <input type="range" min={0.5} max={4} step={0.1} value={k} onChange={(e) => setK(Number(e.target.value))} className="flex-1 accent-primary" />
          </label>
          <p className={cn("font-mono text-xs", anomalyOk ? "text-primary" : "text-accent")}>
            {anomalyOk ? "✓ Only the attack window is flagged" : "✗ Threshold flags the wrong samples"}
          </p>
        </section>
      )}

      <Panel className="space-y-4">
        <h2 className="font-bold">Questions</h2>
        {lab.tasks.map((t, i) => (
          <div key={i} className="space-y-1.5">
            <label className="text-sm font-medium" htmlFor={`task-${i}`}>
              {i + 1}. {t.q}
            </label>
            <input
              id={`task-${i}`}
              value={answers[i]}
              onChange={(e) => setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))}
              className={cn(
                "w-full rounded-xl border-2 border-border bg-terminal px-3 py-2 font-mono text-sm outline-none focus:border-primary",
                checked && (checked[i] ? "border-primary" : "border-offense"),
              )}
            />
            {checked && !checked[i] && t.hint && <p className="text-xs text-accent">Hint: {t.hint}</p>}
          </div>
        ))}
        <div className="flex flex-wrap items-center gap-3">
          <Btn onClick={submit}>Submit lab</Btn>
          {result && (
            <span className="font-mono text-sm">
              Score {Math.round(result.score)}% {result.score >= 60 ? "· passed" : "· need 60%"}
              {result.xp !== null && <span className="text-primary"> · +{result.xp} XP</span>}
            </span>
          )}
          {result && result.score >= 60 && (
            <Btn variant="accent" onClick={() => navigate({ to: "/learn" })}>
              Continue
            </Btn>
          )}
        </div>
      </Panel>
    </div>
  );
}
