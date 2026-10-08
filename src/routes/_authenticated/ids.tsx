import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { UNITS } from "@/content/units";
import { CAPSTONE_FLAG, CAPSTONE_STEPS } from "@/content/final";
import { CAPSTONES, type Capstone } from "@/content/capstones";
import { bestScores, isDone, useActivity, useComplete } from "@/lib/progress";
import { Btn, Panel } from "@/components/kit";
import { cn } from "@/lib/utils";
import { toast } from "sonner";


export const Route = createFileRoute("/_authenticated/ids")({
  head: () => ({
    meta: [
      { title: "Toolkit & Capstone — NetSec Academy" },
      {
        name: "description",
        content: "Your hacker's toolkit and the final chained CTF — turn every skill into one bounty-grade report.",
      },
      { property: "og:title", content: "Toolkit & Capstone — NetSec Academy" },
      {
        property: "og:description",
        content: "Your hacker's toolkit and the final chained CTF.",
      },
    ],
  }),
  component: ToolkitPage,
});

const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");

function ToolkitPage() {
  const { data: activity } = useActivity();
  const best = bestScores(activity);
  const complete = useComplete();
  const online = UNITS.map((u) => isDone(best, "test", u.id));
  const unlocked = online.every(Boolean);
  const finalDone = isDone(best, "lab", "final-chain");

  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [answers, setAnswers] = useState<string[]>(CAPSTONE_STEPS.map(() => ""));
  const [checked, setChecked] = useState<(boolean | null)[]>(CAPSTONE_STEPS.map(() => null));
  const [submitted, setSubmitted] = useState<{ score: number; xp: number | null } | null>(null);

  function check(i: number) {
    const ok = CAPSTONE_STEPS[i]!.answers.some((a) => norm(a) === norm(answers[i] ?? ""));
    setChecked((c) => c.map((v, j) => (j === i ? ok : v)));
  }

  async function submit() {
    const score = (checked.filter((v) => v === true).length / CAPSTONE_STEPS.length) * 100;
    setSubmitted({ score, xp: null });
    try {
      const xp = await complete.mutateAsync({ kind: "lab", ref: "final-chain", score });
      setSubmitted({ score, xp });
      if (score === 100) toast.success(`Capstone complete. +${xp} XP`);
    } catch {
      toast.error("Couldn't save the capstone result.");
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <p className="font-mono text-xs text-muted-foreground">TOOLKIT &amp; CAPSTONE</p>
        <h1 className="text-3xl font-bold">Your hacker's toolkit</h1>
        <p className="mt-1 max-w-2xl text-muted-foreground">
          Each unit test you pass unlocks a skill set here. Once all eight are green, the final chained CTF opens — a realistic
          bug-bounty workflow from recon to a critical write-up.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {UNITS.map((u, i) => (
          <div
            key={u.id}
            className={cn(
              "rounded-2xl border-2 p-4",
              online[i] ? "glow border-primary/60 bg-primary/10" : "border-dashed border-border bg-card/50 opacity-70",
            )}
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] text-muted-foreground">SKILL 0{u.index}</span>
              <span className={cn("font-mono text-[10px] font-bold", online[i] ? "text-primary" : "text-muted-foreground")}>
                {online[i] ? "UNLOCKED" : "LOCKED"}
              </span>
            </div>
            <h3 className="mt-1 font-bold">{u.ids.name}</h3>
            <p className="mt-1 text-xs text-muted-foreground">{u.ids.description}</p>
          </div>
        ))}
      </div>

      <Panel
        className={cn(
          "space-y-4",
          unlocked ? "border-accent/60 bg-accent/5" : "opacity-60",
        )}
      >
        <div>
          <p className="font-mono text-xs text-accent">FINAL · CHAINED CTF</p>
          <h2 className="text-2xl font-bold">Bounty capstone</h2>
          {!unlocked ? (
            <p className="mt-1 text-sm text-muted-foreground">
              Finish every unit test to unlock. You have {online.filter(Boolean).length}/8 skills unlocked.
            </p>
          ) : (
            <p className="mt-1 text-sm text-muted-foreground">
              A fresh HackerOne program just dropped: <span className="font-mono text-foreground">*.megashop.example</span>. Walk
              the full chain from recon to a critical finding. Submit each step's answer, then file the final report.
            </p>
          )}
        </div>

        {unlocked && (
          <>
            <ol className="space-y-3">
              {CAPSTONE_STEPS.map((s, i) => {
                const isOpen = open[s.id] ?? false;
                return (
                  <li key={s.id} className="rounded-xl border-2 border-border bg-card">
                    <button
                      type="button"
                      onClick={() => setOpen((o) => ({ ...o, [s.id]: !isOpen }))}
                      className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
                    >
                      <span className="font-bold">{s.title}</span>
                      <span
                        className={cn(
                          "font-mono text-xs",
                          checked[i] === true && "text-primary",
                          checked[i] === false && "text-offense",
                          checked[i] === null && "text-muted-foreground",
                        )}
                      >
                        {checked[i] === true ? "✓ solved" : checked[i] === false ? "✗ retry" : isOpen ? "▾" : "▸"}
                      </span>
                    </button>
                    {isOpen && (
                      <div className="space-y-3 border-t-2 border-border p-4">
                        <p className="text-sm">{s.prompt}</p>
                        <div className="rounded-lg border border-border bg-terminal p-3 font-mono text-xs text-muted-foreground">
                          <p className="text-primary">$ {s.commandHint}</p>
                          <pre className="mt-1 whitespace-pre-wrap text-foreground/85">{s.response}</pre>
                        </div>
                        <div className="flex gap-2">
                          <input
                            value={answers[i] ?? ""}
                            onChange={(e) => setAnswers((a) => a.map((v, j) => (j === i ? e.target.value : v)))}
                            placeholder="Your answer"
                            aria-label={`Answer to ${s.title}`}
                            className={cn(
                              "flex-1 rounded-lg border-2 border-border bg-terminal px-3 py-2 font-mono text-sm outline-none focus:border-primary",
                              checked[i] === true && "border-primary",
                              checked[i] === false && "border-offense",
                            )}
                          />
                          <Btn type="button" onClick={() => check(i)}>
                            Check
                          </Btn>
                        </div>
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>

            <div className="flex flex-wrap items-center gap-3">
              <Btn variant="accent" onClick={submit}>
                Submit the chain
              </Btn>
              {submitted && (
                <span className="font-mono text-sm">
                  Score {Math.round(submitted.score)}%
                  {submitted.xp !== null && <span className="text-primary"> · +{submitted.xp} XP</span>}
                </span>
              )}
              {submitted?.score === 100 && (
                <span className="font-mono text-primary">★ {CAPSTONE_FLAG}</span>
              )}
            </div>

            {finalDone && (
              <p className="rounded-xl border-2 border-accent/50 bg-accent/10 p-3 text-center font-mono text-sm text-accent">
                ★ Capstone complete. In real life, this chain is often a $5 000+ critical.
              </p>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}
