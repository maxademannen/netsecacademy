import { useMemo, useState } from "react";
import type { Exercise } from "@/content/types";
import { Btn, Panel } from "./kit";
import { cn } from "@/lib/utils";
import { RuleEditor } from "./RuleEditor";

const norm = (s: string) => s.trim().toLowerCase().replace(/\s+/g, " ");

function shuffle<T>(a: T[]) {
  const r = [...a];
  for (let i = r.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [r[i], r[j]] = [r[j]!, r[i]!];
  }
  return r;
}

export function ExercisePlayer({
  ex,
  onAnswer,
}: {
  ex: Exercise;
  /** called once with whether the first submission was correct */
  onAnswer: (correct: boolean) => void;
}) {
  const [checked, setChecked] = useState<null | boolean>(null);
  const [wrongTries, setWrongTries] = useState(0);
  const hintsAvailable = ex.hints ?? [];

  // state per type
  const [pick, setPick] = useState<number | null>(null);
  const [text, setText] = useState("");
  const [order, setOrder] = useState<string[]>(() => (ex.type === "order" ? shuffle(ex.items) : []));
  const [matches, setMatches] = useState<Record<string, string>>({});
  const rightCol = useMemo(() => (ex.type === "match" ? shuffle(ex.pairs.map((p) => p[1])) : []), [ex]);

  function verdict(ok: boolean) {
    if (ok) {
      setChecked(true);
      // first-try correctness is already captured by the parent via onAnswer
      onAnswer(true);
      return;
    }
    const nextTries = wrongTries + 1;
    setWrongTries(nextTries);
    // Fire onAnswer only on the first attempt so the lesson's heart/XP accounting
    // still runs; further wrong attempts just surface more hints.
    if (nextTries === 1) onAnswer(false);
    // Reveal full explanation once hints are exhausted
    if (nextTries > hintsAvailable.length) setChecked(false);
  }

  function check() {
    if (checked !== null) return;
    switch (ex.type) {
      case "mc":
        return verdict(pick === ex.answer);
      case "fill":
        return verdict(ex.answers.some((a) => norm(a) === norm(text)));
      case "order":
        return verdict(order.every((v, i) => v === ex.items[i]));
      case "match":
        return verdict(ex.pairs.every(([l, r]) => matches[l] === r));
      default:
        return;
    }
  }


  function move(i: number, d: number) {
    if (checked !== null) return;
    const j = i + d;
    if (j < 0 || j >= order.length) return;
    const n = [...order];
    [n[i], n[j]] = [n[j]!, n[i]!];
    setOrder(n);
  }

  return (
    <Panel className="space-y-4">
      <p className="text-base font-semibold">{ex.q}</p>
      {ex.exhibit && (
        <pre className="overflow-auto rounded-lg border border-border bg-terminal p-3 font-mono text-xs text-foreground/90">
          {ex.exhibit}
        </pre>
      )}

      {ex.type === "mc" && (
        <div className="grid gap-2">
          {ex.options.map((o, i) => (
            <button
              key={i}
              type="button"
              disabled={checked !== null}
              onClick={() => setPick(i)}
              className={cn(
                "btn-3d rounded-xl border-2 px-4 py-3 text-left text-sm",
                pick === i ? "border-primary bg-primary/10" : "border-border bg-card hover:bg-secondary",
                checked !== null && i === ex.answer && "border-primary bg-primary/20",
                checked === false && pick === i && i !== ex.answer && "border-offense bg-offense/15",
              )}
            >
              {o}
            </button>
          ))}
        </div>
      )}

      {ex.type === "fill" && (
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && check()}
          disabled={checked !== null}
          placeholder="Type your answer"
          aria-label="Answer"
          className="w-full rounded-xl border-2 border-border bg-terminal px-4 py-3 font-mono text-sm outline-none focus:border-primary"
        />
      )}

      {ex.type === "order" && (
        <div className="space-y-2">
          {order.map((item, i) => (
            <div key={item} className="flex items-center gap-2 rounded-xl border-2 border-border bg-card px-3 py-2">
              <span className="font-mono text-xs text-muted-foreground">{i + 1}</span>
              <span className="flex-1 text-sm">{item}</span>
              <button type="button" aria-label="Move up" onClick={() => move(i, -1)} className="px-2 text-muted-foreground hover:text-primary">
                ▲
              </button>
              <button type="button" aria-label="Move down" onClick={() => move(i, 1)} className="px-2 text-muted-foreground hover:text-primary">
                ▼
              </button>
            </div>
          ))}
        </div>
      )}

      {ex.type === "match" && (
        <div className="space-y-2">
          {ex.pairs.map(([l]) => (
            <div key={l} className="flex flex-wrap items-center gap-2">
              <span className="min-w-36 text-sm font-medium">{l}</span>
              <select
                aria-label={l}
                disabled={checked !== null}
                value={matches[l] ?? ""}
                onChange={(e) => setMatches((m) => ({ ...m, [l]: e.target.value }))}
                className={cn(
                  "flex-1 rounded-lg border-2 border-border bg-terminal px-3 py-2 text-sm outline-none focus:border-primary",
                  checked !== null && (matches[l] === ex.pairs.find((p) => p[0] === l)![1] ? "border-primary" : "border-offense"),
                )}
              >
                <option value="">Choose…</option>
                {rightCol.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
      )}

      {ex.type === "rule" && (
        <RuleEditor
          traffic={ex.traffic}
          starter={ex.starter ?? ""}
          showTraffic={false}
          onResult={(g) => checked === null && verdict(g.passed)}
        />
      )}

      {ex.type !== "rule" && checked === null && (
        <div className="flex flex-wrap gap-2">
          <Btn type="button" onClick={check} disabled={ex.type === "mc" && pick === null}>
            {wrongTries > 0 ? "Try again" : "Check"}
          </Btn>
          {wrongTries > 0 && (
            <Btn type="button" variant="ghost" onClick={() => resolve(false)}>
              Show explanation
            </Btn>
          )}
        </div>
      )}

      {checked === null && wrongTries > 0 && (
        <div className="rounded-xl border-2 border-accent/50 bg-accent/10 p-3 text-sm">
          <p className="font-bold text-accent">Not yet — hint {Math.min(wrongTries, hintsAvailable.length)}/{hintsAvailable.length}</p>
          <p className="mt-1 text-foreground/90">{hintsAvailable[Math.min(wrongTries, hintsAvailable.length) - 1]}</p>
        </div>
      )}

      {checked !== null && (
        <div
          className={cn(
            "rounded-xl border-2 p-3 text-sm",
            checked ? "border-primary/50 bg-primary/10" : "border-offense/50 bg-offense/10",
          )}
        >
          <p className="font-bold">{checked ? (wrongTries ? "Got it — with hints" : "Correct") : "Here's the reasoning"}</p>
          <p className="mt-1 text-muted-foreground">{ex.explain}</p>
        </div>
      )}

    </Panel>
  );
}
