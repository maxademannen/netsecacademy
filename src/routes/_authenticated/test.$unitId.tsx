import { createFileRoute, Link, notFound, useNavigate } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { getUnit } from "@/content/units";
import { useComplete } from "@/lib/progress";
import { Btn, Panel } from "@/components/kit";
import { ExercisePlayer } from "@/components/ExercisePlayer";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/test/$unitId")({
  loader: ({ params }) => {
    const u = getUnit(params.unitId);
    if (!u) throw notFound();
    return { title: u.title };
  },
  head: ({ loaderData }) => ({
    meta: [{ title: loaderData ? `Unit test: ${loaderData.title} — NetSec Academy` : "Unit test — NetSec Academy" }],
  }),
  notFoundComponent: () => <p className="text-muted-foreground">Unit not found.</p>,
  component: TestPage,
});

function TestPage() {
  const { unitId } = Route.useParams();
  const unit = getUnit(unitId)!;
  const navigate = useNavigate();
  const complete = useComplete();
  const questions = useMemo(() => {
    const all = unit.lessons.flatMap((l) => l.exercises).filter((e) => e.type !== "rule");
    return [...all].sort(() => Math.random() - 0.5).slice(0, 12);
  }, [unit]);
  const [i, setI] = useState(0);
  const [results, setResults] = useState<boolean[]>([]);
  const [answered, setAnswered] = useState(false);
  const [final, setFinal] = useState<{ score: number; xp: number | null } | null>(null);

  async function next() {
    setAnswered(false);
    if (i + 1 < questions.length) return setI(i + 1);
    const score = (results.filter(Boolean).length / questions.length) * 100;
    setFinal({ score, xp: null });
    try {
      const xp = await complete.mutateAsync({ kind: "test", ref: unit.id, score });
      setFinal({ score, xp });
    } catch {
      toast.error("Couldn't save your result. Try again.");
    }
  }

  if (final) {
    const pass = final.score >= 80;
    return (
      <Panel className="mx-auto max-w-lg space-y-3 text-center">
        <p className="text-5xl">{pass ? "★" : "✗"}</p>
        <h1 className="text-2xl font-bold">{pass ? "Unit passed" : "Not yet"}</h1>
        <p className="font-mono text-3xl">{Math.round(final.score)}%</p>
        <p className="text-sm text-muted-foreground">
          {pass
            ? `The "${unit.ids.name}" module is now online in your IDS, and the next unit is unlocked.`
            : "You need 80% to pass. Review the lessons and try again."}
        </p>
        {final.xp !== null && <p className="font-mono text-primary">+{final.xp} XP</p>}
        <div className="flex justify-center gap-2">
          {!pass && (
            <Btn variant="outline" onClick={() => window.location.reload()}>
              Retry
            </Btn>
          )}
          <Btn onClick={() => navigate({ to: pass ? "/ids" : "/learn" })}>{pass ? "See your IDS" : "Back"}</Btn>
        </div>
      </Panel>
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <div className="flex items-center gap-3">
        <Link to="/learn" aria-label="Exit test" className="text-xl text-muted-foreground hover:text-foreground">
          ✕
        </Link>
        <div className="h-3 flex-1 overflow-hidden rounded-full bg-secondary">
          <div className="h-full bg-accent transition-all" style={{ width: `${(i / questions.length) * 100}%` }} />
        </div>
        <span className="font-mono text-sm text-muted-foreground">
          {i + 1}/{questions.length}
        </span>
      </div>
      <h1 className="text-2xl font-bold">Unit {unit.index} test · {unit.title}</h1>
      <p className="text-sm text-muted-foreground">No hearts lost here. Score 80% or more to pass.</p>
      <ExercisePlayer
        key={i}
        ex={questions[i]}
        onAnswer={(ok) => {
          setResults((r) => [...r, ok]);
          setAnswered(true);
        }}
      />
      {answered && (
        <div className="flex justify-end">
          <Btn onClick={next}>{i + 1 < questions.length ? "Next" : "Finish"}</Btn>
        </div>
      )}
    </div>
  );
}
