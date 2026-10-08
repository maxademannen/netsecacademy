import { createFileRoute, Link, notFound, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { getLesson } from "@/content/units";
import { lessonRef, useComplete, useLoseHeart, useProfile } from "@/lib/progress";
import { Btn, Panel, ToneTag } from "@/components/kit";
import { ExercisePlayer } from "@/components/ExercisePlayer";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/lesson/$unitId/$lessonId")({
  loader: ({ params }) => {
    const r = getLesson(params.unitId, params.lessonId);
    if (!r?.lesson) throw notFound();
    return { unitTitle: r.unit.title, title: r.lesson.title };
  },
  head: ({ loaderData }) => ({
    meta: [
      { title: loaderData ? `${loaderData.title} — NetSec Academy` : "Lesson — NetSec Academy" },
      { name: "description", content: "Interactive network security lesson." },
    ],
  }),
  notFoundComponent: () => <p className="text-muted-foreground">Lesson not found.</p>,
  component: LessonPage,
});

function LessonPage() {
  const { unitId, lessonId } = Route.useParams();
  const { unit, lesson } = getLesson(unitId, lessonId)!;
  const navigate = useNavigate();
  const { data: profile } = useProfile();
  const loseHeart = useLoseHeart();
  const complete = useComplete();

  const [phase, setPhase] = useState<"cards" | "ex" | "done">("cards");
  const [card, setCard] = useState(0);
  const [queue, setQueue] = useState(() => lesson!.exercises.map((_, i) => i));
  const [answered, setAnswered] = useState<null | boolean>(null);
  const [firstTry, setFirstTry] = useState<Record<number, boolean>>({});
  const [earned, setEarned] = useState<number | null>(null);
  const [step, setStep] = useState(0);

  if (!lesson) return null;
  const total = lesson.cards.length + lesson.exercises.length;
  const progress = phase === "cards" ? card : phase === "ex" ? lesson.cards.length + Object.keys(firstTry).length : total;
  const hearts = profile?.hearts ?? 5;

  if (phase !== "done" && hearts <= 0 && profile) {
    return (
      <Panel className="mx-auto max-w-lg text-center">
        <p className="text-5xl">💔</p>
        <h1 className="mt-3 text-2xl font-bold">Out of hearts</h1>
        <p className="mt-2 text-muted-foreground">One heart comes back every 30 minutes. Labs and unit tests don't cost hearts — try one meanwhile.</p>
        <Link to="/learn" className="mt-4 inline-block text-primary underline">
          Back to the skill tree
        </Link>
      </Panel>
    );
  }

  const current = queue[0];

  async function onAnswer(ok: boolean) {
    setAnswered(ok);
    if (!(current in firstTry)) setFirstTry((f) => ({ ...f, [current]: ok }));
    if (!ok) loseHeart.mutate();
  }

  async function next() {
    const rest = queue.slice(1);
    const nq = answered ? rest : [...rest, current];
    setAnswered(null);
    setStep((s) => s + 1);
    if (nq.length === 0) {
      const correct = Object.values({ ...firstTry }).filter(Boolean).length;
      const score = (correct / lesson!.exercises.length) * 100;
      setPhase("done");
      try {
        const xp = await complete.mutateAsync({ kind: "lesson", ref: lessonRef(unit, lesson!.id), score });
        setEarned(xp);
      } catch (e) {
        toast.error("Couldn't save your progress. Check your connection and try again.");
      }
    } else setQueue(nq);
  }

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <div className="flex items-center gap-3">
        <Link to="/learn" aria-label="Close lesson" className="text-xl text-muted-foreground hover:text-foreground">
          ✕
        </Link>
        <div className="h-3 flex-1 overflow-hidden rounded-full bg-secondary">
          <div className="h-full bg-primary transition-all" style={{ width: `${(progress / total) * 100}%` }} />
        </div>
        <span className="font-mono text-sm text-offense">♥ {hearts}</span>
      </div>
      <div>
        <p className="font-mono text-xs text-muted-foreground">
          UNIT {unit.index} · {unit.title}
        </p>
        <h1 className="text-2xl font-bold">{lesson.title}</h1>
      </div>

      {phase === "cards" && (
        <Panel
          className={cn(
            "space-y-3",
            lesson.cards[card].tone === "offense" && "border-offense/50",
            lesson.cards[card].tone === "defense" && "border-primary/50",
          )}
        >
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-muted-foreground">
              {card + 1}/{lesson.cards.length}
            </span>
            <ToneTag tone={lesson.cards[card].tone} />
          </div>
          <h2 className="text-xl font-bold">{lesson.cards[card].title}</h2>
          {lesson.cards[card].body.map((p, i) => (
            <p key={i} className="leading-relaxed text-foreground/90">
              {p}
            </p>
          ))}
          {lesson.cards[card].code && (
            <pre className="overflow-auto rounded-lg border border-border bg-terminal p-3 font-mono text-xs leading-relaxed text-primary/90">
              {lesson.cards[card].code}
            </pre>
          )}
          <div className="flex justify-between pt-2">
            <Btn variant="ghost" disabled={card === 0} onClick={() => setCard(card - 1)}>
              Back
            </Btn>
            <Btn onClick={() => (card + 1 < lesson.cards.length ? setCard(card + 1) : setPhase("ex"))}>
              {card + 1 < lesson.cards.length ? "Next" : "Start practice"}
            </Btn>
          </div>
        </Panel>
      )}

      {phase === "ex" && (
        <>
          <ExercisePlayer key={step} ex={lesson.exercises[current]} onAnswer={onAnswer} />
          {answered !== null && (
            <div className="flex justify-end">
              <Btn variant={answered ? "primary" : "offense"} onClick={next}>
                {answered ? "Continue" : "Got it — retry later"}
              </Btn>
            </div>
          )}
        </>
      )}

      {phase === "done" && (
        <Panel className="space-y-3 text-center">
          <p className="text-5xl">✓</p>
          <h2 className="text-2xl font-bold">Lesson complete</h2>
          <p className="font-mono text-primary">{earned === null ? "saving…" : `+${earned} XP`}</p>
          <p className="text-sm text-muted-foreground">
            First-try accuracy: {Object.values(firstTry).filter(Boolean).length}/{lesson.exercises.length}
          </p>
          <Btn onClick={() => navigate({ to: "/learn" })}>Continue</Btn>
        </Panel>
      )}
    </div>
  );
}
