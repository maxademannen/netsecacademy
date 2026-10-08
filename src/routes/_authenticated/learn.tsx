import { createFileRoute, Link } from "@tanstack/react-router";
import { UNITS } from "@/content/units";
import { bestScores, isDone, unitNodes, unitUnlocked, useActivity, useProfile, type PathNode } from "@/lib/progress";
import { Panel, ToneTag } from "@/components/kit";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/learn")({
  head: () => ({
    meta: [
      { title: "Learn — NetSec Academy" },
      { name: "description", content: "Your skill tree from networking basics to building an IDS." },
      { property: "og:title", content: "Learn — NetSec Academy" },
      { property: "og:description", content: "Your skill tree from networking basics to building an IDS." },
    ],
  }),
  component: Learn,
});

const icon = { lesson: "▤", lab: "⌨", test: "★" } as const;

function NodeLink({ node, offset }: { node: PathNode; offset: number }) {
  const base = cn(
    "btn-3d grid h-16 w-16 place-items-center rounded-full border-2 text-2xl font-bold",
    node.state === "done" && "border-primary-shade bg-primary text-primary-foreground",
    node.state === "open" && "glow border-accent-shade bg-accent text-accent-foreground",
    node.state === "locked" && "cursor-not-allowed border-border bg-secondary text-muted-foreground",
  );
  const inner = (
    <div className="flex flex-col items-center gap-1.5" style={{ transform: `translateX(${offset}px)` }}>
      <div className={base}>{node.state === "locked" ? "🔒" : icon[node.kind]}</div>
      <span className="max-w-40 text-center text-xs text-muted-foreground">{node.label}</span>
    </div>
  );
  if (node.state === "locked") return inner;
  const to = node.to;
  if (to.type === "lesson")
    return (
      <Link to="/lesson/$unitId/$lessonId" params={{ unitId: to.unitId, lessonId: to.lessonId }}>
        {inner}
      </Link>
    );
  if (to.type === "lab")
    return (
      <Link to="/lab/$labId" params={{ labId: to.labId }}>
        {inner}
      </Link>
    );
  return (
    <Link to="/test/$unitId" params={{ unitId: to.unitId }}>
      {inner}
    </Link>
  );
}

function Learn() {
  const { data: activity } = useActivity();
  const { data: profile } = useProfile();
  const best = bestScores(activity);
  const today = new Date().toISOString().slice(0, 10);
  const xpToday = (activity ?? []).filter((a) => a.created_at.slice(0, 10) === today).reduce((n, a) => n + a.xp, 0);
  const goal = 50;
  const modules = UNITS.filter((u) => isDone(best, "test", u.id)).length;
  const offsets = [0, 50, 80, 50, 0, -50, -80, -50];

  return (
    <div className="grid gap-8 lg:grid-cols-[1fr_320px]">
      <div className="space-y-10">
        {UNITS.map((u, ui) => {
          const unlocked = unitUnlocked(best, ui);
          const nodes = unitNodes(best, u, ui);
          return (
            <section key={u.id} className={cn(!unlocked && "opacity-60")}>
              <div
                className={cn(
                  "mb-6 rounded-2xl border-2 p-5",
                  u.tone === "offense" ? "border-offense/50 bg-offense/10" : u.tone === "defense" ? "border-primary/40 bg-primary/10" : "border-info/40 bg-info/10",
                )}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-muted-foreground">UNIT {u.index}</span>
                  <ToneTag tone={u.tone} />
                </div>
                <h2 className="mt-1 text-2xl font-bold">{u.title}</h2>
                <p className="text-sm text-muted-foreground">{u.tagline}</p>
                <p className="mt-2 font-mono text-xs text-primary">→ IDS module: {u.ids.name}</p>
              </div>
              <div className="flex flex-col items-center gap-6">
                {nodes.map((n, i) => (
                  <NodeLink key={n.kind + n.ref} node={n} offset={offsets[i % offsets.length] ?? 0} />
                ))}
              </div>
            </section>
          );
        })}
        <section className="rounded-2xl border-2 border-accent/50 bg-accent/10 p-6 text-center">
          <h2 className="text-2xl font-bold">Final: assemble your IDS</h2>
          <p className="mt-1 text-sm text-muted-foreground">Run every module you've unlocked against a mixed attack replay.</p>
          <Link to="/ids" className="btn-3d mt-4 inline-block rounded-xl border-2 border-accent-shade bg-accent px-5 py-2.5 text-sm font-bold uppercase text-accent-foreground">
            Open workbench
          </Link>
        </section>
      </div>

      <aside className="space-y-4 lg:sticky lg:top-20 lg:self-start">
        <Panel>
          <h3 className="font-bold">Daily goal</h3>
          <div className="mt-3 h-3 overflow-hidden rounded-full bg-secondary">
            <div className="h-full bg-accent" style={{ width: `${Math.min(100, (xpToday / goal) * 100)}%` }} />
          </div>
          <p className="mt-2 font-mono text-xs text-muted-foreground">
            {xpToday}/{goal} XP today · 🔥 {profile?.streak ?? 0} day streak
          </p>
        </Panel>
        <Panel>
          <h3 className="font-bold">Your IDS</h3>
          <p className="mb-3 text-xs text-muted-foreground">{modules}/8 modules online</p>
          <ul className="space-y-1.5 font-mono text-xs">
            {UNITS.map((u) => {
              const on = isDone(best, "test", u.id);
              return (
                <li key={u.id} className={cn("flex items-center gap-2", on ? "text-primary" : "text-muted-foreground")}>
                  <span className={cn("h-2 w-2 rounded-full", on ? "bg-primary glow" : "bg-border")} />
                  {u.ids.name}
                </li>
              );
            })}
          </ul>
        </Panel>
        <Panel>
          <h3 className="font-bold">Hearts</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            You lose a heart for each wrong answer in a lesson. One regenerates every 30 minutes. Labs and tests are free.
          </p>
          <p className="mt-2 font-mono text-lg text-offense">{"♥".repeat(profile?.hearts ?? 0)}<span className="text-border">{"♥".repeat(5 - (profile?.hearts ?? 0))}</span></p>
        </Panel>
      </aside>
    </div>
  );
}
