import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Panel } from "@/components/kit";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/leaderboard")({
  head: () => ({
    meta: [
      { title: "Leaderboard — NetSec Academy" },
      { name: "description", content: "Weekly XP rankings for NetSec Academy learners." },
      { property: "og:title", content: "Leaderboard — NetSec Academy" },
      { property: "og:description", content: "Weekly XP rankings for NetSec Academy learners." },
    ],
  }),
  component: Leaderboard,
});

function Leaderboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["leaderboard"],
    queryFn: async () => {
      const { data, error } = await supabase.rpc("get_leaderboard");
      if (error) throw error;
      return data;
    },
  });
  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <h1 className="text-3xl font-bold">Weekly leaderboard</h1>
      <p className="text-muted-foreground">XP earned in the last 7 days.</p>
      <Panel className="p-0">
        {isLoading && <p className="p-5 text-muted-foreground">Loading…</p>}
        {error && <p className="p-5 text-offense">Couldn't load the leaderboard.</p>}
        <ol>
          {data?.map((r, i) => (
            <li
              key={i}
              className={cn("flex items-center gap-4 border-b border-border px-5 py-3 last:border-0", r.is_me && "bg-primary/10")}
            >
              <span className={cn("w-6 font-mono font-bold", i < 3 ? "text-accent" : "text-muted-foreground")}>{i + 1}</span>
              <span className="flex-1 font-medium">
                {r.username}
                {r.is_me && <span className="ml-2 text-xs text-primary">(you)</span>}
              </span>
              <span className="font-mono text-primary">{r.weekly_xp} XP</span>
              <span className="hidden font-mono text-xs text-muted-foreground sm:inline">{r.total_xp} total</span>
            </li>
          ))}
        </ol>
      </Panel>
    </div>
  );
}
