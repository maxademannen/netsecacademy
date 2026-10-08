import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useProfile, levelFromXp } from "@/lib/progress";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

function Stat({ icon, value, title, className }: { icon: string; value: ReactNode; title: string; className?: string }) {
  return (
    <span title={title} className={cn("flex items-center gap-1 font-mono text-sm font-semibold", className)}>
      <span aria-hidden>{icon}</span>
      {value}
    </span>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { data: profile } = useProfile();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const lvl = levelFromXp(profile?.xp ?? 0);

  async function signOut() {
    await qc.cancelQueries();
    qc.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }

  const nav = [
    { to: "/learn", label: "Learn" },
    { to: "/ids", label: "Toolkit" },
    { to: "/leaderboard", label: "Leaderboard" },
    { to: "/profile", label: "Profile" },
  ] as const;

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b-2 border-border bg-background/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3">
          <Link to="/learn" className="font-mono text-base font-bold tracking-tight text-primary">
            net<span className="text-foreground">sec</span>://academy
          </Link>
          <nav className="flex gap-1 text-sm">
            {nav.map((n) => (
              <Link
                key={n.to}
                to={n.to}
                className="rounded-lg px-3 py-1.5 text-muted-foreground hover:bg-secondary hover:text-foreground"
                activeProps={{ className: "bg-secondary text-foreground" }}
              >
                {n.label}
              </Link>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-4">
            <Stat icon="🔥" value={profile?.streak ?? 0} title="Day streak" className="text-accent" />
            <Stat icon="◈" value={profile?.xp ?? 0} title="Total XP" className="text-primary" />
            <Stat icon="♥" value={profile?.hearts ?? 0} title="Hearts (regenerate every 30 min)" className="text-offense" />
            <span className="hidden font-mono text-xs text-muted-foreground sm:inline">Lv {lvl.level}</span>
            <button onClick={signOut} className="text-xs text-muted-foreground underline-offset-4 hover:text-foreground hover:underline">
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
    </div>
  );
}
