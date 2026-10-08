import { createFileRoute, Link } from "@tanstack/react-router";
import { UNITS } from "@/content/units";
import { ToneTag } from "@/components/kit";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "NetSec Academy — learn network security by breaking and defending" },
      {
        name: "description",
        content: "Bite-sized lessons, hands-on simulated labs and quizzes that take you from packets to building your own intrusion detection system.",
      },
      { property: "og:title", content: "NetSec Academy — learn network security by breaking and defending" },
      {
        property: "og:description",
        content: "Bite-sized lessons, simulated labs and quizzes — from packets to your own IDS.",
      },
    ],
  }),
  component: Landing,
});

function Landing() {
  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-4 py-5">
        <span className="font-mono text-base font-bold text-primary">
          net<span className="text-foreground">sec</span>://academy
        </span>
        <Link to="/auth" className="text-sm text-muted-foreground hover:text-foreground">
          Sign in
        </Link>
      </header>

      <section className="mx-auto grid max-w-6xl items-center gap-10 px-4 py-16 lg:grid-cols-2">
        <div>
          <p className="font-mono text-xs uppercase tracking-widest text-accent">break it → understand it → defend it</p>
          <h1 className="mt-3 text-5xl font-bold leading-[1.05] tracking-tight md:text-6xl">
            Learn network security <span className="text-primary">one packet</span> at a time.
          </h1>
          <p className="mt-5 max-w-lg text-lg text-muted-foreground">
            Short lessons, simulated hacking labs and daily streaks — all building toward your own working intrusion detection
            system.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              to="/auth"
              className="btn-3d rounded-xl border-2 border-primary-shade bg-primary px-6 py-3 font-bold uppercase tracking-wide text-primary-foreground"
            >
              Start learning — free
            </Link>
            <Link to="/learn" className="btn-3d rounded-xl border-2 border-border bg-card px-6 py-3 font-bold uppercase tracking-wide">
              I have an account
            </Link>
          </div>
        </div>
        <div className="scanlines rounded-2xl border-2 border-border bg-terminal p-5 font-mono text-xs leading-relaxed">
          <p className="text-muted-foreground">attacker@kali:~$ nmap -sS 10.0.0.20</p>
          <p>22/tcp open ssh · 80/tcp open http · 3306/tcp filtered</p>
          <p className="mt-3 text-muted-foreground">analyst@sensor:~$ cat local.rules</p>
          <p className="text-primary">
            alert tcp any any -&gt; $HOME_NET any (msg:"Port scan"; flags:S;
            <br />
            &nbsp;&nbsp;threshold: type threshold, track by_src, count 15, seconds 5; sid:1000001;)
          </p>
          <p className="mt-3 text-accent">[**] [1:1000001] Port scan [**] 203.0.113.77 → 10.0.0.20</p>
          <p className="mt-3">
            <span className="text-primary">+30 XP</span> · 🔥 4 day streak<span className="caret">▌</span>
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 pb-20">
        <h2 className="text-2xl font-bold">The path</h2>
        <p className="text-muted-foreground">Eight units. Every unit test you pass brings one module of your IDS online.</p>
        <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {UNITS.map((u) => (
            <div key={u.id} className="rounded-2xl border-2 border-border bg-card p-4">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-muted-foreground">0{u.index}</span>
                <ToneTag tone={u.tone} />
              </div>
              <h3 className="mt-2 font-bold">{u.title}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{u.tagline}</p>
              <p className="mt-3 font-mono text-[11px] text-primary">→ {u.ids.name}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
