import { createFileRoute, Link } from "@tanstack/react-router";
import { UNITS } from "@/content/units";
import { ToneTag } from "@/components/kit";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "NetSec Academy — learn offensive security and bug bounty, by hacking" },
      {
        name: "description",
        content:
          "Bite-sized lessons and CTF-style labs that take you from packets to critical bug-bounty finds — the Duolingo of offensive security.",
      },
      { property: "og:title", content: "NetSec Academy — learn offensive security and bug bounty, by hacking" },
      {
        property: "og:description",
        content: "Lessons, CTFs and a capstone chain — from packets to your first bounty report.",
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
          <p className="font-mono text-xs uppercase tracking-widest text-accent">recon → exploit → report → bounty</p>
          <h1 className="mt-3 text-5xl font-bold leading-[1.05] tracking-tight md:text-6xl">
            Learn <span className="text-primary">offensive security</span> by actually hacking.
          </h1>
          <p className="mt-5 max-w-lg text-lg text-muted-foreground">
            Bite-sized lessons, CTF-style labs and a daily streak — building toward real bug-bounty workflows and your first
            paid report.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              to="/auth"
              className="btn-3d rounded-xl border-2 border-primary-shade bg-primary px-6 py-3 font-bold uppercase tracking-wide text-primary-foreground"
            >
              Start hunting — free
            </Link>
            <Link to="/learn" className="btn-3d rounded-xl border-2 border-border bg-card px-6 py-3 font-bold uppercase tracking-wide">
              I have an account
            </Link>
          </div>
        </div>
        <div className="scanlines rounded-2xl border-2 border-border bg-terminal p-5 font-mono text-xs leading-relaxed">
          <p className="text-muted-foreground">hunter@kali:~$ curl -s shop.example/search?q=book'</p>
          <p className="text-offense">SQLSTATE[42000]: Syntax error near 'book''</p>
          <p className="mt-2 text-muted-foreground">hunter@kali:~$ curl "shop.example/search?q=x' UNION SELECT version()-- -"</p>
          <p>MySQL 5.7.42 — shop_app@localhost</p>
          <p className="mt-2 text-muted-foreground">hunter@kali:~$ cat report.md</p>
          <p className="text-primary"># SQL injection in /search `q` parameter<br />Severity: Critical (CVSS 9.1)</p>
          <p className="mt-3">
            <span className="text-primary">+30 XP</span> · <span className="text-accent">🏆 FLAG{"{"}first_blood{"}"}</span> · 🔥 4 day streak<span className="caret">▌</span>
          </p>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 pb-20">
        <h2 className="text-2xl font-bold">The path</h2>
        <p className="text-muted-foreground">Eight units, each ending in a CTF-style lab. The final capstone chains them into a bounty-grade finding.</p>
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
