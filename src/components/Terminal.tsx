import { useEffect, useRef, useState } from "react";

export function Terminal({ host, commands, hints }: { host: string; commands: Record<string, string>; hints: string[] }) {
  const [lines, setLines] = useState<{ cmd?: string; out: string }[]>([
    { out: `Simulated shell. Type "help" for available commands.` },
  ]);
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [hIdx, setHIdx] = useState(-1);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => {
    end.current?.scrollIntoView({ block: "nearest" });
  }, [lines]);

  function run(raw: string) {
    const cmd = raw.trim().replace(/\s+/g, " ");
    if (!cmd) return;
    setHistory((h) => [cmd, ...h]);
    setHIdx(-1);
    if (cmd === "clear") return setLines([]);
    let out: string;
    if (cmd === "help") out = "Commands available in this lab:\n" + hints.map((h) => "  " + h).join("\n") + "\n  clear";
    else if (commands[cmd] !== undefined) out = commands[cmd];
    else out = `${cmd.split(" ")[0]}: not available in this simulation. Try "help".`;
    setLines((l) => [...l, { cmd, out }]);
  }

  return (
    <div className="scanlines overflow-hidden rounded-xl border-2 border-border bg-terminal font-mono text-xs">
      <div className="flex items-center gap-1.5 border-b border-border px-3 py-2">
        <span className="h-2.5 w-2.5 rounded-full bg-offense" />
        <span className="h-2.5 w-2.5 rounded-full bg-accent" />
        <span className="h-2.5 w-2.5 rounded-full bg-primary" />
        <span className="ml-2 text-muted-foreground">{host}</span>
      </div>
      <div className="h-72 overflow-auto p-3" onClick={() => document.getElementById("term-in")?.focus()}>
        {lines.map((l, i) => (
          <div key={i} className="mb-2">
            {l.cmd && (
              <div>
                <span className="text-primary">{host}</span>
                <span className="text-muted-foreground">:~$ </span>
                {l.cmd}
              </div>
            )}
            <pre className="whitespace-pre-wrap text-foreground/85">{l.out}</pre>
          </div>
        ))}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            run(input);
            setInput("");
          }}
          className="flex"
        >
          <span className="text-primary">{host}</span>
          <span className="text-muted-foreground">:~$&nbsp;</span>
          <input
            id="term-in"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowUp") {
                const n = Math.min(hIdx + 1, history.length - 1);
                if (history[n]) {
                  setHIdx(n);
                  setInput(history[n]);
                }
                e.preventDefault();
              } else if (e.key === "ArrowDown") {
                const n = hIdx - 1;
                setHIdx(Math.max(n, -1));
                setInput(n >= 0 ? history[n] : "");
                e.preventDefault();
              }
            }}
            autoComplete="off"
            spellCheck={false}
            aria-label="Terminal input"
            className="flex-1 bg-transparent text-foreground caret-primary outline-none"
          />
        </form>
        <div ref={end} />
      </div>
      <div className="flex flex-wrap gap-1.5 border-t border-border p-2">
        {hints.map((h) => (
          <button
            key={h}
            type="button"
            onClick={() => run(h)}
            className="rounded-md border border-border bg-secondary px-2 py-1 text-[11px] text-muted-foreground hover:text-primary"
          >
            {h}
          </button>
        ))}
      </div>
    </div>
  );
}
