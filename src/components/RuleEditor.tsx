import { useState } from "react";
import type { Packet } from "@/content/types";
import { gradeDetection, runRules, type Grade, type EngineResult } from "@/lib/rule-engine";
import { Btn } from "./kit";
import { PacketViewer } from "./PacketViewer";

export function RuleEditor({
  traffic,
  starter,
  onResult,
  showTraffic = true,
  names,
}: {
  traffic: Packet[];
  starter: string;
  onResult?: (g: Grade) => void;
  showTraffic?: boolean;
  names?: Record<string, string>;
}) {
  const [text, setText] = useState(starter);
  const [res, setRes] = useState<{ engine: EngineResult; grade: Grade } | null>(null);

  function run() {
    const engine = runRules(text, traffic);
    const grade = gradeDetection(traffic, engine.alerts);
    setRes({ engine, grade });
    onResult?.(grade);
  }

  const hits = new Set(res?.engine.alerts.map((a) => a.packetId));
  const fps = new Set(res?.grade.falsePositives);

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border-2 border-border bg-terminal">
        <div className="flex items-center justify-between border-b border-border px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
          <span>local.rules</span>
          <span>HOME_NET = 10.0.0.0/24</span>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          rows={Math.max(5, text.split("\n").length + 1)}
          aria-label="Detection rules"
          className="w-full resize-y bg-transparent p-3 font-mono text-xs leading-relaxed text-foreground outline-none"
        />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Btn type="button" onClick={run}>
          ▶ Run against traffic
        </Btn>
        <Btn type="button" variant="ghost" onClick={() => setText(starter)}>
          Reset
        </Btn>
      </div>
      {res && (
        <div className="space-y-2 rounded-xl border-2 border-border bg-card p-3 font-mono text-xs">
          {res.engine.errors.map((e, i) => (
            <div key={i} className="text-offense">
              line {e.line}: {e.message}
            </div>
          ))}
          <div className="flex flex-wrap gap-4">
            <span>
              alerts: <b>{res.engine.alerts.length}</b>
            </span>
            <span className="text-primary">
              detected: {res.grade.detected.length}/{res.grade.incidents.length}
            </span>
            <span className={res.grade.falsePositives.length ? "text-offense" : "text-muted-foreground"}>
              false positives: {res.grade.falsePositives.length}
            </span>
            <span className={res.grade.passed ? "text-primary" : "text-accent"}>{res.grade.passed ? "✓ PASS" : "✗ not yet"}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {res.grade.incidents.map((i) => (
              <span
                key={i}
                className={
                  res.grade.detected.includes(i)
                    ? "rounded bg-primary/15 px-2 py-0.5 text-primary"
                    : "rounded bg-offense/15 px-2 py-0.5 text-offense"
                }
              >
                {res.grade.detected.includes(i) ? "✓" : "✗"} {names?.[i] ?? i}
              </span>
            ))}
          </div>
          {res.engine.alerts.length > 0 && (
            <div className="max-h-32 overflow-auto text-muted-foreground">
              {res.engine.alerts.slice(0, 40).map((a, i) => (
                <div key={i}>
                  [**] [1:{a.sid}] {a.msg} — packet #{traffic.findIndex((p) => p.id === a.packetId) + 1}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {showTraffic && <PacketViewer packets={traffic} highlight={hits} falsePositive={fps} />}
    </div>
  );
}
