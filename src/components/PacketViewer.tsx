import { useState } from "react";
import type { Packet } from "@/content/types";
import { cn } from "@/lib/utils";

function hexdump(s: string) {
  const bytes = Array.from(new TextEncoder().encode(s)).slice(0, 256);
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const asc = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48)}  ${asc}`);
  }
  return lines.join("\n");
}

const protoColor: Record<string, string> = {
  TCP: "text-primary",
  UDP: "text-accent",
  ICMP: "text-info",
  ARP: "text-chart-5",
};

export function PacketViewer({
  packets,
  highlight,
  falsePositive,
  className,
}: {
  packets: Packet[];
  highlight?: Set<number>;
  falsePositive?: Set<number>;
  className?: string;
}) {
  const [sel, setSel] = useState<Packet | null>(packets[0] ?? null);
  return (
    <div className={cn("overflow-hidden rounded-xl border-2 border-border bg-terminal font-mono text-xs", className)}>
      <div className="max-h-72 overflow-auto">
        <table className="w-full">
          <thead className="sticky top-0 bg-secondary text-left text-muted-foreground">
            <tr>
              <th className="px-2 py-1.5">#</th>
              <th className="px-2">Time</th>
              <th className="px-2">Source</th>
              <th className="px-2">Destination</th>
              <th className="px-2">Proto</th>
              <th className="px-2">Info</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((p, i) => (
              <tr
                key={p.id}
                onClick={() => setSel(p)}
                className={cn(
                  "cursor-pointer border-t border-border/50 hover:bg-secondary/60",
                  sel?.id === p.id && "bg-secondary",
                  highlight?.has(p.id) && "bg-primary/15",
                  falsePositive?.has(p.id) && "bg-offense/20",
                )}
              >
                <td className="px-2 py-1 text-muted-foreground">{i + 1}</td>
                <td className="px-2">{p.t.toFixed(2)}</td>
                <td className="px-2">
                  {p.src}
                  {p.sport ? `:${p.sport}` : ""}
                </td>
                <td className="px-2">
                  {p.dst}
                  {p.dport ? `:${p.dport}` : ""}
                </td>
                <td className={cn("px-2 font-semibold", protoColor[p.proto])}>{p.proto}</td>
                <td className="max-w-[22rem] truncate px-2 text-muted-foreground">{p.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sel && (
        <div className="grid gap-3 border-t-2 border-border p-3 md:grid-cols-2">
          <div className="space-y-0.5">
            <div className="mb-1 text-muted-foreground">▸ Decoded</div>
            <div>
              {sel.proto === "ARP" ? "Link: ARP" : `IPv4  src ${sel.src}  dst ${sel.dst}  ttl ${sel.ttl ?? "-"}`}
            </div>
            {sel.proto === "TCP" && (
              <div>
                TCP  sport {sel.sport}  dport {sel.dport}  flags [{sel.flags}]
              </div>
            )}
            {sel.proto === "UDP" && (
              <div>
                UDP  sport {sel.sport}  dport {sel.dport}
              </div>
            )}
            {sel.proto === "ICMP" && <div>ICMP type {sel.icmpType}</div>}
            <div>length {sel.len}</div>
            <div className="text-muted-foreground">{sel.info}</div>
          </div>
          <div>
            <div className="mb-1 text-muted-foreground">▸ Payload</div>
            <pre className="whitespace-pre-wrap break-all text-foreground/90">{sel.payload ? hexdump(sel.payload) : "(none)"}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
