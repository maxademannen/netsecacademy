export function stats(series: number[]) {
  const mean = series.reduce((a, b) => a + b, 0) / series.length;
  const sd = Math.sqrt(series.reduce((a, b) => a + (b - mean) ** 2, 0) / series.length);
  return { mean, sd };
}

export function AnomalyChart({ series, k, unit }: { series: number[]; k: number; unit: string }) {
  const { mean, sd } = stats(series);
  const thr = mean + k * sd;
  const max = Math.max(...series, thr) * 1.1;
  const W = 600;
  const H = 200;
  const x = (i: number) => (i / (series.length - 1)) * W;
  const y = (v: number) => H - (v / max) * H;
  const path = series.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  return (
    <div className="rounded-xl border-2 border-border bg-terminal p-3">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-52 w-full" role="img" aria-label="Request rate chart">
        <line x1={0} x2={W} y1={y(thr)} y2={y(thr)} className="stroke-accent" strokeDasharray="6 4" strokeWidth={1.5} />
        <line x1={0} x2={W} y1={y(mean)} y2={y(mean)} className="stroke-muted-foreground" strokeDasharray="2 4" />
        <path d={path} fill="none" className="stroke-primary" strokeWidth={2} />
        {series.map((v, i) =>
          v > thr ? <circle key={i} cx={x(i)} cy={y(v)} r={4} className="fill-offense" /> : null,
        )}
      </svg>
      <div className="mt-2 flex flex-wrap gap-4 font-mono text-[11px] text-muted-foreground">
        <span>mean {mean.toFixed(1)} {unit}</span>
        <span>σ {sd.toFixed(1)}</span>
        <span className="text-accent">threshold μ+{k}σ = {thr.toFixed(1)}</span>
        <span className="text-offense">flagged: {series.filter((v) => v > thr).length}</span>
      </div>
    </div>
  );
}
