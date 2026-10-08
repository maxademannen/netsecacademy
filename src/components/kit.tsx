import { cn } from "@/lib/utils";
import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "accent" | "offense" | "ghost" | "outline";

const variants: Record<Variant, string> = {
  primary: "bg-primary text-primary-foreground border-primary-shade hover:brightness-105",
  accent: "bg-accent text-accent-foreground border-accent-shade hover:brightness-105",
  offense: "bg-offense text-offense-foreground border-offense-shade hover:brightness-105",
  outline: "bg-card text-foreground border-border hover:bg-secondary",
  ghost: "border-transparent bg-transparent text-muted-foreground hover:text-foreground hover:bg-secondary",
};

export function Btn({
  variant = "primary",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      {...props}
      className={cn(
        "btn-3d inline-flex items-center justify-center gap-2 rounded-xl border-2 px-5 py-2.5 text-sm font-bold uppercase tracking-wide disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        className,
      )}
    />
  );
}

export function Panel({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div {...props} className={cn("rounded-2xl border-2 border-border bg-card p-5", className)} />;
}

export function ToneTag({ tone }: { tone: "offense" | "defense" | "foundation" | "info" | undefined }) {
  if (!tone || tone === "info") return null;
  const map = {
    offense: "bg-offense/15 text-offense border-offense/40",
    defense: "bg-primary/15 text-primary border-primary/40",
    foundation: "bg-info/15 text-info border-info/40",
  } as const;
  const label = { offense: "Offense", defense: "Defense", foundation: "Foundation" }[tone];
  return (
    <span className={cn("rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider", map[tone])}>
      {label}
    </span>
  );
}
