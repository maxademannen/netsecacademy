
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Btn, Panel } from "@/components/kit";
import { toast } from "sonner";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in — NetSec Academy" },
      {
        name: "description",
        content:
          "Sign in or create your NetSec Academy account to save progress and streaks.",
      },
      { property: "og:title", content: "Sign in — NetSec Academy" },
      {
        property: "og:description",
        content: "Sign in or create your NetSec Academy account.",
      },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"in" | "up">("in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) {
        navigate({ to: "/learn", replace: true });
      }
    });

    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) {
        navigate({ to: "/learn", replace: true });
      }
    });

    return () => data.subscription.unsubscribe();
  }, [navigate]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);

    try {
      if (mode === "up") {
        if (username.trim().length < 2) {
          throw new Error("Pick a username of at least 2 characters.");
        }

        const { error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            emailRedirectTo: `${window.location.origin}/learn`,
            data: {
              username: username.trim().slice(0, 24),
            },
          },
        });

        if (error) throw error;

        setSent(true);
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });

        if (error) throw error;
      }
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Something went wrong"
      );
    } finally {
      setBusy(false);
    }
  }

  async function google() {
    setBusy(true);

    try {
      const { error } = await supabase.auth.signInWithOAuth({
        provider: "google",
        options: {
          redirectTo: `${window.location.origin}/learn`,
        },
      });

      if (error) {
        toast.error(error.message);
      }
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Google sign-in failed"
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <Panel className="w-full max-w-sm space-y-5">
        <Link to="/" className="font-mono text-sm font-bold text-primary">
          net<span className="text-foreground">sec</span>://academy
        </Link>

        <h1 className="text-2xl font-bold">
          {mode === "in" ? "Welcome back" : "Create your account"}
        </h1>

        {sent ? (
          <p className="text-sm text-muted-foreground">
            Check your inbox — we sent a confirmation link to{" "}
            <b className="text-foreground">{email}</b>. Click it to start
            learning.
          </p>
        ) : (
          <>
            <form onSubmit={submit} className="space-y-3">
              {mode === "up" && (
                <input
                  required
                  placeholder="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  aria-label="Username"
                  className="w-full rounded-xl border-2 border-border bg-terminal px-3 py-2.5 outline-none focus:border-primary"
                />
              )}

              <input
                required
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                aria-label="Email"
                className="w-full rounded-xl border-2 border-border bg-terminal px-3 py-2.5 outline-none focus:border-primary"
              />

              <input
                required
                type="password"
                minLength={6}
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-label="Password"
                className="w-full rounded-xl border-2 border-border bg-terminal px-3 py-2.5 outline-none focus:border-primary"
              />

              <Btn type="submit" disabled={busy} className="w-full">
                {busy
                  ? "Please wait..."
                  : mode === "in"
                    ? "Sign in"
                    : "Sign up"}
              </Btn>
            </form>

            <Btn
              type="button"
              variant="outline"
              onClick={google}
              disabled={busy}
              className="w-full normal-case"
            >
              {busy ? "Please wait..." : "Continue with Google"}
            </Btn>

            <p className="text-center text-sm text-muted-foreground">
              {mode === "in" ? "New here?" : "Already have an account?"}{" "}
              <button
                type="button"
                onClick={() => setMode(mode === "in" ? "up" : "in")}
                className="text-primary underline-offset-4 hover:underline"
              >
                {mode === "in" ? "Create an account" : "Sign in"}
              </button>
            </p>
          </>
        )}
      </Panel>
    </div>
  );
}
