<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Architecture rules
- Course content (units, lessons, labs, IDS modules) lives as typed data in `src/content/units/*.ts`; why: versioned with code, no CMS.
- XP, streaks and hearts change only through security-definer RPCs (`complete_activity`, `lose_heart`); why: clients cannot edit their own scores.
- Labs and the IDS workbench run fully in-browser via `src/lib/rule-engine.ts` (Snort-style subset); why: safe simulated labs, no real network access.
