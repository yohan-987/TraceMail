/**
 * Prompt 9 (AI Investigation UX), requirement: "Repeated identical
 * observations should be grouped" + "Top 3-5 evidence points".
 *
 * Kept in its own dependency-free module (no React/JSX, no other
 * project imports) specifically so this one piece of real logic in
 * the AI Investigation page can be unit-tested directly, rather than
 * only reachable through a full React render.
 *
 * Consolidates the deterministic explanation list with the AI's own
 * (already-consolidated, per Prompt 6's prompt instructions) topReasons
 * into ONE deduplicated list, capped at `max`. Dedup is exact-string on
 * the trimmed, lowercased message — this does not re-interpret or
 * re-score anything; it only prevents the same sentence appearing
 * twice when both the deterministic evidence and the AI summary happen
 * to describe the same finding in the same words.
 */
export function consolidateTopEvidencePoints(
  deterministicMessages: string[],
  aiTopReasons: string[],
  max = 5
): string[] {
  const seen = new Set<string>();
  const combined: string[] = [];
  for (const item of [...deterministicMessages, ...aiTopReasons]) {
    const trimmed = String(item ?? "").trim();
    const key = trimmed.toLowerCase();
    if (!trimmed || seen.has(key)) continue;
    seen.add(key);
    combined.push(trimmed);
  }
  return combined.slice(0, max);
}
