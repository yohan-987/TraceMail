import { promises as fs } from "fs";
import path from "path";
import { LABELED_EMAILS } from "./dataset";
import { stratifiedSplit, documentText, toMlInput } from "./model";

/**
 * Writes ml-transformer/data/dataset_split.json using the exact same
 * `stratifiedSplit()` (seed 26106) the classical TF-IDF+LR pipeline uses,
 * so a transformer trained from this file is compared against the
 * classical model on an identical test set — required for the fair
 * comparison in docs/ml/AUDIT.md / Phase 7. The split logic is not
 * reimplemented in Python: this script is the single source of truth,
 * exported once to a flat JSON file the Python pipeline only reads.
 */
async function main() {
  const { train, validation, test } = stratifiedSplit(LABELED_EMAILS);

  const toRow = (row: (typeof LABELED_EMAILS)[number]) => ({
    text: documentText(toMlInput(row)),
    label: row.label,
  });

  const payload = {
    splitSeed: 26106,
    note:
      "Exported from src/ml/dataset.ts via stratifiedSplit() so the " +
      "transformer pipeline evaluates on the identical held-out test " +
      "set as the classical TF-IDF+LR benchmark. Do not regenerate this " +
      "file with a different seed without also regenerating the " +
      "classical benchmark for the same comparison to remain valid.",
    train: train.map(toRow),
    validation: validation.map(toRow),
    test: test.map(toRow),
  };

  const outDir = path.join(__dirname, "..", "..", "ml-transformer", "data");
  await fs.mkdir(outDir, { recursive: true });
  const outPath = path.join(outDir, "dataset_split.json");
  await fs.writeFile(outPath, JSON.stringify(payload, null, 2), "utf-8");
  console.log(`Wrote ${outPath} (train=${train.length}, validation=${validation.length}, test=${test.length})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
