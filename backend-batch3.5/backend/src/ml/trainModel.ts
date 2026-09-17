import { promises as fs } from "fs";
import path from "path";
import { LABELED_EMAILS } from "./dataset";
import { trainSerializedModel } from "./model";
import { explainModel } from "./explain";

async function main() {
  const { model, metrics, validationMetrics } = trainSerializedModel(LABELED_EMAILS);
  const outDir = path.join(__dirname, "..", "..", "models");
  await fs.mkdir(outDir, { recursive: true });
  await fs.writeFile(path.join(outDir, "tfidf-logistic-v1.json"), JSON.stringify(model), "utf-8");
  await fs.writeFile(
    path.join(outDir, "tfidf-logistic-v1.metrics.json"),
    JSON.stringify(
      {
        note:
          "Prototype hold-out metrics on an 81-example hand-authored dataset " +
          "(40 phishing / 41 legitimate). Test split is 13 examples — treat " +
          "as illustrative, not production-grade statistical evidence. " +
          "Probability is an uncalibrated model score, not a real-world " +
          "probability of attack. See docs/ml/AUDIT.md for the full audit, " +
          "the leakage fix applied to this version, and the baseline-vs-" +
          "improved comparison this configuration was chosen from.",
        modelVersion: model.modelVersion,
        metadata: model.metadata,
        test: metrics,
        validation: validationMetrics,
        explanation: explainModel(model, 10),
      },
      null,
      2
    ),
    "utf-8"
  );
  console.log("Wrote models/tfidf-logistic-v1.json");
  console.log("test", metrics);
  console.log("validation", validationMetrics);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
