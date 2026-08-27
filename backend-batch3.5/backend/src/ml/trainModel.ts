import { promises as fs } from "fs";
import path from "path";
import { LABELED_EMAILS } from "./dataset";
import { trainSerializedModel } from "./model";

async function main() {
  const { model, metrics, validationMetrics } = trainSerializedModel(LABELED_EMAILS);
  const outDir = path.join(__dirname, "..", "..", "models");
  await fs.mkdir(outDir, { recursive: true });
  await fs.writeFile(path.join(outDir, "tfidf-logistic-v1.json"), JSON.stringify(model), "utf-8");
  await fs.writeFile(
    path.join(outDir, "tfidf-logistic-v1.metrics.json"),
    JSON.stringify(
      {
        note: "Prototype hold-out metrics. Not production accuracy. Probability is an uncalibrated model score.",
        test: metrics,
        validation: validationMetrics,
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
