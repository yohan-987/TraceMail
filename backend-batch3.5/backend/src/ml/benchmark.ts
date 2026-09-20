import { promises as fs } from "fs";
import path from "path";
import { LABELED_EMAILS } from "./dataset";
import {
  trainSerializedModel,
  predictPhishingProbability,
  toMlInput,
  type EvaluationMetrics,
  type SerializedMlModel,
} from "./model";

/**
 * Reproducible ML benchmark (see docs/ml/AUDIT.md for the full writeup).
 *
 * Prints/writes:
 *  - OLD REPORTED METRICS: verbatim from the previously-shipped
 *    models/tfidf-logistic-v1.metrics.json, if present. Not
 *    recomputed — these numbers were measured under the leaky
 *    structured-feature setup described in dataset.ts, so they are
 *    kept for transparency, not treated as ground truth.
 *  - NEW REPRODUCIBLE BENCHMARK: computed by actually running the
 *    current (leakage-fixed) pipeline, for both TF-IDF tokenizer
 *    configurations, using the same fixed seed and the same untouched
 *    test split for both.
 *  - Latency and serialized model size, measured on this machine —
 *    reported as a rough indicator, not a production SLA.
 *
 * This script never fabricates a transformer row: no transformer is
 * trained here (see ml-transformer/ for that pipeline), so no
 * transformer numbers appear in this output.
 */

interface BenchmarkRow {
  config: string;
  tokenizer: string;
  vocabularySize: number;
  test: EvaluationMetrics;
  validation: Omit<EvaluationMetrics, "splitSizes">;
  modelSizeBytes: number;
  meanInferenceLatencyMs: number;
}

function measureLatency(model: SerializedMlModel, rows: typeof LABELED_EMAILS, iterations = 5): number {
  const inputs = rows.map(toMlInput);
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    for (const input of inputs) predictPhishingProbability(model, input);
  }
  const end = process.hrtime.bigint();
  const totalMs = Number(end - start) / 1e6;
  return totalMs / (iterations * inputs.length);
}

async function benchmarkConfig(config: string, tokenizer: "unigram" | "unigram+bigram"): Promise<BenchmarkRow> {
  const { model, metrics, validationMetrics } = trainSerializedModel(LABELED_EMAILS, { tokenizer });
  const serialized = JSON.stringify(model);
  return {
    config,
    tokenizer,
    vocabularySize: model.tfidf.vocabulary.length,
    test: metrics,
    validation: validationMetrics,
    modelSizeBytes: Buffer.byteLength(serialized, "utf-8"),
    meanInferenceLatencyMs: measureLatency(model, LABELED_EMAILS),
  };
}

export async function runBenchmark(): Promise<{
  oldReportedMetrics: unknown;
  newBenchmark: BenchmarkRow[];
  transformerBenchmark: "NOT EXECUTED";
  datasetAudit: {
    totalExamples: number;
    phishing: number;
    legitimate: number;
    note: string;
  };
}> {
  const metricsPath = path.join(__dirname, "..", "..", "models", "tfidf-logistic-v1.metrics.json");
  let oldReportedMetrics: unknown = null;
  try {
    oldReportedMetrics = JSON.parse(await fs.readFile(metricsPath, "utf-8"));
  } catch {
    oldReportedMetrics = null;
  }

  const newBenchmark = [
    await benchmarkConfig("baseline (unigram TF-IDF, leakage-fixed features)", "unigram"),
    await benchmarkConfig("improved (unigram+bigram TF-IDF, leakage-fixed features)", "unigram+bigram"),
  ];

  const phishing = LABELED_EMAILS.filter((r) => r.label === 1).length;
  const legitimate = LABELED_EMAILS.filter((r) => r.label === 0).length;

  return {
    oldReportedMetrics,
    newBenchmark,
    transformerBenchmark: "NOT EXECUTED",
    datasetAudit: {
      totalExamples: LABELED_EMAILS.length,
      phishing,
      legitimate,
      note:
        "81 hand-authored short examples. No exact or near-duplicate rows " +
        "(word-set Jaccard > 0.5) were found. Test split is only 13 " +
        "examples — a single flipped prediction moves F1 by roughly 8-9 " +
        "points, so treat all metrics here as illustrative, not " +
        "production-grade statistical evidence. See docs/ml/AUDIT.md.",
    },
  };
}

async function main() {
  const report = await runBenchmark();
  const outDir = path.join(__dirname, "..", "..", "models");
  await fs.mkdir(outDir, { recursive: true });
  const outPath = path.join(outDir, "benchmark-report.json");
  await fs.writeFile(outPath, JSON.stringify(report, null, 2), "utf-8");
  console.log("=== OLD REPORTED METRICS (pre-fix, kept for transparency) ===");
  console.log(JSON.stringify(report.oldReportedMetrics, null, 2));
  console.log("\n=== NEW REPRODUCIBLE BENCHMARK (leakage-fixed) ===");
  console.log(JSON.stringify(report.newBenchmark, null, 2));
  console.log("\nTRANSFORMER BENCHMARK: NOT EXECUTED (see ml-transformer/README.md)");
  console.log(`\nFull report written to ${outPath}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
