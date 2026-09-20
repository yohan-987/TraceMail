import { test } from "node:test";
import assert from "node:assert/strict";
import { LABELED_EMAILS } from "../src/ml/dataset";
import { deriveStructuredFeatures } from "../src/ml/datasetFeatures";
import { trainSerializedModel, stratifiedSplit, toMlInput } from "../src/ml/model";
import { explainModel } from "../src/ml/explain";
import { runBenchmark } from "../src/ml/benchmark";

test("dataset rows no longer carry hand-authored structured-feature extras", () => {
  // Regression test for the leakage finding in docs/ml/AUDIT.md: the old
  // rows carried urlCount/urgency/credentialRequest/financialRequest
  // numbers that were a near-perfect proxy for the label rather than a
  // measurement of the text. LabeledEmail should only ever describe the
  // raw text and its label now.
  for (const row of LABELED_EMAILS) {
    assert.deepEqual(Object.keys(row).sort(), ["body", "label", "subject"]);
  }
});

test("training-time structured features match the production feature extractor for the same text", () => {
  // toMlInput() must derive features the same way for every row — there
  // is no per-row override left to disagree with analyzeContent().
  for (const row of LABELED_EMAILS.slice(0, 15)) {
    const viaToMlInput = toMlInput(row);
    const viaDirect = deriveStructuredFeatures(row.subject, row.body);
    assert.equal(viaToMlInput.urgency, viaDirect.urgency);
    assert.equal(viaToMlInput.credentialRequest, viaDirect.credentialRequest);
    assert.equal(viaToMlInput.financialRequest, viaDirect.financialRequest);
    assert.equal(viaToMlInput.urlCount, viaDirect.urlCount);
  }
});

test("structured features alone no longer trivially separate every row by label", () => {
  // Before the fix, every phishing row had at least one non-zero
  // structured feature and every legitimate row had all-zero — a
  // constructed shortcut, not a real signal. After deriving features
  // from text, this should no longer hold for the whole dataset.
  const phishingAllZero = LABELED_EMAILS.filter((r) => {
    if (r.label !== 1) return false;
    const f = deriveStructuredFeatures(r.subject, r.body);
    return f.urlCount === 0 && f.urgency === 0 && f.credentialRequest === 0 && f.financialRequest === 0;
  });
  assert.ok(
    phishingAllZero.length > 0,
    "expected at least some phishing rows whose text doesn't trip the keyword heuristics, proving structured features are no longer a perfect label proxy"
  );
});

test("trained model carries reproducibility metadata", () => {
  const { model } = trainSerializedModel(LABELED_EMAILS);
  assert.match(model.metadata.datasetHash, /^[0-9a-f]{64}$/);
  assert.equal(model.metadata.datasetSize, LABELED_EMAILS.length);
  assert.equal(model.metadata.splitSeed, 26106);
  assert.equal(model.metadata.tokenizer, "unigram+bigram");
  assert.equal(typeof model.metadata.trainedAt, "string");
  assert.ok(!Number.isNaN(Date.parse(model.metadata.trainedAt)));
  assert.deepEqual(model.metadata.hyperparams, { learningRate: 0.5, epochs: 400, l2: 0.02 });
});

test("dataset hash changes if the training data changes", () => {
  const { model: modelA } = trainSerializedModel(LABELED_EMAILS);
  const mutated = [...LABELED_EMAILS, { subject: "extra", body: "extra row", label: 0 as const }];
  const { model: modelB } = trainSerializedModel(mutated);
  assert.notEqual(modelA.metadata.datasetHash, modelB.metadata.datasetHash);
});

test("evaluation metrics report false positive / false negative rate", () => {
  const { train, test: holdout } = stratifiedSplit(LABELED_EMAILS);
  const { model } = trainSerializedModel(LABELED_EMAILS);
  assert.ok(train.length > 0 && holdout.length > 0);
  const { metrics } = trainSerializedModel(LABELED_EMAILS);
  assert.equal(typeof metrics.falsePositiveRate, "number");
  assert.equal(typeof metrics.falseNegativeRate, "number");
  assert.ok(metrics.falsePositiveRate >= 0 && metrics.falsePositiveRate <= 1);
  assert.ok(metrics.falseNegativeRate >= 0 && metrics.falseNegativeRate <= 1);
  assert.ok(model.tfidf.vocabulary.length > 0);
});

test("explainModel returns real vocabulary terms, not structured-feature slots or fabricated labels", () => {
  const { model } = trainSerializedModel(LABELED_EMAILS);
  const explanation = explainModel(model, 5);
  assert.equal(explanation.method, "logistic_regression_coefficients");
  assert.equal(explanation.scope, "global_model_coefficients_not_per_prediction");
  assert.ok(explanation.topPositive.length > 0);
  assert.ok(explanation.topNegative.length > 0);
  const vocab = new Set(model.tfidf.vocabulary);
  for (const term of [...explanation.topPositive, ...explanation.topNegative]) {
    assert.ok(vocab.has(term.term), `explained term "${term.term}" must be an actual vocabulary entry`);
  }
  // Positive terms must actually have positive weight and vice versa —
  // an honesty check on the explanation itself, not just its shape.
  for (const t of explanation.topPositive) assert.ok(t.weight > 0);
  for (const t of explanation.topNegative) assert.ok(t.weight < 0);
});

test("benchmark never reports a transformer result it did not measure", async () => {
  const report = await runBenchmark();
  assert.equal(report.transformerBenchmark, "NOT EXECUTED");
  assert.equal(report.newBenchmark.length, 2);
  for (const row of report.newBenchmark) {
    assert.ok(row.test.splitSizes.test > 0);
    assert.equal(typeof row.modelSizeBytes, "number");
    assert.equal(typeof row.meanInferenceLatencyMs, "number");
  }
  assert.equal(report.datasetAudit.totalExamples, LABELED_EMAILS.length);
  assert.equal(report.datasetAudit.phishing + report.datasetAudit.legitimate, LABELED_EMAILS.length);
});
