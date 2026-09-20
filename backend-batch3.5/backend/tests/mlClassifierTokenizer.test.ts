import { test } from "node:test";
import assert from "node:assert/strict";
import { assessMl } from "../src/analyzers/mlClassifier";
import type { MlPredictor } from "../src/analyzers/mlClassifier";

// Prompt 10 — "unambiguous model/version display" (MODEL / VERSION /
// TOKENIZATION). Confirms the new `tokenizer` field is correctly
// sourced from the predictor's describe() output (which in production
// reads the loaded model file's own metadata.tokenizer — see
// ml/model.ts's SerializedMlModel.metadata.tokenizer, confirmed
// present in the real tfidf-logistic-v1.json via direct inspection),
// never fabricated, and null wherever the model genuinely can't be
// described. Does not touch or re-test predictPhishingProbability()
// itself — that scoring logic is unchanged (Prompt 10: "do not touch
// risk calculations").

const input = { text: "hello", urlCount: 0, featureCounts: {} } as any;

test("tokenizer is populated from a real describe() on the success path", () => {
  const predictor: MlPredictor = {
    predict: () => ({ probability: 0.2 }),
    describe: () => ({
      model: "tfidf-logistic-v1",
      modelVersion: "2.0",
      tokenizer: "unigram+bigram",
      explanation: { topFeatures: [] } as any,
    }),
  };
  const { mlAssessment } = assessMl({ emailId: "t", input, predictor });
  assert.equal(mlAssessment.status, "AVAILABLE");
  assert.equal(mlAssessment.tokenizer, "unigram+bigram");
  assert.equal(mlAssessment.model, "tfidf-logistic-v1");
  assert.equal(mlAssessment.modelVersion, "2.0");
});

test("tokenizer is null when the predictor has no describe() at all (bare mock)", () => {
  const predictor: MlPredictor = { predict: () => ({ probability: 0.2 }) };
  const { mlAssessment } = assessMl({ emailId: "t", input, predictor });
  assert.equal(mlAssessment.status, "AVAILABLE");
  assert.equal(mlAssessment.tokenizer, null);
});

test("tokenizer is null when there is no predictor at all", () => {
  const { mlAssessment } = assessMl({ emailId: "t", input, predictor: null });
  assert.equal(mlAssessment.status, "UNAVAILABLE");
  assert.equal(mlAssessment.tokenizer, null);
});

test("tokenizer is still surfaced on the ERROR path (invalid probability) as long as describe() succeeded", () => {
  const predictor: MlPredictor = {
    predict: () => ({ probability: 42 }), // out of [0,1] range -> ERROR path
    describe: () => ({
      model: "tfidf-logistic-v1",
      modelVersion: "2.0",
      tokenizer: "unigram+bigram",
      explanation: { topFeatures: [] } as any,
    }),
  };
  const { mlAssessment } = assessMl({ emailId: "t", input, predictor });
  assert.equal(mlAssessment.status, "ERROR");
  assert.equal(mlAssessment.tokenizer, "unigram+bigram");
});

test("scoring/classification logic is unchanged by the tokenizer plumbing (0.5 threshold, weight formula)", () => {
  const predictor: MlPredictor = {
    predict: () => ({ probability: 0.9 }),
    describe: () => ({ model: "m", modelVersion: "v", tokenizer: "t", explanation: {} as any }),
  };
  const { mlAssessment, evidence } = assessMl({ emailId: "t", input, predictor });
  assert.equal(mlAssessment.classification, "phishing");
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].weight, Math.round(0.9 * 35));
});
