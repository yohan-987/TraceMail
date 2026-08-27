import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import os from "os";
import { promises as fs } from "fs";
import { LABELED_EMAILS } from "../src/ml/dataset";
import { predictPhishingProbability, stratifiedSplit, trainSerializedModel } from "../src/ml/model";
import { assessMl, loadSerializedModel, mlInputFromEmail } from "../src/analyzers/mlClassifier";
import type { ParsedEmail } from "../src/schemas/types";

function parsed(subject: string, body: string): ParsedEmail {
  return {
    emailId: "EMAIL-ML",
    subject,
    from: [],
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: null,
    messageId: null,
    headers: { normalized: {}, raw: [] },
    body: { text: body, html: null },
    attachments: [],
  };
}

test("train/validation/test split is disjoint (no leakage)", () => {
  const { train, validation, test: holdout } = stratifiedSplit(LABELED_EMAILS, 26106);
  const key = (r: { subject: string; body: string }) => `${r.subject}||${r.body}`;
  const trainKeys = new Set(train.map(key));
  for (const row of [...validation, ...holdout]) {
    assert.equal(trainKeys.has(key(row)), false);
  }
  assert.ok(train.length > 0 && validation.length > 0 && holdout.length > 0);
});

test("trained model loads and predicts a bounded probability", () => {
  const { model } = trainSerializedModel(LABELED_EMAILS);
  const pPhish = predictPhishingProbability(model, {
    subject: "Urgent: verify your account immediately",
    body: "Click here to verify your account and enter your password.",
    urlCount: 1,
    urgency: 2,
    credentialRequest: 1,
    financialRequest: 0,
  });
  const pHam = predictPhishingProbability(model, {
    subject: "Weekly digest",
    body: "Here is your weekly digest of company news and updates.",
    urlCount: 0,
    urgency: 0,
    credentialRequest: 0,
    financialRequest: 0,
  });
  assert.ok(pPhish >= 0 && pPhish <= 1);
  assert.ok(pHam >= 0 && pHam <= 1);
  assert.ok(pPhish > pHam);
});

test("assessMl is UNAVAILABLE when the predictor cannot load", () => {
  const { mlAssessment, evidence } = assessMl({
    emailId: "EMAIL-1",
    input: mlInputFromEmail(parsed("hi", "hello"), 0, {
      urgency: 0,
      credential_request: 0,
      financial_request: 0,
      call_to_action: 0,
    }),
    predictor: null,
  });
  assert.equal(mlAssessment.status, "UNAVAILABLE");
  assert.equal(mlAssessment.probability, null);
  assert.equal(evidence.length, 0);
});

test("assessMl ERROR when probability is out of bounds", () => {
  const { mlAssessment } = assessMl({
    emailId: "EMAIL-2",
    input: mlInputFromEmail(parsed("x", "y"), 0, {
      urgency: 0,
      credential_request: 0,
      financial_request: 0,
      call_to_action: 0,
    }),
    predictor: { predict: () => ({ probability: 1.4 }) },
  });
  assert.equal(mlAssessment.status, "ERROR");
});

test("valid prediction emits ML evidence only for high phishing scores", () => {
  const { mlAssessment, evidence } = assessMl({
    emailId: "EMAIL-3",
    input: mlInputFromEmail(parsed("verify", "password"), 1, {
      urgency: 1,
      credential_request: 1,
      financial_request: 0,
      call_to_action: 0,
    }),
    predictor: { predict: () => ({ probability: 0.94 }) },
  });
  assert.equal(mlAssessment.status, "AVAILABLE");
  assert.equal(mlAssessment.classification, "phishing");
  assert.equal(mlAssessment.probability, 0.94);
  assert.equal(mlAssessment.model, "tfidf-logistic-v1");
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].provenance, "ML_ASSESSMENT");
  assert.equal(evidence[0].category, "content");
});

test("loadSerializedModel returns null for a missing file", async () => {
  const loaded = await loadSerializedModel(path.join(os.tmpdir(), "no-such-model.json"));
  assert.equal(loaded, null);
});

test("loadSerializedModel reads a saved model", async () => {
  const { model } = trainSerializedModel(LABELED_EMAILS);
  const file = path.join(os.tmpdir(), `ml-test-${Date.now()}.json`);
  await fs.writeFile(file, JSON.stringify(model), "utf-8");
  const loaded = await loadSerializedModel(file);
  assert.ok(loaded);
  assert.equal(loaded.model, "tfidf-logistic-v1");
});
