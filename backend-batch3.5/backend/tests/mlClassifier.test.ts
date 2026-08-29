import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import os from "os";
import { promises as fs } from "fs";
import { LABELED_EMAILS } from "../src/ml/dataset";
import { predictPhishingProbability, stratifiedSplit, trainSerializedModel } from "../src/ml/model";
import { assessMl, getDefaultPredictor, loadSerializedModel, mlInputFromEmail, resetMlModelCache } from "../src/analyzers/mlClassifier";
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

test("a blank explicit modelPath argument falls back to the bundled default model, not an empty path", async () => {
  // Root-cause regression test: `loadSerializedModel("")` used to try
  // fs.readFile("") (always fails) instead of falling back to the
  // bundled models/tfidf-logistic-v1.json.
  const loaded = await loadSerializedModel("");
  assert.ok(loaded, "blank modelPath must fall back to the bundled model, not resolve to an empty path");
  assert.equal(loaded!.model, "tfidf-logistic-v1");
});

test("a blank ML_MODEL_PATH env var falls back to the bundled default model, not an empty path", async () => {
  // Root-cause regression test for the actual reported bug: .env.example
  // ships `ML_MODEL_PATH=` (present but blank). dotenv sets
  // process.env.ML_MODEL_PATH to "" in that case — "" is not
  // null/undefined, so a bare `??` chain does NOT fall through to the
  // bundled model path, silently breaking local ML in any environment
  // that copied .env.example verbatim.
  const previous = process.env.ML_MODEL_PATH;
  process.env.ML_MODEL_PATH = "";
  try {
    const loaded = await loadSerializedModel();
    assert.ok(loaded, "blank ML_MODEL_PATH must fall back to the bundled model, not resolve to an empty path");
    assert.equal(loaded!.model, "tfidf-logistic-v1");
  } finally {
    if (previous === undefined) delete process.env.ML_MODEL_PATH;
    else process.env.ML_MODEL_PATH = previous;
  }
});

test("a whitespace-only ML_MODEL_PATH env var also falls back to the bundled default model", async () => {
  const previous = process.env.ML_MODEL_PATH;
  process.env.ML_MODEL_PATH = "   ";
  try {
    const loaded = await loadSerializedModel();
    assert.ok(loaded);
    assert.equal(loaded!.model, "tfidf-logistic-v1");
  } finally {
    if (previous === undefined) delete process.env.ML_MODEL_PATH;
    else process.env.ML_MODEL_PATH = previous;
  }
});

test("an explicit non-blank modelPath still takes priority over ML_MODEL_PATH", async () => {
  const { model } = trainSerializedModel(LABELED_EMAILS);
  const file = path.join(os.tmpdir(), `ml-priority-test-${Date.now()}.json`);
  await fs.writeFile(file, JSON.stringify(model), "utf-8");

  const previous = process.env.ML_MODEL_PATH;
  process.env.ML_MODEL_PATH = path.join(os.tmpdir(), "should-not-be-used.json");
  try {
    const loaded = await loadSerializedModel(file);
    assert.ok(loaded);
  } finally {
    if (previous === undefined) delete process.env.ML_MODEL_PATH;
    else process.env.ML_MODEL_PATH = previous;
  }
});

test("end-to-end: getDefaultPredictor + assessMl produce a genuine AVAILABLE result from the bundled model when ML_MODEL_PATH is blank", async () => {
  const previous = process.env.ML_MODEL_PATH;
  process.env.ML_MODEL_PATH = "";
  resetMlModelCache();
  try {
    const predictor = await getDefaultPredictor();
    assert.ok(predictor, "getDefaultPredictor() must not be null when a real bundled model is present");

    const { mlAssessment, evidence } = assessMl({
      emailId: "EMAIL-BLANK-ENV",
      input: mlInputFromEmail(parsed("Urgent: verify your account immediately", "Click here to verify your account and enter your password."), 1, {
        urgency: 2,
        credential_request: 1,
        financial_request: 0,
        call_to_action: 1,
      }),
      predictor,
    });

    assert.equal(mlAssessment.status, "AVAILABLE");
    assert.equal(mlAssessment.model, "tfidf-logistic-v1");
    assert.ok(typeof mlAssessment.probability === "number" && Number.isFinite(mlAssessment.probability));
    assert.ok(mlAssessment.probability! >= 0 && mlAssessment.probability! <= 1);
    assert.ok(mlAssessment.classification === "phishing" || mlAssessment.classification === "legitimate");
    assert.ok(Array.isArray(evidence));
  } finally {
    if (previous === undefined) delete process.env.ML_MODEL_PATH;
    else process.env.ML_MODEL_PATH = previous;
    resetMlModelCache();
  }
});
