import { fitTfidf, transformTfidf, type TfidfModel } from "./tfidf";
import { fitLogisticRegression, predictProba, type LogisticRegressionModel } from "./logisticRegression";
import type { LabeledEmail } from "./dataset";

export const MODEL_NAME = "tfidf-logistic-v1";
export const MODEL_VERSION = "1.0";

export interface SerializedMlModel {
  model: typeof MODEL_NAME;
  modelVersion: typeof MODEL_VERSION;
  tfidf: TfidfModel;
  logistic: LogisticRegressionModel;
  structuredFeatureCount: number;
}

export interface MlInput {
  subject: string;
  body: string;
  urlCount: number;
  urgency: number;
  credentialRequest: number;
  financialRequest: number;
}

export interface ConfusionMatrix {
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
}

export interface EvaluationMetrics {
  precision: number;
  recall: number;
  f1: number;
  confusionMatrix: ConfusionMatrix;
  splitSizes: { train: number; validation: number; test: number };
}

const STRUCTURED = 4;

export function structuredFeatures(input: Pick<MlInput, "urlCount" | "urgency" | "credentialRequest" | "financialRequest">): number[] {
  return [
    Math.min(input.urlCount, 10) / 10,
    Math.min(input.urgency, 5) / 5,
    Math.min(input.credentialRequest, 5) / 5,
    Math.min(input.financialRequest, 5) / 5,
  ];
}

export function documentText(input: Pick<MlInput, "subject" | "body">): string {
  return `${input.subject}\n${input.body}`;
}

export function vectorize(input: MlInput, tfidf: TfidfModel): number[] {
  return [...transformTfidf(documentText(input), tfidf), ...structuredFeatures(input)];
}

export function toMlInput(row: LabeledEmail): MlInput {
  return {
    subject: row.subject,
    body: row.body,
    urlCount: row.urlCount ?? 0,
    urgency: row.urgency ?? 0,
    credentialRequest: row.credentialRequest ?? 0,
    financialRequest: row.financialRequest ?? 0,
  };
}

function mulberry32(seed: number): () => number {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function stratifiedSplit(
  data: LabeledEmail[],
  seed = 26106
): { train: LabeledEmail[]; validation: LabeledEmail[]; test: LabeledEmail[] } {
  const rng = mulberry32(seed);
  const byLabel = new Map<number, LabeledEmail[]>();
  for (const row of data) {
    const list = byLabel.get(row.label) ?? [];
    list.push(row);
    byLabel.set(row.label, list);
  }

  const train: LabeledEmail[] = [];
  const validation: LabeledEmail[] = [];
  const test: LabeledEmail[] = [];

  for (const list of byLabel.values()) {
    const shuffled = [...list];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const n = shuffled.length;
    const nTrain = Math.max(1, Math.floor(n * 0.7));
    const nVal = Math.max(1, Math.floor(n * 0.15));
    train.push(...shuffled.slice(0, nTrain));
    validation.push(...shuffled.slice(nTrain, nTrain + nVal));
    test.push(...shuffled.slice(nTrain + nVal));
  }

  return { train, validation, test };
}

export function evaluate(model: SerializedMlModel, rows: LabeledEmail[]): Omit<EvaluationMetrics, "splitSizes"> {
  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  for (const row of rows) {
    const prob = predictProba(model.logistic, vectorize(toMlInput(row), model.tfidf));
    const pred = prob >= 0.5 ? 1 : 0;
    if (pred === 1 && row.label === 1) tp++;
    else if (pred === 1 && row.label === 0) fp++;
    else if (pred === 0 && row.label === 0) tn++;
    else fn++;
  }
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return {
    precision,
    recall,
    f1,
    confusionMatrix: {
      truePositive: tp,
      falsePositive: fp,
      trueNegative: tn,
      falseNegative: fn,
    },
  };
}

export function trainSerializedModel(data: LabeledEmail[]): {
  model: SerializedMlModel;
  metrics: EvaluationMetrics;
  validationMetrics: Omit<EvaluationMetrics, "splitSizes">;
} {
  const { train, validation, test } = stratifiedSplit(data);
  const tfidf = fitTfidf(train.map((r) => documentText(toMlInput(r))));
  const X = train.map((r) => vectorize(toMlInput(r), tfidf));
  const y = train.map((r) => r.label);
  const logistic = fitLogisticRegression(X, y, { learningRate: 0.5, epochs: 400, l2: 0.02 });
  const model: SerializedMlModel = {
    model: MODEL_NAME,
    modelVersion: MODEL_VERSION,
    tfidf,
    logistic,
    structuredFeatureCount: STRUCTURED,
  };

  // Validation is used only for reporting — hyperparameters are fixed,
  // so the test split is not used to pick a model.
  const testMetrics = evaluate(model, test);
  const validationMetrics = evaluate(model, validation);

  return {
    model,
    metrics: {
      ...testMetrics,
      splitSizes: { train: train.length, validation: validation.length, test: test.length },
    },
    validationMetrics,
  };
}

export function predictPhishingProbability(model: SerializedMlModel, input: MlInput): number {
  const p = predictProba(model.logistic, vectorize(input, model.tfidf));
  return Math.min(1, Math.max(0, p));
}
