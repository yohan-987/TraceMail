import { promises as fs } from "fs";
import path from "path";
import type { MLAssessment, MLClassification, RiskEvidenceItem } from "../schemas/types";
import type { ContentFeatureCounts } from "./contentHeuristics";
import type { ParsedEmail } from "../schemas/types";
import {
  MODEL_NAME,
  MODEL_VERSION,
  predictPhishingProbability,
  type MlInput,
  type SerializedMlModel,
} from "../ml/model";

export interface MlPredictor {
  predict(input: MlInput): { probability: number };
}

const ML_EVIDENCE_THRESHOLD = 0.6;

let cachedModel: SerializedMlModel | null | undefined;

export function resetMlModelCache(): void {
  cachedModel = undefined;
}

export async function loadSerializedModel(modelPath?: string): Promise<SerializedMlModel | null> {
  const resolved =
    modelPath ??
    process.env.ML_MODEL_PATH ??
    path.join(__dirname, "..", "..", "models", "tfidf-logistic-v1.json");
  try {
    const raw = await fs.readFile(resolved, "utf-8");
    const parsed = JSON.parse(raw) as SerializedMlModel;
    if (!parsed?.tfidf?.vocabulary || !parsed?.logistic?.weights) return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function getDefaultPredictor(): Promise<MlPredictor | null> {
  if (cachedModel === undefined) {
    cachedModel = await loadSerializedModel();
  }
  if (!cachedModel) return null;
  const model = cachedModel;
  return {
    predict(input: MlInput) {
      return { probability: predictPhishingProbability(model, input) };
    },
  };
}

export function mlInputFromEmail(
  parsed: ParsedEmail,
  urlCount: number,
  features: ContentFeatureCounts
): MlInput {
  const body = `${parsed.body.text ?? ""}\n${parsed.body.html ?? ""}`.trim();
  return {
    subject: parsed.subject ?? "",
    body,
    urlCount,
    urgency: features.urgency,
    credentialRequest: features.credential_request,
    financialRequest: features.financial_request,
  };
}

export function assessMl(options: {
  emailId: string;
  input: MlInput;
  predictor: MlPredictor | null;
}): { mlAssessment: MLAssessment; evidence: RiskEvidenceItem[] } {
  const { emailId, input, predictor } = options;
  if (!predictor) {
    return {
      mlAssessment: {
        emailId,
        model: null,
        modelVersion: null,
        classification: null,
        probability: null,
        status: "UNAVAILABLE",
      },
      evidence: [],
    };
  }

  try {
    const probability = predictor.predict(input).probability;
    if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
      return {
        mlAssessment: {
          emailId,
          model: MODEL_NAME,
          modelVersion: MODEL_VERSION,
          classification: null,
          probability: null,
          status: "ERROR",
        },
        evidence: [],
      };
    }

    const classification: MLClassification = probability >= 0.5 ? "phishing" : "legitimate";
    const mlAssessment: MLAssessment = {
      emailId,
      model: MODEL_NAME,
      modelVersion: MODEL_VERSION,
      classification,
      probability,
      status: "AVAILABLE",
    };

    const evidence: RiskEvidenceItem[] = [];
    if (classification === "phishing" && probability >= ML_EVIDENCE_THRESHOLD) {
      evidence.push({
        type: "ml_phishing_classification",
        severity: probability >= 0.85 ? "high" : "medium",
        weight: Math.round(probability * 35),
        message: `TF-IDF logistic classifier scored this message as phishing (uncalibrated score ${probability.toFixed(2)}).`,
        evidence: { model: MODEL_NAME, modelVersion: MODEL_VERSION, probability },
        category: "content",
        provenance: "ML_ASSESSMENT",
      });
    }

    return { mlAssessment, evidence };
  } catch {
    return {
      mlAssessment: {
        emailId,
        model: MODEL_NAME,
        modelVersion: MODEL_VERSION,
        classification: null,
        probability: null,
        status: "UNAVAILABLE",
      },
      evidence: [],
    };
  }
}
