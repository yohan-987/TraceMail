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
import { explainModel, type ModelExplanation } from "../ml/explain";

export interface MlPredictor {
  predict(input: MlInput): { probability: number };
  /**
   * Optional: identifies which concrete model produced predictions from
   * this predictor, plus its global explanation. Added so the ML output
   * contract reports the model that actually ran — not just the
   * currently-bundled MODEL_NAME/MODEL_VERSION constants, which would be
   * wrong if ML_MODEL_PATH points at a different saved model — while
   * staying optional so existing simple test mocks that only implement
   * `predict()` keep working unchanged.
   */
  describe?(): { model: string; modelVersion: string; explanation: ModelExplanation };
}

const ML_EVIDENCE_THRESHOLD = 0.6;

let cachedModel: SerializedMlModel | null | undefined;

export function resetMlModelCache(): void {
  cachedModel = undefined;
}

// Treats a value that is unset OR blank/whitespace-only as "not provided".
// This matters specifically for env vars: `ML_MODEL_PATH=` (present but
// empty — exactly what .env.example ships, and what a .env copied from
// it will contain) sets process.env.ML_MODEL_PATH to "", and "" is NOT
// null/undefined, so `??` alone does not fall through to the bundled
// model path. Root cause of getDefaultPredictor() silently returning
// null: an empty-but-set ML_MODEL_PATH resolved to fs.readFile(""),
// which fails and was (correctly) swallowed by the catch below, masking
// the real problem as "no model available".
function firstNonBlank(...values: (string | undefined | null)[]): string | undefined {
  for (const value of values) {
    if (value != null && value.trim() !== "") return value;
  }
  return undefined;
}

export async function loadSerializedModel(modelPath?: string): Promise<SerializedMlModel | null> {
  const resolved =
    firstNonBlank(modelPath, process.env.ML_MODEL_PATH) ??
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
  // Computed once per loaded model, not per prediction: this is a global
  // description of what the model learned (see explain.ts), so it's
  // wasteful and semantically wrong to recompute it per email.
  const explanation = explainModel(model, 10);
  return {
    predict(input: MlInput) {
      return { probability: predictPhishingProbability(model, input) };
    },
    describe() {
      return { model: model.model, modelVersion: model.modelVersion, explanation };
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
    const described = predictor.describe?.();
    const modelName = described?.model ?? MODEL_NAME;
    const modelVersion = described?.modelVersion ?? MODEL_VERSION;
    if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
      return {
        mlAssessment: {
          emailId,
          model: modelName,
          modelVersion,
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
      model: modelName,
      modelVersion,
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
        evidence: {
          model: modelName,
          modelVersion,
          probability,
          // Global model-level explanation (see explain.ts) — not a
          // per-email explanation of this specific score. null when the
          // predictor doesn't expose one (e.g. a bare test mock).
          explanation: described?.explanation ?? null,
        },
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
