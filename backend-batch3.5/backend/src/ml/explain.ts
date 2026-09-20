import type { SerializedMlModel } from "./model";

export interface TermContribution {
  term: string;
  weight: number;
}

export interface ModelExplanation {
  method: "logistic_regression_coefficients";
  /** Terms whose weight pushes the score toward "phishing". */
  topPositive: TermContribution[];
  /** Terms whose weight pushes the score toward "legitimate". */
  topNegative: TermContribution[];
  /**
   * Explicit and load-bearing: this is a GLOBAL description of what the
   * model learned across its whole vocabulary, not a per-prediction
   * explanation of why THIS email got THIS score (a genuine per-instance
   * explanation would need each document's actual non-zero TF-IDF
   * weights, e.g. a LIME/SHAP-style local attribution — not implemented
   * here; see docs/ml/AUDIT.md "Explainability" for why that was left out
   * rather than added as a checkbox).
   */
  scope: "global_model_coefficients_not_per_prediction";
}

/**
 * Ranks TF-IDF vocabulary terms by their logistic-regression coefficient.
 * Only covers the TF-IDF slots of the weight vector — the four structured
 * feature slots (urlCount/urgency/credentialRequest/financialRequest) are
 * excluded because they aren't vocabulary terms and would be mislabeled
 * if included in a "top terms" list.
 *
 * This is a real (not decorative) explanation method: logistic regression
 * coefficients are exactly and only what the model uses to score a
 * document, so listing the largest ones is a faithful description of what
 * it learned — unlike, say, raw transformer attention weights, which are
 * not a reliable explanation of model behavior (see docs/ml/AUDIT.md).
 */
export function explainModel(model: SerializedMlModel, topN = 10): ModelExplanation {
  const vocabSize = model.tfidf.vocabulary.length;
  const contributions: TermContribution[] = [];
  for (let i = 0; i < vocabSize; i++) {
    const weight = model.logistic.weights[i] ?? 0;
    if (weight === 0) continue;
    contributions.push({ term: model.tfidf.vocabulary[i], weight });
  }

  const positive = contributions
    .filter((c) => c.weight > 0)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, topN);
  const negative = contributions
    .filter((c) => c.weight < 0)
    .sort((a, b) => a.weight - b.weight)
    .slice(0, topN);

  return {
    method: "logistic_regression_coefficients",
    topPositive: positive,
    topNegative: negative,
    scope: "global_model_coefficients_not_per_prediction",
  };
}
