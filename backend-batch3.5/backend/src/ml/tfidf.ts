import { tokenize, tokenizeWithBigrams } from "./tokenize";

export interface TfidfModel {
  vocabulary: string[];
  idf: number[];
  /**
   * Which tokenizer produced this vocabulary. Persisted so a saved model
   * always transforms new text the same way it was fit — added by the
   * ML upgrade so "unigram" (legacy) and "unigram+bigram" (current
   * default, see docs/ml/AUDIT.md) models never get vectorized with the
   * wrong tokenizer. Missing/undefined is treated as "unigram" for
   * backwards compatibility with models saved before this field existed.
   */
  tokenizer?: "unigram" | "unigram+bigram";
}

function tokenizerFor(model: Pick<TfidfModel, "tokenizer">): (text: string) => string[] {
  return model.tokenizer === "unigram+bigram" ? tokenizeWithBigrams : tokenize;
}

export function fitTfidf(
  documents: string[],
  options?: { maxFeatures?: number; minDf?: number; tokenizer?: TfidfModel["tokenizer"] }
): TfidfModel {
  const maxFeatures = options?.maxFeatures ?? 1200;
  const minDf = options?.minDf ?? 2;
  const tokenizer = options?.tokenizer ?? "unigram";
  const tokenizeFn = tokenizerFor({ tokenizer });

  const docsTokens = documents.map(tokenizeFn);
  const df = new Map<string, number>();
  for (const tokens of docsTokens) {
    for (const term of new Set(tokens)) {
      df.set(term, (df.get(term) ?? 0) + 1);
    }
  }

  const scored = [...df.entries()]
    .filter(([, count]) => count >= minDf)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, maxFeatures);

  const vocabulary = scored.map(([term]) => term);
  const n = documents.length;
  const idf = scored.map(([, count]) => Math.log((n + 1) / (count + 1)) + 1);
  return { vocabulary, idf, tokenizer };
}

export function transformTfidf(text: string, model: TfidfModel): number[] {
  const tokenizeFn = tokenizerFor(model);
  const tokens = tokenizeFn(text);
  const tf = new Map<string, number>();
  for (const token of tokens) tf.set(token, (tf.get(token) ?? 0) + 1);

  const vec = new Array(model.vocabulary.length).fill(0);
  const index = new Map(model.vocabulary.map((term, i) => [term, i]));
  for (const [term, count] of tf) {
    const i = index.get(term);
    if (i === undefined) continue;
    vec[i] = count * model.idf[i];
  }

  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0));
  if (norm === 0) return vec;
  return vec.map((v) => v / norm);
}
