import { tokenize } from "./tokenize";

export interface TfidfModel {
  vocabulary: string[];
  idf: number[];
}

export function fitTfidf(documents: string[], maxFeatures = 1200, minDf = 2): TfidfModel {
  const docsTokens = documents.map(tokenize);
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
  return { vocabulary, idf };
}

export function transformTfidf(text: string, model: TfidfModel): number[] {
  const tokens = tokenize(text);
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
