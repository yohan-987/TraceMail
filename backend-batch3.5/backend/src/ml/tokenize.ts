export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " urltoken ")
    .replace(/[^a-z0-9]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 1);
}

/**
 * Word unigrams + bigrams. Bigrams capture short phishing-style phrases
 * ("wire the", "verify your", "gift card") that unigram-only TF-IDF
 * treats as independent, unrelated words. Benchmarked against
 * unigram-only in docs/ml/AUDIT.md ("Baseline improvement") before being
 * adopted as the default — this is not included speculatively.
 */
export function tokenizeWithBigrams(text: string): string[] {
  const unigrams = tokenize(text);
  const bigrams: string[] = [];
  for (let i = 0; i < unigrams.length - 1; i++) {
    bigrams.push(`${unigrams[i]}_${unigrams[i + 1]}`);
  }
  return [...unigrams, ...bigrams];
}