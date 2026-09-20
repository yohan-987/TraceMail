# Transformer content classifier — pipeline (not yet benchmarked)

**TRANSFORMER BENCHMARK: NOT EXECUTED.**

The environment this ML upgrade was performed in has no network access
and does not have `torch`/`transformers` installed (confirmed by
attempting `pip install transformers`, which fails with "no matching
distribution" — not assumed, actually tried). No transformer was trained,
and no transformer metrics appear anywhere in this repository. What
follows is a complete, runnable pipeline for an environment that does
have both, plus the exact commands to reproduce it and drop the result
into `docs/ml/AUDIT.md` next to the classical benchmark.

## Why a transformer at all

The classical model (`../src/ml/model.ts`, TF-IDF + logistic regression)
already has real measured numbers (see `../docs/ml/AUDIT.md`). This
pipeline exists so that claim can be tested against evidence rather than
assumed — a transformer is adopted only if it demonstrably outperforms
the classical baseline on the same held-out test set, not because it is
newer.

## 1. Dataset

Same 81-row dataset as the classical model
(`../src/ml/dataset.ts`), same seed-26106 stratified 70/15/15 split
(`stratifiedSplit()` in `../src/ml/model.ts`). The split is not
reimplemented here — `../src/ml/exportDatasetJson.ts` exports it once to
`data/dataset_split.json` so both pipelines are guaranteed to evaluate on
the identical test rows.

## 2. Preprocessing / tokenization

Each row's `text` field is `subject + "\n" + body` (identical to the
classical pipeline's `documentText()`), tokenized by the chosen model's
own tokenizer (WordPiece for DistilBERT), truncated/padded to
`--max-length` (default 128 tokens — generous for this dataset's
2–24 word examples).

## 3. Model choice

Default: `distilbert-base-uncased` (66M parameters) — chosen because it
is small enough to plausibly run on CPU in a constrained deployment and
is a standard, well-understood baseline encoder. A larger model was not
selected; nothing about this 81-example dataset would justify one, and
Phase 6 of this upgrade explicitly rules out picking a model for
prestige. `--model` accepts any Hugging Face
`AutoModelForSequenceClassification`-compatible model id if a different
compact encoder is preferred.

## 4. Training

```bash
cd backend-batch3.5/backend
npx ts-node --transpile-only src/ml/exportDatasetJson.ts
cd ml-transformer
pip install -r requirements.txt
python train_transformer.py --model distilbert-base-uncased --epochs 4
```

Fine-tunes a sequence-classification head (2 labels: phishing/legitimate)
using Hugging Face `Trainer`. Validation metrics are reported per epoch
for development visibility; the **test** split is evaluated exactly once,
after training finishes — the same test-set discipline the classical
pipeline follows (see `../docs/ml/AUDIT.md`, Phase 4/5).

## 5. Evaluation

`train_transformer.py` writes
`checkpoints/<run-id>/metrics.json` using the **same field names** as the
classical benchmark (`precision`, `recall`, `f1`, `falsePositiveRate`,
`falseNegativeRate`, `confusionMatrix`, plus `modelSizeBytes` and
`meanInferenceLatencyMs`), specifically so the two can be placed side by
side without translation. Confusion matrix uses `labels=[0, 1]` (0 =
legitimate, 1 = phishing), matching `dataset.ts`'s `EmailLabel`.

## 6. Inference

```bash
python infer.py --checkpoint checkpoints/<run-id> --text "Verify your account now"
```

Outputs `{classification, probability}`, matching the classical model's
output shape (`predictPhishingProbability()` in `../src/ml/model.ts`),
so integration code would not need to special-case which model produced
a result — should this model ever be promoted to production.

## 7. Fair comparison checklist (Phase 7)

Both models, when both have real numbers:
- [x] Same dataset (`dataset.ts`, exported once via `exportDatasetJson.ts`)
- [x] Same labels (0 = legitimate, 1 = phishing)
- [x] Same held-out test set (seed 26106, `stratifiedSplit()`)
- [x] Same metric definitions (precision/recall/F1/FPR/FNR/confusion,
      identical field names)
- [ ] **Transformer side of this comparison: not yet run.**

Do not fill in a transformer row in `../docs/ml/AUDIT.md`'s comparison
table until `train_transformer.py` has actually been run and
`metrics.json` actually exists — copy the numbers from that file
verbatim when it does.

## 8. What NOT to do with this pipeline

- Do not report a transformer result without running this script.
- Do not select the transformer automatically once it does run — compare
  it against the classical model's F1/recall/FPR on the same 13-example
  test set, and remember that with a test set this small a difference of
  one example is not strong evidence either way (see the statistical
  caveat in `../docs/ml/AUDIT.md`, section 4).
- Do not swap this in as the production model in `mlClassifier.ts`
  without also updating `getDefaultPredictor()`/`MlPredictor` to handle a
  transformer runtime (this pipeline is Python; the backend is
  TypeScript/Node — serving this model in production would need either an
  ONNX export + a Node ONNX runtime, or a small inference microservice.
  Neither is implemented here, and neither should be added "for visual
  optics" without the benchmark above actually justifying the switch).

## Requirements

Python 3.10+ (uses `X | None` type hints). See `requirements.txt`. Not
installed or verified in this task's environment — versions are
deliberately unpinned since no install was performed here to confirm
which versions actually work together.
