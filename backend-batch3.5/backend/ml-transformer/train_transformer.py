"""
Fine-tune a compact encoder (default: DistilBERT) as a second, separate
content-phishing classifier, for a fair comparison against the classical
TF-IDF + logistic regression baseline.

STATUS: NOT EXECUTED. This environment has no network access and does
not have torch/transformers installed (`pip install transformers` fails
here with "no matching distribution" — confirmed by actually attempting
it). This script is a complete, reproducible pipeline for an environment
that does have both. Running it does not happen automatically as part of
this ML upgrade; nothing in this repository claims a transformer result
because none was measured. See docs/ml/AUDIT.md, Phase 6/7.

Usage (in an environment with network access and requirements.txt installed):

    cd backend-batch3.5/backend
    npx ts-node --transpile-only src/ml/exportDatasetJson.ts
    cd ml-transformer
    python train_transformer.py --model distilbert-base-uncased --epochs 4

Writes:
    ml-transformer/checkpoints/<run-id>/          (model + tokenizer)
    ml-transformer/checkpoints/<run-id>/metrics.json

metrics.json uses the same field names as the classical benchmark
(precision/recall/f1/falsePositiveRate/falseNegativeRate/confusionMatrix)
specifically so the two can be placed side by side in
docs/ml/AUDIT.md without translation.
"""

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def load_split(data_path: Path):
    with open(data_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return payload["train"], payload["validation"], payload["test"], payload["splitSeed"]


@dataclass
class Metrics:
    precision: float
    recall: float
    f1: float
    falsePositiveRate: float
    falseNegativeRate: float
    confusionMatrix: dict
    splitSizes: dict | None = None

    def to_json(self):
        out = {
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "falsePositiveRate": self.falsePositiveRate,
            "falseNegativeRate": self.falseNegativeRate,
            "confusionMatrix": self.confusionMatrix,
        }
        if self.splitSizes is not None:
            out["splitSizes"] = self.splitSizes
        return out


def compute_metrics_from_predictions(y_true, y_pred, split_sizes=None) -> Metrics:
    from sklearn.metrics import confusion_matrix

    # Fixed label order [0, 1] so tn/fp/fn/tp line up with the classical
    # pipeline's ConfusionMatrix shape (0 = legitimate, 1 = phishing).
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return Metrics(
        precision=precision,
        recall=recall,
        f1=f1,
        falsePositiveRate=fpr,
        falseNegativeRate=fnr,
        confusionMatrix={
            "truePositive": int(tp),
            "falsePositive": int(fp),
            "trueNegative": int(tn),
            "falseNegative": int(fn),
        },
        splitSizes=split_sizes,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="distilbert-base-uncased", help="HF model id (compact encoder only — do not select a large model for this dataset size)")
    parser.add_argument("--data", default="data/dataset_split.json")
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--seed", type=int, default=26106, help="Must match src/ml/model.ts stratifiedSplit seed for the comparison to be meaningful")
    parser.add_argument("--out-dir", default="checkpoints")
    args = parser.parse_args()

    set_seed(args.seed)

    try:
        import torch
        from torch.utils.data import Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        print(
            "transformers/torch are not installed in this environment. "
            "This is expected here (see module docstring) — install "
            "requirements.txt in an environment with network access to "
            "actually run this pipeline.",
            file=sys.stderr,
        )
        print(f"Import error: {exc}", file=sys.stderr)
        sys.exit(1)

    data_path = Path(args.data)
    if not data_path.exists():
        print(
            f"{data_path} not found. Generate it first with:\n"
            "  npx ts-node --transpile-only ../src/ml/exportDatasetJson.ts\n"
            "(run from backend-batch3.5/backend)",
            file=sys.stderr,
        )
        sys.exit(1)

    train_rows, val_rows, test_rows, split_seed = load_split(data_path)
    if split_seed != args.seed:
        print(
            f"WARNING: dataset_split.json was exported with seed {split_seed}, "
            f"but --seed={args.seed} was passed. Proceeding with the seed "
            "already baked into the exported split (re-export if you need "
            "a different one) — this warning exists so a mismatch is never "
            "silent.",
            file=sys.stderr,
        )

    tokenizer = AutoTokenizer.from_pretrained(args.model)

    class PhishingTextDataset(Dataset):
        def __init__(self, rows):
            self.texts = [r["text"] for r in rows]
            self.labels = [r["label"] for r in rows]

        def __len__(self):
            return len(self.texts)

        def __getitem__(self, idx):
            enc = tokenizer(
                self.texts[idx],
                truncation=True,
                max_length=args.max_length,
                padding="max_length",
                return_tensors="pt",
            )
            item = {k: v.squeeze(0) for k, v in enc.items()}
            item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
            return item

    train_ds = PhishingTextDataset(train_rows)
    val_ds = PhishingTextDataset(val_rows)
    test_ds = PhishingTextDataset(test_rows)

    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=2)

    run_id = f"{args.model.replace('/', '_')}-{int(time.time())}"
    out_dir = Path(args.out_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    def hf_compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        m = compute_metrics_from_predictions(labels, preds)
        return {"precision": m.precision, "recall": m.recall, "f1": m.f1}

    training_args = TrainingArguments(
        output_dir=str(out_dir / "trainer"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        eval_strategy="epoch",
        save_strategy="no",
        logging_strategy="epoch",
        seed=args.seed,
        report_to=[],
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        compute_metrics=hf_compute_metrics,
    )

    train_start = time.time()
    trainer.train()
    training_time_seconds = time.time() - train_start

    # Validation is used only for early visibility during development
    # (via hf_compute_metrics above / TrainingArguments eval_strategy).
    # The line below is the single, final evaluation on the held-out
    # test split — run once, after training is complete, matching the
    # classical pipeline's discipline of not touching the test set for
    # model selection.
    test_logits = trainer.predict(test_ds).predictions
    test_preds = np.argmax(test_logits, axis=-1)
    test_labels = [r["label"] for r in test_rows]
    test_metrics = compute_metrics_from_predictions(
        test_labels,
        test_preds,
        split_sizes={"train": len(train_rows), "validation": len(val_rows), "test": len(test_rows)},
    )

    val_logits = trainer.predict(val_ds).predictions
    val_preds = np.argmax(val_logits, axis=-1)
    val_labels = [r["label"] for r in val_rows]
    val_metrics = compute_metrics_from_predictions(val_labels, val_preds)

    model.save_pretrained(out_dir)
    tokenizer.save_pretrained(out_dir)

    model_size_bytes = sum(f.stat().st_size for f in out_dir.glob("*") if f.is_file())

    # Rough single-example CPU latency, matching how the classical
    # benchmark measures latency in src/ml/benchmark.ts, so the two are
    # comparable rather than measured on different hardware assumptions
    # left unstated.
    model.eval()
    sample = test_ds[0]
    sample_inputs = {k: v.unsqueeze(0) for k, v in sample.items() if k != "labels"}
    warmup = 3
    iters = 20
    with torch.no_grad():
        for _ in range(warmup):
            model(**sample_inputs)
        start = time.time()
        for _ in range(iters):
            model(**sample_inputs)
        mean_latency_ms = (time.time() - start) / iters * 1000

    report = {
        "model": args.model,
        "modelVersion": run_id,
        "framework": "transformers+torch",
        "trainedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hyperparams": {
            "epochs": args.epochs,
            "batchSize": args.batch_size,
            "learningRate": args.learning_rate,
            "maxLength": args.max_length,
        },
        "splitSeed": split_seed,
        "test": test_metrics.to_json(),
        "validation": val_metrics.to_json(),
        "trainingTimeSeconds": training_time_seconds,
        "modelSizeBytes": model_size_bytes,
        "meanInferenceLatencyMs": mean_latency_ms,
        "note": (
            "Evaluated on the same seed-26106 stratified test split as "
            "the classical TF-IDF+LR benchmark (see "
            "../src/ml/exportDatasetJson.ts and ../docs/ml/AUDIT.md). "
            "Test set is 13 examples — treat as illustrative, not "
            "production-grade statistical evidence, same caveat as the "
            "classical benchmark."
        ),
    }

    metrics_path = out_dir / "metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Wrote {metrics_path}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
