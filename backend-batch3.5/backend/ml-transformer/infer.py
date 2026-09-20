"""
Single-text inference against a fine-tuned transformer checkpoint.

STATUS: NOT EXECUTED (no checkpoint exists yet in this repository — see
train_transformer.py's module docstring for why). This script is provided
so the inference path exists and is reviewable alongside the training
path, per Phase 6's pipeline requirements, not because a checkpoint has
been produced.

Usage:
    python infer.py --checkpoint checkpoints/<run-id> --text "Verify your account now"

Prints a JSON object shaped like the classical model's contract
(classification/probability) so downstream integration code would not
need to special-case which model produced it.
"""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--text", required=True)
    args = parser.parse_args()

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        print(f"transformers/torch not installed: {exc}", file=sys.stderr)
        sys.exit(1)

    tokenizer = AutoTokenizer.from_pretrained(args.checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(args.checkpoint)
    model.eval()

    inputs = tokenizer(args.text, truncation=True, max_length=128, return_tensors="pt")
    with torch.no_grad():
        logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=-1).squeeze(0).tolist()

    # Index 1 = phishing, matching src/ml/dataset.ts's EmailLabel convention
    # (1 = phishing, 0 = legitimate) and dataset_split.json's labels.
    probability_phishing = probs[1]
    result = {
        "classification": "phishing" if probability_phishing >= 0.5 else "legitimate",
        "probability": probability_phishing,
        "note": "Softmax output of a fine-tuned classifier head — not independently calibrated against real-world attack frequency, same caveat as the classical model's score.",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
