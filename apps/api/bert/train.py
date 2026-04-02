"""
Fine-tune DistilBERT for phishing email classification.
Run: pip install -r bert/requirements-train.txt && python bert/train.py

Uses GPU (CUDA) automatically. Downloads ALL available datasets.
No sample cap — uses every row available for maximum precision.
"""

import io
import os
import json
import numpy as np
import pandas as pd
import requests
import torch
from pathlib import Path

from datasets import Dataset, DatasetDict, load_dataset
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    TrainingArguments,
    Trainer,
)
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

MODEL_NAME = "distilbert-base-uncased"
OUTPUT_DIR = Path(__file__).parent / "model"
MAX_LENGTH = 512
EPOCHS = 6
LEARNING_RATE = 2e-5
WARMUP_RATIO = 0.1
WEIGHT_DECAY = 0.01

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
BATCH_SIZE = 32 if DEVICE == "cuda" else 16
USE_FP16 = DEVICE == "cuda"


def _format_row(subject: str, body: str) -> str:
    """Structured input — must match bert_engine.py inference."""
    return f"subject: {subject.strip()} [SEP] body: {body.strip()}"


# ---------------------------------------------------------------------------
# Dataset loaders
# ---------------------------------------------------------------------------

def _normalize_label(val) -> int | None:
    s = str(val).lower().strip()
    if s in ("1", "true", "phishing", "phishing email", "spam"):
        return 1
    if s in ("0", "false", "legit", "legitimate", "safe email", "ham", "not_spam"):
        return 0
    return None


def load_local_data(data_dir: Path) -> pd.DataFrame:
    for name in ("texts.json", "phishing_emails.csv", "emails.csv", "dataset.csv"):
        p = data_dir / name
        if not p.exists():
            continue
        print(f"  Loading local file: {p.name}")
        df = pd.read_json(p) if p.suffix == ".json" else pd.read_csv(p)
        df.columns = [c.lower().strip() for c in df.columns]
        text_col = next((c for c in df.columns if c in ("text", "email_text", "body", "email", "message", "content", "email text")), None)
        label_col = next((c for c in df.columns if c in ("label", "class", "target", "is_phishing", "phishing", "email_type", "email type", "type")), None)
        subj_col = next((c for c in df.columns if "subject" in c), None)
        if not text_col or not label_col:
            continue
        subj = df[subj_col].fillna("") if subj_col else pd.Series([""] * len(df))
        df["text"] = [_format_row(str(s), str(b)) for s, b in zip(subj, df[text_col].fillna(""))]
        df["label"] = df[label_col].apply(_normalize_label)
        df = df[["text", "label"]].dropna()
        df["label"] = df["label"].astype(int)
        print(f"    {len(df)} rows")
        return df
    raise FileNotFoundError("No local dataset found")


def _hf_load(repo: str, config=None) -> list[pd.DataFrame] | None:
    """Load a HuggingFace dataset and return list of DataFrames, one per split."""
    try:
        print(f"  [{repo}] downloading...")
        ds = load_dataset(repo, config) if config else load_dataset(repo)
        frames = []
        for split_name in ds:
            df = ds[split_name].to_pandas()
            df.columns = [c.lower().strip() for c in df.columns]
            frames.append((split_name, df))
        return frames
    except Exception as e:
        print(f"  [{repo}] FAILED: {e}")
        return None


def _extract_text_label(df: pd.DataFrame, label_map=None) -> pd.DataFrame | None:
    text_col = next((c for c in df.columns if c in ("text", "email_text", "body", "email", "message", "content", "email text")), None)
    label_col = next((c for c in df.columns if c in ("label", "class", "target", "is_phishing", "phishing", "email_type", "email type", "type", "label_text")), None)
    if not text_col or not label_col:
        return None
    subj_col = next((c for c in df.columns if "subject" in c), None)
    subj = df[subj_col].fillna("") if subj_col else pd.Series([""] * len(df))
    out = pd.DataFrame()
    out["text"] = [_format_row(str(s), str(b)) for s, b in zip(subj, df[text_col].fillna(""))]
    if label_map:
        out["label"] = df[label_col].apply(label_map)
    else:
        out["label"] = df[label_col].apply(_normalize_label)
    out = out.dropna()
    out["label"] = out["label"].astype(int)
    return out if len(out) > 0 else None


def load_all_hf_datasets() -> list[pd.DataFrame]:
    frames = []

    # ── 1. zefang-liu/phishing-email-dataset (18,700 phishing emails) ──────
    splits = _hf_load("zefang-liu/phishing-email-dataset")
    if splits:
        for name, df in splits:
            out = _extract_text_label(df, label_map=lambda x: 1 if "phish" in str(x).lower() else 0)
            if out is not None:
                print(f"    {name}: {len(out)} rows  (phish={out['label'].sum()}, legit={len(out)-out['label'].sum()})")
                frames.append(out)

    # ── 2. SetFit/enron_spam (33,716 ham/spam emails, has subject) ──────────
    splits = _hf_load("SetFit/enron_spam")
    if splits:
        for name, df in splits:
            out = _extract_text_label(df)
            if out is not None:
                print(f"    {name}: {len(out)} rows  (phish={out['label'].sum()}, legit={len(out)-out['label'].sum()})")
                frames.append(out)

    # ── 3. cybersectony/PhishingEmailDetectionv2.0 (22k email rows) ─────────
    splits = _hf_load("cybersectony/PhishingEmailDetectionv2.0")
    if splits:
        for name, df in splits:
            # label: 0=legit_email, 1=phish_email, 2=legit_url, 3=phish_url → keep <2
            if "label" in df.columns:
                df = df[df["label"] < 2].copy()
                df.columns = [c.lower().strip() for c in df.columns]
                text_col = next((c for c in df.columns if c in ("content", "text", "body")), None)
                if text_col:
                    out = pd.DataFrame()
                    out["text"] = df[text_col].fillna("").apply(lambda t: _format_row("", str(t)))
                    out["label"] = df["label"].astype(int)
                    out = out.dropna()
                    print(f"    {name}: {len(out)} rows  (phish={out['label'].sum()}, legit={len(out)-out['label'].sum()})")
                    frames.append(out)

    # ── 4. Deysi/spam-detection-dataset (10,900 spam/not_spam) ─────────────
    splits = _hf_load("Deysi/spam-detection-dataset")
    if splits:
        for name, df in splits:
            out = _extract_text_label(df, label_map=lambda x: 1 if str(x).lower() in ("spam", "1", "true") else 0)
            if out is not None:
                print(f"    {name}: {len(out)} rows  (phish={out['label'].sum()}, legit={len(out)-out['label'].sum()})")
                frames.append(out)

    # ── 5. ucirvine/sms_spam (5,574 SMS spam) ──────────────────────────────
    splits = _hf_load("ucirvine/sms_spam")
    if splits:
        for name, df in splits:
            out = _extract_text_label(df, label_map=lambda x: 1 if str(x).lower() in ("spam", "1") else 0)
            if out is not None:
                print(f"    {name}: {len(out)} rows  (phish={out['label'].sum()}, legit={len(out)-out['label'].sum()})")
                frames.append(out)

    # ── 6. Direct CSV downloads from GitHub ─────────────────────────────────
    GITHUB_SOURCES = [
        {
            "url": "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_full.csv",
            "text_col": "anchor",
            "label_col": "phishing",
            "label_map": lambda x: 1 if str(x) in ("1", "phishing") else 0,
        },
    ]
    for src in GITHUB_SOURCES:
        try:
            print(f"  Downloading from GitHub...")
            r = requests.get(src["url"], timeout=30)
            r.raise_for_status()
            df = pd.read_csv(io.StringIO(r.text))
            df.columns = [c.strip() for c in df.columns]
            tc = next((c for c in df.columns if c.lower() == src["text_col"].lower()), None)
            lc = next((c for c in df.columns if c.lower() == src["label_col"].lower()), None)
            if tc and lc:
                out = pd.DataFrame()
                out["text"] = df[tc].fillna("").apply(lambda t: _format_row("", str(t)))
                out["label"] = df[lc].apply(src["label_map"])
                out = out.dropna()
                out["label"] = out["label"].astype(int)
                print(f"    {len(out)} rows  (phish={out['label'].sum()}, legit={len(out)-out['label'].sum()})")
                frames.append(out)
        except Exception as e:
            print(f"  GitHub download failed: {e}")

    return frames


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy":  accuracy_score(labels, preds),
        "f1":        f1_score(labels, preds, average="binary"),
        "precision": precision_score(labels, preds, average="binary"),
        "recall":    recall_score(labels, preds, average="binary"),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Device : {DEVICE.upper()}")
    if DEVICE == "cuda":
        props = torch.cuda.get_device_properties(0)
        print(f"GPU    : {props.name}")
        print(f"VRAM   : {props.total_memory / 1e9:.1f} GB")

    # ── Load data ────────────────────────────────────────────────────────────
    all_frames = []

    data_dir = Path(__file__).parent / "dataset"
    try:
        local_df = load_local_data(data_dir)
        all_frames.append(local_df)
        print(f"Local dataset: {len(local_df)} rows")
    except FileNotFoundError:
        pass

    print("\nDownloading remote datasets...")
    all_frames.extend(load_all_hf_datasets())

    if not all_frames:
        raise RuntimeError("No data loaded. Place a CSV in apps/api/bert/dataset/")

    df = pd.concat(all_frames, ignore_index=True).dropna()
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    n_phish = int(df["label"].sum())
    n_legit = len(df) - n_phish
    print(f"\nTotal unique rows : {len(df)}")
    print(f"  Phishing        : {n_phish}")
    print(f"  Legit           : {n_legit}")

    # ── Balance classes (use ALL of the minority, match with majority) ───────
    minority = min(n_phish, n_legit)
    phish_df = df[df["label"] == 1].sample(n=minority, random_state=42)
    legit_df = df[df["label"] == 0].sample(n=minority, random_state=42)
    df = pd.concat([phish_df, legit_df]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"\nBalanced dataset  : {len(df)} ({minority} phish + {minority} legit)")

    # ── Split ────────────────────────────────────────────────────────────────
    train_df, temp_df = train_test_split(df, test_size=0.15, random_state=42, stratify=df["label"])
    val_df,   test_df = train_test_split(temp_df, test_size=0.5, random_state=42, stratify=temp_df["label"])
    print(f"Train : {len(train_df)} | Val : {len(val_df)} | Test : {len(test_df)}")

    # ── Tokenize ─────────────────────────────────────────────────────────────
    print(f"\nTokenizing (MAX_LENGTH={MAX_LENGTH})...")
    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)

    def tokenize(examples):
        return tokenizer(examples["text"], truncation=True, padding="max_length", max_length=MAX_LENGTH)

    ds = DatasetDict({
        "train": Dataset.from_pandas(train_df, preserve_index=False),
        "val":   Dataset.from_pandas(val_df,   preserve_index=False),
        "test":  Dataset.from_pandas(test_df,  preserve_index=False),
    })
    ds = ds.map(tokenize, batched=True, num_proc=1)
    ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])

    # ── Model ────────────────────────────────────────────────────────────────
    model = DistilBertForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
        id2label={0: "legit", 1: "phishing"},
        label2id={"legit": 0, "phishing": 1},
    )

    # ── Class weights (handles any residual imbalance) ───────────────────────
    n_total = len(train_df)
    n_p = int(train_df["label"].sum())
    n_l = n_total - n_p
    class_weights = torch.tensor([n_total / (2 * max(n_l, 1)), n_total / (2 * max(n_p, 1))], dtype=torch.float)
    print(f"Class weights — legit: {class_weights[0]:.3f}, phishing: {class_weights[1]:.3f}")

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights.to(outputs.logits.device))
            loss = loss_fn(outputs.logits, labels)
            return (loss, outputs) if return_outputs else loss

    # ── Training args ────────────────────────────────────────────────────────
    steps_per_epoch = len(train_df) // BATCH_SIZE
    total_steps = steps_per_epoch * EPOCHS
    print(f"\nSteps per epoch : {steps_per_epoch}")
    print(f"Total steps     : {total_steps}")

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR / "checkpoints"),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=LEARNING_RATE,
        weight_decay=WEIGHT_DECAY,
        warmup_ratio=WARMUP_RATIO,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=100,
        fp16=USE_FP16,
        dataloader_num_workers=0,
        report_to="none",
    )

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=ds["train"],
        eval_dataset=ds["val"],
        compute_metrics=compute_metrics,
        processing_class=tokenizer,
    )

    print(f"\nStarting training on {DEVICE.upper()} | batch={BATCH_SIZE} | fp16={USE_FP16} | epochs={EPOCHS}\n")
    trainer.train()

    # ── Evaluate ─────────────────────────────────────────────────────────────
    print("\nTest set evaluation:")
    results = trainer.evaluate(ds["test"])
    for k, v in results.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")

    # ── Save ─────────────────────────────────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    meta = {
        "base_model": MODEL_NAME,
        "max_length": MAX_LENGTH,
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
        "device": DEVICE,
        "fp16": USE_FP16,
        "total_samples": len(df),
        "train_samples": len(train_df),
        "input_format": "subject: {subject} [SEP] body: {body}",
        "test_accuracy":  results.get("eval_accuracy",  0),
        "test_f1":        results.get("eval_f1",        0),
        "test_precision": results.get("eval_precision", 0),
        "test_recall":    results.get("eval_recall",    0),
    }
    with open(OUTPUT_DIR / "training_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nModel saved to {OUTPUT_DIR}")
    print(f"Accuracy  : {results.get('eval_accuracy', 0):.4f}")
    print(f"F1        : {results.get('eval_f1', 0):.4f}")
    print(f"Precision : {results.get('eval_precision', 0):.4f}")
    print(f"Recall    : {results.get('eval_recall', 0):.4f}")


if __name__ == "__main__":
    main()
