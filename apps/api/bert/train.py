"""
Fine-tune DistilBERT for phishing email classification.
Run: pip install -r bert/requirements-train.txt && python bert/train.py
"""

import os
import json
import numpy as np
import pandas as pd
from pathlib import Path

from datasets import Dataset, DatasetDict
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
MAX_LENGTH = 256
EPOCHS = 3
BATCH_SIZE = 16
LEARNING_RATE = 2e-5
MAX_SAMPLES = 5000


def load_local_data(data_dir: Path) -> pd.DataFrame:
    json_path = data_dir / "texts.json"
    csv_path = data_dir / "phishing_emails.csv"

    if json_path.exists():
        df = pd.read_json(json_path)
    elif csv_path.exists():
        df = pd.read_csv(csv_path)
    else:
        raise FileNotFoundError(f"No dataset found in {data_dir}")

    # normalize column names
    col_map = {}
    for c in df.columns:
        cl = c.lower().strip()
        if cl in ("text", "email_text", "body", "email", "message", "content"):
            col_map[c] = "text"
        elif cl in ("label", "class", "target", "is_phishing", "phishing"):
            col_map[c] = "label"
        elif cl in ("subject",):
            col_map[c] = "subject"
    df = df.rename(columns=col_map)

    if "subject" in df.columns and "text" in df.columns:
        df["text"] = df["subject"].fillna("") + " " + df["text"].fillna("")
    elif "text" not in df.columns:
        raise ValueError(f"Could not find text column. Columns: {list(df.columns)}")

    if "label" not in df.columns:
        raise ValueError(f"Could not find label column. Columns: {list(df.columns)}")

    df["label"] = df["label"].astype(int)
    df = df[["text", "label"]].dropna()
    return df


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, average="binary"),
        "precision": precision_score(labels, preds, average="binary"),
        "recall": recall_score(labels, preds, average="binary"),
    }


def main():
    data_dir = Path(__file__).parent / "dataset"
    print(f"Loading dataset from {data_dir}")
    df = load_local_data(data_dir)

    print(f"Full dataset: {len(df)} samples ({df['label'].sum()} phishing, {(1-df['label']).sum()} legit)")

    if MAX_SAMPLES and len(df) > MAX_SAMPLES:
        half = MAX_SAMPLES // 2
        phish = df[df["label"] == 1].sample(n=min(half, df["label"].sum()), random_state=42)
        legit = df[df["label"] == 0].sample(n=half, random_state=42)
        df = pd.concat([phish, legit]).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"Sampled down to {len(df)} for CPU training")

    # split
    train_df, temp_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])
    val_df, test_df = train_test_split(temp_df, test_size=0.5, random_state=42, stratify=temp_df["label"])

    print(f"Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")

    # tokenize
    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)

    def tokenize(examples):
        return tokenizer(examples["text"], truncation=True, padding="max_length", max_length=MAX_LENGTH)

    ds = DatasetDict({
        "train": Dataset.from_pandas(train_df, preserve_index=False),
        "val": Dataset.from_pandas(val_df, preserve_index=False),
        "test": Dataset.from_pandas(test_df, preserve_index=False),
    })
    ds = ds.map(tokenize, batched=True)
    ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])

    # model
    model = DistilBertForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2,
        id2label={0: "legit", 1: "phishing"},
        label2id={"legit": 0, "phishing": 1},
    )

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR / "checkpoints"),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=LEARNING_RATE,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=50,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=ds["train"],
        eval_dataset=ds["val"],
        compute_metrics=compute_metrics,
        tokenizer=tokenizer,
    )

    print("Training...")
    trainer.train()

    # evaluate on test set
    print("\nTest set evaluation:")
    results = trainer.evaluate(ds["test"])
    for k, v in results.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")

    # save
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    # save metadata
    meta = {
        "base_model": MODEL_NAME,
        "max_length": MAX_LENGTH,
        "epochs": EPOCHS,
        "train_samples": len(train_df),
        "test_accuracy": results.get("eval_accuracy", 0),
        "test_f1": results.get("eval_f1", 0),
        "test_precision": results.get("eval_precision", 0),
        "test_recall": results.get("eval_recall", 0),
    }
    with open(OUTPUT_DIR / "training_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\nModel saved to {OUTPUT_DIR}")
    print(f"Accuracy: {results.get('eval_accuracy', 0):.4f}")
    print(f"F1: {results.get('eval_f1', 0):.4f}")


if __name__ == "__main__":
    main()
