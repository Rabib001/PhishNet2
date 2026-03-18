import os
import json
from pathlib import Path

import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

_model = None
_tokenizer = None
_meta = None
_model_path = None

MAX_LENGTH = 512


def _load_model():
    global _model, _tokenizer, _meta, _model_path
    if _model is not None:
        return

    _model_path = os.getenv("BERT_MODEL_PATH", str(Path(__file__).parent.parent / "bert" / "model"))

    if not Path(_model_path).exists() or not (Path(_model_path) / "config.json").exists():
        raise FileNotFoundError(f"BERT model not found at {_model_path}. Run bert/train.py first.")

    _tokenizer = DistilBertTokenizerFast.from_pretrained(_model_path)
    _model = DistilBertForSequenceClassification.from_pretrained(_model_path)
    _model.eval()

    meta_path = Path(_model_path) / "training_meta.json"
    if meta_path.exists():
        with open(meta_path) as f:
            _meta = json.load(f)


def bert_available() -> bool:
    model_path = os.getenv("BERT_MODEL_PATH", str(Path(__file__).parent.parent / "bert" / "model"))
    return (Path(model_path) / "config.json").exists()


def detect_email_with_bert(subject: str, from_addr: str, body_text: str, urls: list[str]) -> dict:
    _load_model()

    text = f"{subject} {from_addr} {body_text}"
    if urls:
        text += " " + " ".join(urls[:10])

    inputs = _tokenizer(
        text,
        truncation=True,
        padding="max_length",
        max_length=MAX_LENGTH,
        return_tensors="pt",
    )

    with torch.no_grad():
        outputs = _model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]

    phishing_prob = probs[1].item()
    legit_prob = probs[0].item()

    score = int(phishing_prob * 100)
    if score >= 65:
        label = "phishing"
    elif score >= 30:
        label = "suspicious"
    else:
        label = "benign"

    reasons = [f"BERT confidence: {phishing_prob:.1%} phishing, {legit_prob:.1%} legit"]

    if _meta:
        acc = _meta.get("test_accuracy", 0)
        f1 = _meta.get("test_f1", 0)
        reasons.append(f"Model: distilbert (test acc={acc:.2%}, f1={f1:.2%})")

    return {"score": score, "label": label, "reasons": reasons}
