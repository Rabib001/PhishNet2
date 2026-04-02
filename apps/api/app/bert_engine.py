import os
import re
import json
from pathlib import Path
from urllib.parse import urlparse

import torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

_model = None
_tokenizer = None
_meta = None
_model_path = None


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


def _build_input_text(subject: str, from_addr: str, body_text: str, urls: list[str]) -> str:
    """Build a structured input string matching the training format."""
    # Use [SEP] as field separator — same format used in train.py
    parts = [
        f"subject: {subject.strip()}",
        f"from: {from_addr.strip()}",
        f"body: {body_text[:1500].strip()}",
    ]
    if urls:
        parts.append(f"urls: {' '.join(urls[:10])}")
    return " [SEP] ".join(parts)


def _get_max_length() -> int:
    """Read max_length from training metadata so inference always matches training."""
    if _meta and "max_length" in _meta:
        return int(_meta["max_length"])
    # Fallback: check config
    if _model_path:
        cfg = Path(_model_path) / "training_meta.json"
        if cfg.exists():
            try:
                with open(cfg) as f:
                    return int(json.load(f).get("max_length", 512))
            except Exception:
                pass
    return 512


def _technical_signals(urls: list[str]) -> list[str]:
    """Extract hard technical phishing signals that BERT can miss."""
    signals = []
    for u in urls[:20]:
        try:
            host = (urlparse(u).hostname or "").strip(".").lower()
        except Exception:
            continue
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            signals.append("raw-ip-link")
        if "xn--" in host:
            signals.append("punycode-domain")
        if host.count(".") > 4:
            signals.append("deep-subdomain")
    return list(set(signals))


def detect_email_with_bert(subject: str, from_addr: str, body_text: str, urls: list[str]) -> dict:
    _load_model()

    text = _build_input_text(subject, from_addr, body_text, urls)
    max_length = _get_max_length()

    inputs = _tokenizer(
        text,
        truncation=True,
        padding="max_length",
        max_length=max_length,
        return_tensors="pt",
    )

    with torch.no_grad():
        outputs = _model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]

    phishing_prob = probs[1].item()
    legit_prob = probs[0].item()

    score = int(phishing_prob * 100)

    # Apply hard technical signal overrides that BERT may miss
    tech = _technical_signals(urls)
    if tech and score < 60:
        score = max(score, 65)
        phishing_prob = score / 100

    if score >= 65:
        label = "phishing"
    elif score >= 35:
        label = "suspicious"
    else:
        label = "benign"

    reasons = [f"BERT: {phishing_prob:.1%} phishing probability ({legit_prob:.1%} legit)"]
    if tech:
        reasons.append(f"Technical signals: {', '.join(tech)}")

    if _meta:
        acc = _meta.get("test_accuracy", 0)
        f1 = _meta.get("test_f1", 0)
        reasons.append(f"Model stats: acc={acc:.1%}, f1={f1:.1%}")

    return {"score": score, "label": label, "reasons": reasons}
