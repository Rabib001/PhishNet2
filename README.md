
# PhishNet: AI-Powered Email Security Sandbox

**PhishNet** is a secure, localized environment for analyzing suspicious emails. It combines three independent detection methods — a **fine-tuned DistilBERT classifier** (96.2% F1), **Llama 3.2** (via Ollama), and a **multi-signal heuristic engine** — with a sandboxed "Safe Preview" to view malicious content without risk.

## Key Features

* **Three Detection Methods:** Users choose between Heuristic, LLM (Llama 3.2), BERT, or run all three simultaneously. Results are combined (max score, most severe label, union of reasons).
* **Fine-Tuned BERT Classifier:** DistilBERT fine-tuned on 5K phishing/legit email samples — 96.2% accuracy, 96.2% F1. Pre-trained model ships with the repo via Git LFS, no training required to use.
* **LLM Analysis:** Llama 3.2 1B runs locally through Ollama for contextual intent analysis. No data leaves your machine.
* **Multi-Signal Heuristic Engine:** Catches technical threats (raw IPs, punycode, brand spoofing, suspicious TLDs, credential harvesting URLs, free hosting abuse) even if BERT and LLM are unavailable.
* **Open Safely Mode:** Renders emails in a headless Chromium sandbox to capture screenshots and extract IOCs without exposing your machine.
* **Deep Link Analysis:** Domain root matching, subdomain abuse detection, and a brand-to-domain mapping database covering 50+ brands.
* **Privacy Focused:** Fully self-hosted via Docker. All inference runs locally — no API keys, no external calls.

## Detection Methodology

### BERT Classifier

A fine-tuned `distilbert-base-uncased` model trained on the [ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset) (5K balanced samples, 3 epochs). The model outputs a phishing probability that maps to a 0-100 risk score. Pre-trained weights are included in `apps/api/bert/model/` — cloning the repo gives you a working classifier out of the box.

To retrain on your own data, place a CSV or JSON file in `apps/api/bert/dataset/` and run `python bert/train.py`.

### Heuristic Engine

The heuristic engine runs multiple independent checks across five layers:

**Sender Analysis** — Display name brand spoofing against 50+ known brands, email-in-display-name tricks, suspicious TLD detection, domain entropy analysis for randomly generated sender domains.

**Content Analysis** — High-confidence scam phrase matching, credential harvesting language detection, financial bait (gift cards, wire transfers, crypto), attachment-based social engineering, urgency/pressure language with conservative weighting.

**URL Analysis** — Raw IP links, punycode/IDN homograph domains, suspicious TLD detection, free hosting/dynamic DNS identification, excessive subdomain obfuscation, brand-as-subdomain attacks (e.g., `paypal.evil.com`), credential-harvesting URL paths, data/javascript URI detection, URL shortener abuse in brand impersonation context.

**Cross-Correlation** — Signals compound: brand impersonation + deceptive URLs escalates score. Urgency + credential harvesting + mismatched URLs triggers the classic phishing pattern bonus. 4+ independent indicators apply a high-confidence multiplier.

**Negative Signals** — Unsubscribe links reduce score. All URLs matching sender domain reduces score. Generic email senders (gmail, yahoo) suppress mismatch penalties. Short plain-text emails with no URLs get a risk reduction.

> All three methods run independently. The heuristic engine is always available; BERT works if the model weights exist; LLM requires Ollama to be running. The frontend grays out unavailable methods.

---

## Architecture

PhishNet runs as a multi-container Docker application:

```
User / Browser
    |
    v
Next.js Frontend (port 3000)
    |
    v
FastAPI Backend (port 8000)
    |--- DistilBERT classifier (CPU, in-process)
    |--- Ollama / Llama 3.2 1B (port 11434)
    |--- Heuristic engine (rule-based, no deps)
    |--- SQLite (local file)
    |--- Headless Chromium Runner (port 7070)
            |
            v
        Local Artifact Storage
```

---

## Prerequisites

* **Docker Desktop** (running and updated)
* **Git LFS** — the BERT model weights (~268MB) are stored with Git LFS. Run `git lfs install` before cloning.
* That's it. No API keys needed — Ollama pulls Llama 3.2 1B automatically on first boot.

---

## Quick Start

### 1. Install Git LFS

```bash
git lfs install
```

### 2. Clone

```bash
git clone https://github.com/Mananshah237/PhishNet.git
cd PhishNet
```

This pulls the full repo including the pre-trained BERT model weights (~268MB via LFS).

### 3. Configure Environment

Create a `.env` file in the root directory:

```ini
DATABASE_URL=sqlite:///data/phishnet.db
OLLAMA_BASE_URL=http://ollama:11434
```

### 4. Launch

```bash
docker compose up -d --build
```

First run takes a few minutes — Docker builds the containers, installs PyTorch + Transformers for BERT inference, and pulls the Llama 3.2 1B model (~1.3GB) via Ollama.

### 5. Access

* **Frontend:** http://localhost:3000
* **API Docs:** http://localhost:8000/docs

### 6. Verify Detection Methods

Hit the methods endpoint to confirm what's available:

```bash
curl http://localhost:8000/detect/methods
```

```json
{"heuristic": true, "llm": true, "bert": true}
```

If `bert` is `false`, the LFS pull may have failed — run `git lfs pull` and restart the API container. If `llm` is `false`, Ollama is still downloading the model — give it a minute.

### Running Without Docker (local dev)

```bash
cd apps/api
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

BERT works out of the box (model weights are in `bert/model/`). For LLM detection, run Ollama separately: `ollama serve` and `ollama pull llama3.2:1b`.

### Retraining the BERT Model (optional)

To retrain on a different dataset:

```bash
cd apps/api
pip install -r bert/requirements-train.txt
# place your dataset in bert/dataset/ (JSON or CSV with 'text' and 'label' columns)
python bert/train.py
```

Training takes ~60-80 minutes on CPU (5K samples, 3 epochs). The new model overwrites `bert/model/`.

---

## Usage

1. **Upload** — Drag and drop a `.eml` file into the dashboard.
2. **Select Method** — Choose Heuristic, LLM, BERT, or All from the sidebar.
3. **Analysis** — The system runs your selected method(s):
   * **Heuristic:** Technical indicator checks (IP links, punycode, brand spoofing, etc.)
   * **BERT:** DistilBERT classifier outputs a phishing probability score.
   * **LLM:** Llama 3.2 analyzes email context and intent.
   * **All:** Runs all three, combines results (max score, most severe label).
4. **Result** — Score (0-100) and verdict (Benign, Suspicious, Phishing) with per-method reasons.
5. **Open Safely** — Renders the email in a sandboxed headless browser. Returns screenshots + extracted text + IOCs.

---

## Sample Analysis Output

```
Email: "Your PayPal account has been limited"
From: PayPal Security <security@paypa1-verify.xyz>

Risk Score: 100/100 — PHISHING

Indicators:
  - Display name impersonates 'paypal' but sender domain is paypa1-verify.xyz
  - Sender domain uses suspicious TLD: paypa1-verify.xyz
  - Credential harvesting language: 'enter your password'
  - Urgency/pressure language detected
  - Link uses raw IP address: 185.234.72.11
  - Credential-harvesting URL path on domain unrelated to sender
  - Brand impersonation + deceptive URL infrastructure
  - 8 independent indicators detected
```

---

## Security Architecture

The "Open Safely" sandbox exists because raw emails are hostile documents:

- **Tracking pixels, JavaScript, and auto-loading resources** in emails can fingerprint the analyst's machine — leaking IP, OS, browser version, and screen resolution to the attacker.
- **Opening links directly** exposes your IP and browser fingerprint, confirming the target is actively investigating.
- **PhishNet's headless Chromium sandbox** renders in isolation with a default-deny network policy. The browser runs inside a dedicated container with no access to the host network or filesystem.
- **Only the target origin is optionally allowed** — all other requests (tracking pixels, third-party scripts) are blocked at the network level.
- **Output is non-interactive:** screenshots + extracted text + IOCs. No executable content reaches the analyst.
- **The runner container is ephemeral** — each render job starts clean with no persistent state.

---

## Troubleshooting

### "AI analysis unavailable; using heuristics"

* **Cause:** Ollama hasn't finished pulling the model, or the container isn't healthy.
* **Fix:**
  1. Check Ollama status: `docker compose logs ollama`
  2. Verify model is loaded: `docker compose exec ollama ollama list`
  3. Force recreate: `docker compose up -d --force-recreate ollama`

### "NetworkError" in Frontend

* **Cause:** The API container crashed or isn't ready.
* **Fix:** Check logs: `docker compose logs -f api`

---

## Project Structure

* **`apps/api`** — Python FastAPI backend (detection engine, BERT inference, Ollama integration, DB)
* **`apps/api/bert/`** — BERT classifier: pre-trained model weights, training script, dataset config
* **`apps/web`** — Next.js frontend with detection method selector
* **`apps/runner`** — Node.js headless Chromium service for safe rendering
* **`artifacts/`** — Local storage for screenshots and analysis data

---

## License

MIT License. Use responsibly for educational and defensive security purposes.
