
# PhishNet: AI-Powered Email Security Sandbox

**PhishNet** is a secure, localized environment for analyzing suspicious emails. It combines **Llama 3.2** (running locally via Ollama) with robust **heuristic analysis** to detect phishing attempts, while providing a sandboxed "Safe Preview" to view malicious content without risk.

## Key Features

* **AI Detection Engine:** Uses **Llama 3.2 1B** running locally through Ollama (OpenAI-compatible API) to analyze email context, intent, and coercion. No data leaves your machine.
* **Multi-Signal Heuristic Fallback:** Catches technical threats (raw IPs, punycode, brand spoofing, suspicious TLDs, credential harvesting URLs, free hosting abuse) even if the LLM is unavailable.
* **Open Safely Mode:** Renders emails in a headless Chromium sandbox to capture screenshots and extract IOCs without exposing your machine.
* **Deep Link Analysis:** Detects deceptive links using domain root matching, subdomain abuse detection, and a brand-to-domain mapping database covering 50+ brands.
* **Privacy Focused:** Fully self-hosted via Docker. All inference runs locally — no API keys, no external calls.

## Detection Methodology

The heuristic engine runs multiple independent checks across five layers:

**Sender Analysis** — Display name brand spoofing against 50+ known brands, email-in-display-name tricks, suspicious TLD detection, domain entropy analysis for randomly generated sender domains.

**Content Analysis** — High-confidence scam phrase matching, credential harvesting language detection, financial bait (gift cards, wire transfers, crypto), attachment-based social engineering, urgency/pressure language with conservative weighting.

**URL Analysis** — Raw IP links, punycode/IDN homograph domains, suspicious TLD detection, free hosting/dynamic DNS identification, excessive subdomain obfuscation, brand-as-subdomain attacks (e.g., `paypal.evil.com`), credential-harvesting URL paths, data/javascript URI detection, URL shortener abuse in brand impersonation context.

**Cross-Correlation** — Signals compound: brand impersonation + deceptive URLs escalates score. Urgency + credential harvesting + mismatched URLs triggers the classic phishing pattern bonus. 4+ independent indicators apply a high-confidence multiplier.

**Negative Signals** — Unsubscribe links reduce score. All URLs matching sender domain reduces score. Generic email senders (gmail, yahoo) suppress mismatch penalties. Short plain-text emails with no URLs get a risk reduction.

> The heuristic engine runs independently of the LLM, ensuring detection continues even if Ollama is unavailable.

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
    |--- Ollama (Llama 3.2 1B, port 11434)
    |--- SQLite (local file)
    |--- Headless Chromium Runner (port 7070)
            |
            v
        Local Artifact Storage
```

---

## Prerequisites

* **Docker Desktop** (running and updated)
* That's it. No API keys needed — Ollama pulls Llama 3.2 1B automatically on first boot.

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/Mananshah237/PhishNet.git
cd PhishNet
```

### 2. Configure Environment

Create a `.env` file in the root directory:

```ini
# Database (SQLite, configured in docker-compose)
DATABASE_URL=sqlite:///data/phishnet.db

# Ollama (configured in docker-compose, no changes needed)
OLLAMA_BASE_URL=http://ollama:11434
```

### 3. Launch

```bash
docker compose up -d --build
```

First run takes a few minutes — Docker pulls the Ollama image and downloads the Llama 3.2 1B model (~1.3GB).

### 4. Access

* **Frontend:** http://localhost:3000
* **API Docs:** http://localhost:8000/docs

---

## Usage

1. **Upload** — Drag and drop a `.eml` file into the dashboard.
2. **Analysis** — The system runs two parallel checks:
   * **LLM:** Llama 3.2 analyzes email context and intent.
   * **Heuristics:** Checks for technical indicators (IP links, punycode, brand spoofing, etc.)
3. **Result** — Score (0-100) and verdict (Benign, Suspicious, Phishing) with specific reasons.
4. **Open Safely** — Renders the email in a sandboxed headless browser. Returns screenshots + extracted text + IOCs.

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

* **`apps/api`** — Python FastAPI backend (detection engine, DB, Ollama integration)
* **`apps/web`** — Next.js frontend
* **`apps/runner`** — Node.js headless Chromium service for safe rendering
* **`artifacts/`** — Local storage for screenshots and analysis data

---

## License

MIT License. Use responsibly for educational and defensive security purposes.
