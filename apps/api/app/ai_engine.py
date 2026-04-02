import os
import json
import re
from openai import OpenAI

_client = None

def _get_client():
    global _client
    if _client is None:
        base_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
        if not base_url.endswith("/v1"):
            base_url = f"{base_url}/v1"
        _client = OpenAI(base_url=base_url, api_key="ollama")
    return _client


def _extract_json(text: str) -> dict | None:
    """Try multiple strategies to extract JSON from LLM output."""
    # Strategy 1: direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    # Strategy 2: find JSON block in markdown fences
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Strategy 3: find first { ... } block
    m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    return None


def detect_email_with_local_ai(subject: str, from_addr: str, body_text: str, urls: list[str]) -> dict:
    """Structured detection for emails using local Ollama."""
    url_list = json.dumps(urls[:10], ensure_ascii=False)
    body_snippet = body_text[:1800].strip()

    prompt = f"""TASK: Classify this email as phishing, suspicious, or benign.

SCORING GUIDE (pick score first, then derive label):
- 0-20  = benign    (normal work/personal email, newsletters, receipts from known brands)
- 21-50 = suspicious (unusual sender, vague urgency, mismatched links, but not conclusive)
- 51-100 = phishing  (clear deception: fake login pages, credential harvesting, spoofed brand, wire transfer fraud)

PHISHING RED FLAGS — each one found adds weight:
1. Urgency + threat: "account suspended", "verify now or lose access", "immediate action required"
2. Spoofed sender: display name says "PayPal" but email domain is not paypal.com
3. Link mismatch: link text says one domain but href goes to a different domain
4. Credential request: asks for password, SSN, credit card, OTP via email
5. Wire transfer / gift card request: "buy $500 in gift cards", "transfer funds"
6. Lookalike domain: paypa1.com, micosoft.com, arnazon.com
7. Raw IP in URL: http://192.168.x.x/login
8. Excessive urgency + prize: "You won!", "Claim your reward in 24 hours"

LEGITIMATE INDICATORS (lower the score):
- Sent from matching corporate domain (e.g. amazon.com email links to amazon.com)
- No credential/payment requests
- Professional language, no spelling errors
- Known sender pattern (e.g. shipping notifications, calendar invites)

EMAIL:
Subject: {subject}
From: {from_addr}
Body:
{body_snippet}
URLs: {url_list}

Respond with ONLY this JSON (no other text):
{{"score": <0-100>, "label": "<benign|suspicious|phishing>", "reasons": ["<reason1>", "<reason2>"]}}"""

    client = _get_client()
    try:
        response = client.chat.completions.create(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": 'You are a phishing detection system. Reply with only a JSON object: {"score": int, "label": string, "reasons": [string]}'},
                {"role": "user", "content": prompt}
            ],
            extra_body={"keep_alive": "5m"},
        )
        content = response.choices[0].message.content
        print(f"DEBUG: AI Raw Response: {content}")

        data = _extract_json(content)
        if data is None:
            print("WARN: Could not parse AI response as JSON, falling back")
            return {"score": 50, "label": "suspicious", "reasons": ["AI returned unparseable response"]}

        # Normalize keys
        normalized = {k.lower(): v for k, v in data.items()}
        if "score" not in normalized and "risk_score" in normalized:
            normalized["score"] = normalized["risk_score"]

        return normalized

    except Exception as e:
        print(f"Error calling Ollama: {e}")
        return {"score": 50, "label": "suspicious", "reasons": [f"AI Error: {str(e)}"]}
