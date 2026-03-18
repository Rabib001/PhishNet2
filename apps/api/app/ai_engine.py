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
    prompt = f"""You are a security analyst. Analyze this email for phishing indicators.

Return ONLY a JSON object with these exact keys:
- "label": one of "benign", "suspicious", or "phishing"
- "score": integer 0-100 (0=definitely safe, 100=definitely phishing)
- "reasons": array of short strings explaining your reasoning

Be calibrated: most legitimate emails should score 0-15. Only flag emails with clear deceptive intent or technical phishing indicators.

EMAIL DATA:
Subject: {subject}
From: {from_addr}
Body (first 2000 chars): {body_text[:2000]}
URLs found: {json.dumps(urls[:10], ensure_ascii=False)}""".strip()

    client = _get_client()
    try:
        response = client.chat.completions.create(
            model="llama3.2:1b",
            messages=[
                {"role": "system", "content": "You are a security analyst. Output valid JSON only. No other text."},
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
